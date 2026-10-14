/**
 * @file Dgram.hpp
 * @brief SOCKS5 UDP 包连接对象（Transmission 装饰器）
 * @details UDP 数据面连接：将底层流连接（Socks5::Conn，同一条 TCP，
 * 不另开底层连接）包装为包级 API（AsyncSendTo / AsyncReceiveFrom），
 * 内部完成 UDP 报文编解码。
 * 报文格式：[RSV 2B 0x0000][FRAG 1B 0x00][ATYP][ADDR][PORT 2B][payload]
 * （RFC 1928 §7）。
 * @note 继承 Preview::Transmission，构造函数传入底层流连接（相当于
 * socket 收发的持有者），对齐 Conn 的装饰器链模式。
 */

#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Protocols/Common/Address.hpp>
#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Socks5/Codec.hpp>
#include <Preview/Protocols/Socks5/Types.hpp>

namespace Preview::Socks5
{

    namespace Net = boost::asio;

    /**
     * @class Dgram
     * @brief SOCKS5 UDP 包连接对象（Transmission 装饰器）
     * @details 持有底层流连接（Socks5::Conn，已握手）的独占所有权，
     * 对外暴露包级 API（AsyncSendTo / AsyncReceiveFrom）。
     * 由工厂（ConnectPacket / AcceptPacket）创建。
     * @tparam Memory 会话内存策略（默认 8KB Arena；可注入自定义策略）
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Dgram : public Preview::Transmission
    {
    public:
        /// 内存策略类型（对外暴露）
        using MemoryType = Memory;

        /**
         * @brief 构造函数（工厂调用）
         * @param Stream 底层流连接（已握手，所有权移交）
         */
        explicit Dgram(SharedTransmission Stream)
            : Preview::Transmission(Stream ? Stream->Executor() : Net::any_io_executor{}),
              NextLayer_(std::move(Stream))
        {
        }

        /**
         * @brief 获取执行器（委托底层流连接）
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (!NextLayer_)
            {
                return Preview::Transmission::Executor();
            }
            return NextLayer_->Executor();
        }

        /**
         * @brief 传输类型（经底层委托，TCP 承载数据报）
         */
        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Udp;
        }

        /**
         * @brief 发送一个 UDP 数据报（WriteTo 语义）
         * @param Destination 按值持有的目标地址，协程帧独立持有其值。
         * @param Payload 借用载荷；调用方须保持其存储有效且不变，直到 awaitable 完成。
         * @return Error；底层传输失败映射为 Error::IoError。
         * @details 报文格式 [RSV 2B][FRAG 1B][ATYP][ADDR][PORT][payload]。
         *          底层写操作遵循 Transmission 固定的 Activity executor。
         *          同方向的发送调用必须串行，遵循 Transmission 的 span 借用和同向发起契约。
         * @note Cancel() 请求取消；Close() 向下层转交最终关闭，成功仅表示命令已接管。
         *       释放 owner 前须等待本层及下层各自 Activity()->Drain()。
         */
        [[nodiscard]] auto AsyncSendTo(
            Address Destination,
            std::span<const std::uint8_t> Payload)
            -> Net::awaitable<Error>
        {
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            BuildUdpDatagram(Destination, Payload, TxWire_);
            if (TxWire_.empty())
            {
                co_return Error::BadAddress;
            }
            std::size_t Done = 0;
            while (Done < TxWire_.size())
            {
                const auto Part = co_await WriteSome(
                    AsBytes(std::span<const std::uint8_t>(TxWire_)).subspan(Done));
                if (Part.Failure.Failed())
                {
                    co_return Error::IoError;
                }
                if (Part.Bytes == 0)
                {
                    co_return Error::BrokenPipe; // 底层零字节写入，防死循环
                }
                if (Part.Bytes > TxWire_.size() - Done)
                {
                    co_return Error::BadLength;
                }
                Done += Part.Bytes;
            }
            co_return Error::None;
        }

        /**
         * @brief 接收一个 UDP 数据报（ReadFrom 语义）
         * @param Source 输出源地址
         * @param Payload 输出载荷
         * @return 错误码
         * @details 经底层流连接预读缓冲精确分段读取：
         * RSV(2) + FRAG(1) + ATYP + ADDR + PORT(2) + payload。
         */
        [[nodiscard]] auto AsyncReceiveFrom(
            Address &Source,
            std::vector<std::uint8_t> &Payload)
            -> Net::awaitable<Error>
        {
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            // 1. RSV(2) + FRAG(1)
            std::array<std::uint8_t, 3> Head{};
            const auto HeadError = co_await ReadExact(std::span<std::uint8_t>(Head));
            if (HeadError != Error::None)
                co_return HeadError;
            if (Head[0] != 0 || Head[1] != 0 || Head[2] != 0)
            {
                co_return Error::BadMessage;
            }

            // 2. ATYP + ADDR + PORT
            std::array<std::uint8_t, 1> AddressTypeByte{};
            const auto AtypError = co_await ReadExact(std::span<std::uint8_t>(AddressTypeByte));
            if (AtypError != Error::None)
                co_return AtypError;
            Source.Type = static_cast<AddressType>(AddressTypeByte[0]);
            const auto AddressError = co_await ReadAddressBody(Source);
            if (AddressError != Error::None)
            {
                co_return AddressError;
            }
            std::array<std::uint8_t, 2> Port{};
            const auto PortError = co_await ReadExact(std::span<std::uint8_t>(Port));
            if (PortError != Error::None)
                co_return PortError;
            Source.Port = static_cast<std::uint16_t>(Port[0]) << 8 | Port[1];

            // 3. 剩余为 payload（单次读取，超读由流连接缓冲保留）
            std::array<std::uint8_t, 512> Chunk{};
            const auto Part = co_await ReadSome(AsBytes(std::span<std::uint8_t>(Chunk)));
            if (Part.Failure.Failed())
            {
                if (Part.Failure.Code == Preview::Fault::Code::Eof)
                {
                    co_return Error::UnexpectedEof;
                }
                co_return Error::IoError;
            }
            if (Part.Bytes == 0)
            {
                co_return Error::UnexpectedEof;
            }
            if (Part.Bytes > Chunk.size())
            {
                co_return Error::BadLength;
            }
            Payload.assign(Chunk.begin(), Chunk.begin() + static_cast<std::ptrdiff_t>(Part.Bytes));
            co_return Error::None;
        }

        /**
         * @brief 透传读取（底层流原样）
         */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Preview::Transport::Detail::PostResult(
                    Executor(), std::move(Handler), Preview::IoResult{0, {Preview::Fault::Code::IoError}});
                return;
            }
            NextLayer_->ReadSome(Buffer, std::move(Handler));
        }

        /**
         * @brief 透传写入（底层流原样）
         */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Preview::Transport::Detail::PostResult(
                    Executor(), std::move(Handler), Preview::IoResult{0, {Preview::Fault::Code::IoError}});
                return;
            }
            NextLayer_->WriteSome(Buffer, std::move(Handler));
        }

        /** @brief 真实写半关闭转交底层流；读取方向保持可用。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Preview::Transport::Detail::PostResult(
                    Executor(), std::move(Handler), Preview::IoResult{0, {Preview::Fault::Code::IoError}});
                return;
            }
            NextLayer_->WriteShutdown(std::move(Handler));
        }

        /**
         * @brief 关闭底层流连接
         */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            if (!NextLayer_)
            {
                return {};
            }
            return NextLayer_->Close();
        }

        /**
         * @brief 取消挂起操作
         */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            if (!NextLayer_)
            {
                return {};
            }
            return NextLayer_->Cancel();
        }

        /**
         * @brief 获取底层传输（装饰器链导航）
         */
        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto Release() -> SharedTransmission override
        {
            return std::move(NextLayer_);
        }

        /**
         * @brief 获取底层流连接
         */
        [[nodiscard]] auto Stream() const noexcept -> SharedTransmission
        {
            return NextLayer_;
        }

    private:
        /**
         * @brief 精确读取指定字节数
         * @param Destination 目标缓冲区
         * @return 错误码；None 表示完整读取，BadLength 表示底层违反窗口契约
         */
        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> Destination) -> Net::awaitable<Error>
        {
            std::size_t Done = 0;
            while (Done < Destination.size())
            {
                const auto Part = co_await ReadSome(AsBytes(Destination.subspan(Done)));
                if (Part.Failure.Failed() || Part.Bytes == 0)
                {
                    co_return Error::IoError;
                }
                if (Part.Bytes > Destination.size() - Done)
                {
                    co_return Error::BadLength;
                }
                Done += Part.Bytes;
            }
            co_return Error::None;
        }

        /**
         * @brief 读取地址体（ATYP 已由调用方解析）
         * @param AddressValue 输出地址
         * @return 错误码
         * @note 转发层：统一实现见 Protocol/common::ReadAddressBody
         */
        [[nodiscard]] auto ReadAddressBody(Address &AddressValue) -> Net::awaitable<Error>
        {
            return Preview::Socks5::ReadAddressBody(
                AddressValue, [this](std::span<std::uint8_t> Destination) -> Net::awaitable<bool>
                {
                    co_return (co_await ReadExact(Destination)) != Error::None;
                });
        }

        SharedTransmission NextLayer_; ///< 底层流连接（嵌入，同一条 TCP）
        Memory Mem_;                     ///< 会话内存策略（Arena，热路径零释放分配）
        typename Memory::template Buffer<std::uint8_t> TxWire_{Mem_.Arena()}; ///< 发送缓冲（Arena 复用，热路径零分配）
    };

    /// 包连接共享指针（默认内存策略）
    using SharedDgram = std::shared_ptr<Dgram<>>;

} // namespace Preview::Socks5
