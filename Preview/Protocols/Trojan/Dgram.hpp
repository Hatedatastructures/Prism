/**
 * @file Dgram.hpp
 * @brief Trojan UDP 包连接对象（Transmission 装饰器）
 * @details UDP 数据面连接：将底层流连接（Trojan::Conn，同一条 TCP，
 * 不另开底层连接）包装为包级 API（AsyncSendTo / AsyncReceiveFrom），
 * 内部完成 UDP 帧编解码与剩余包缓冲。
 * 帧格式：[ATYP][ADDR][PORT 2B BE][LEN 2B BE][CRLF][payload]。
 * @note 对齐 mihomo transport/trojan.PacketConn：包连接是独立类型，
 *          嵌入底层流连接，仅提供包语义（net.PacketConn 对应物）。
 * @note 继承 Preview::Transmission，构造函数传入底层流连接（相当于
 * socket 收发的持有者），对齐 Conn 的装饰器链模式。
 */

#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <expected>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Contract/Io/PacketTransferResult.hpp>
#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Protocols/Common/Address.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Trojan/Codec.hpp>
#include <Preview/Protocols/Trojan/Types.hpp>

namespace Preview::Trojan
{

    namespace Net = boost::asio;

    /**
     * @class Dgram
     * @brief Trojan UDP 包连接对象（Transmission 装饰器）
     * @details 持有底层流连接（Trojan::Conn，已握手）的独占所有权，
     * 对外暴露包级 API（AsyncSendTo / AsyncReceiveFrom），内部
     * 完成 UDP 帧编解码。由工厂（ConnectPacket / AcceptPacket）创建。
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
         * @param Target 按值持有的目标地址，协程帧独立持有其值。
         * @param Payload 借用载荷；调用方须保持其存储有效且不变，直到 awaitable 完成。
         * @return 完整载荷量、真实帧 wire 量与完整协议/native Failure。
         * @details 底层写操作遵循 Transmission 固定的 Activity executor。
         *          同方向的发送调用必须串行，遵循 Transmission 的 span 借用和同向发起契约。
         * @note Cancel() 请求取消；Close() 向下层转交最终关闭，成功仅表示命令已接管。
         *       释放 owner 前须等待本层及下层各自 Activity()->Drain()。
         */
        [[nodiscard]] auto AsyncSendTo(
            Address Target,
            std::span<const std::uint8_t> Payload)
            -> Net::awaitable<Preview::Contract::Io::PacketTransferResult>
        {
            if (!NextLayer_)
            {
                co_return Preview::Contract::Io::PacketTransferResult{
                    0, 0, {Preview::Fault::Code::IoError}};
            }
            if (Payload.size() > 0xFFFF)
            {
                co_return Preview::Contract::Io::PacketTransferResult{
                    0, 0, ProtocolFailure(Error::BadLength)};
            }
            BuildUdpPkt(Target, Payload, TxWire_);
            if (TxWire_.empty())
            {
                co_return Preview::Contract::Io::PacketTransferResult{
                    0, 0, ProtocolFailure(Error::BadAddress)};
            }
            std::size_t Done = 0;
            while (Done < TxWire_.size())
            {
                const auto Remaining = TxWire_.size() - Done;
                const auto Part = co_await WriteSome(
                    AsBytes(std::span<const std::uint8_t>(TxWire_)).subspan(Done));
                if (Part.Bytes > Remaining)
                {
                    const auto Progress = Part.Bytes >
                        (std::numeric_limits<std::size_t>::max)() - Done
                        ? (std::numeric_limits<std::size_t>::max)()
                        : Done + Part.Bytes;
                    co_return Preview::Contract::Io::PacketTransferResult{
                        0, Progress,
                        {Preview::Fault::Code::InvalidArgument, Part.Failure.Native}};
                }
                Done += Part.Bytes;
                if (Part.Failure.Failed())
                {
                    co_return Preview::Contract::Io::PacketTransferResult{
                        0, Done, Part.Failure};
                }
                if (Part.Bytes == 0)
                {
                    co_return Preview::Contract::Io::PacketTransferResult{
                        0, Done, ProtocolFailure(Error::BrokenPipe)};
                }
            }
            co_return Preview::Contract::Io::PacketTransferResult{
                Payload.size(), Done, {}};
        }

        /**
         * @brief 接收一个 UDP 数据报（ReadFrom 语义）
         * @param Source 输出源地址
         * @param Payload 输出载荷
         * @return 完整数据报成功；底层读取失败保留完整 Failure/native cause。
         * @details 经底层流连接的预读缓冲精确分段读取完整帧。
         */
        [[nodiscard]] auto AsyncReceiveFrom(
            Address &Source,
            std::vector<std::uint8_t> &Payload)
            -> Net::awaitable<Preview::Contract::Io::PacketTransferResult>
        {
            if (!NextLayer_)
            {
                co_return Preview::Contract::Io::PacketTransferResult{
                    0, 0, {Preview::Fault::Code::IoError}};
            }
            std::size_t WireBytes = 0;
            // 1. 读取地址体（ATYP + ADDR + PORT 2B BE）
            bool FrameStarted = false;
            std::array<std::uint8_t, 1> AddressTypeByte{};
            const auto AtypRead = co_await ReadExact(
                std::span<std::uint8_t>(AddressTypeByte), FrameStarted, WireBytes);
            if (AtypRead.Failed())
                co_return Preview::Contract::Io::PacketTransferResult{
                    0, WireBytes, AtypRead};
            Source.Type = static_cast<AddressType>(AddressTypeByte[0]);
            std::optional<Preview::Fault::Failure> ReadFailure;
            const auto AddressError = co_await Preview::Trojan::ReadAddressBody(
                Source,
                [this, &ReadFailure, &FrameStarted, &WireBytes](
                    std::span<std::uint8_t> Buffer)
                    -> Net::awaitable<bool>
                {
                    const auto Failure = co_await ReadExact(
                        Buffer, FrameStarted, WireBytes);
                    if (Failure.Failed()) ReadFailure = Failure;
                    co_return Failure.Failed();
                });
            if (ReadFailure)
            {
                co_return Preview::Contract::Io::PacketTransferResult{
                    0, WireBytes, *ReadFailure};
            }
            if (AddressError != Error::None)
            {
                co_return Preview::Contract::Io::PacketTransferResult{
                    0, WireBytes, ProtocolFailure(AddressError)};
            }
            if (Source.Type == AddressType::Domain && Source.Host.empty())
            {
                co_return Preview::Contract::Io::PacketTransferResult{
                    0, WireBytes, ProtocolFailure(Error::BadMessage)};
            }
            std::array<std::uint8_t, 2> Port{};
            const auto PortRead = co_await ReadExact(
                std::span<std::uint8_t>(Port), FrameStarted, WireBytes);
            if (PortRead.Failed())
                co_return Preview::Contract::Io::PacketTransferResult{
                    0, WireBytes, PortRead};
            Source.Port = static_cast<std::uint16_t>(Port[0]) << 8 | Port[1];

            // 2. 读取头部：LEN(2 BE) + CRLF(2)
            std::array<std::uint8_t, 4> Head{};
            const auto HeadRead = co_await ReadExact(
                std::span<std::uint8_t>(Head), FrameStarted, WireBytes);
            if (HeadRead.Failed())
                co_return Preview::Contract::Io::PacketTransferResult{
                    0, WireBytes, HeadRead};
            if (Head[2] != '\r' || Head[3] != '\n')
            {
                co_return Preview::Contract::Io::PacketTransferResult{
                    0, WireBytes, ProtocolFailure(Error::BadMagic)};
            }
            const auto Length = static_cast<std::size_t>(Head[0]) << 8 | Head[1];

            // 3. 读取载荷
            Payload.resize(Length);
            if (Length > 0)
            {
                const auto PayloadRead = co_await ReadExact(
                    Payload, FrameStarted, WireBytes);
                if (PayloadRead.Failed())
                    co_return Preview::Contract::Io::PacketTransferResult{
                        0, WireBytes, PayloadRead};
            }
            co_return Preview::Contract::Io::PacketTransferResult{
                Payload.size(), WireBytes, {}};
        }

        /**
         * @brief 透传读取（底层流原样）
         */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Preview::Transport::Detail::PostResult(Executor(), std::move(Handler), Preview::IoResult{0, {Preview::Fault::Code::IoError}});
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
                Preview::Transport::Detail::PostResult(Executor(), std::move(Handler), Preview::IoResult{0, {Preview::Fault::Code::IoError}});
                return;
            }
            NextLayer_->WriteSome(Buffer, std::move(Handler));
        }

        /** @brief 真实写半关闭转交底层流；读取方向保持可用。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Preview::Transport::Detail::PostResult(Executor(), std::move(Handler), Preview::IoResult{0, {Preview::Fault::Code::IoError}});
                return;
            }
            NextLayer_->WriteShutdown(std::move(Handler));
        }

        /**
         * @brief 关闭底层流连接
         */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            if (NextLayer_)
            {
                return NextLayer_->Close();
            }
            return {};
        }

        /**
         * @brief 取消挂起操作
         */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            if (NextLayer_)
            {
                return NextLayer_->Cancel();
            }
            return {};
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
         * @param Buffer 目标缓冲区
         * @return 错误码；None 表示完整读取，BadLength 表示底层违反窗口契约
         */
        [[nodiscard]] auto ReadExact(
            std::span<std::uint8_t> Buffer,
            bool &FrameStarted,
            std::size_t &FrameWireBytes)
            -> Net::awaitable<Preview::Fault::Failure>
        {
            auto &Carrier = static_cast<Preview::Transmission &>(*this);
            const auto Result = co_await Carrier.ReadExact(AsBytes(Buffer));
            FrameWireBytes = Result.Bytes >
                (std::numeric_limits<std::size_t>::max)() - FrameWireBytes
                ? (std::numeric_limits<std::size_t>::max)()
                : FrameWireBytes + Result.Bytes;
            FrameStarted = FrameStarted || Result.Bytes != 0U;
            auto Failure = Result.Failure;
            if (Failure.Code == Preview::Fault::Code::Eof && FrameStarted)
            {
                Failure.Code = Preview::Fault::Code::BadMessage;
            }
            if (Failure.Failed()) co_return Failure;
            if (Result.Bytes != Buffer.size())
            {
                co_return Preview::Fault::Failure{
                    Preview::Fault::Code::BadMessage, Result.Failure.Native};
            }
            co_return Preview::Fault::Failure{};
        }

        [[nodiscard]] static auto ProtocolFailure(Error Value) noexcept
            -> Preview::Fault::Failure
        {
            return {Preview::Fault::ToCode(Preview::make_error_code(Value))};
        }

        /**
         * @brief 读取地址体（ATYP 已由调用方解析）
         * @param Output 输出地址
         * @return 错误码
         * @note 转发层：统一实现见 Protocol/common::ReadAddressBody
         */
        SharedTransmission NextLayer_; ///< 底层流连接（嵌入，同一条 TCP）
        Memory Mem_;                     ///< 会话内存策略（Arena，热路径零释放分配）
        typename Memory::template Buffer<std::uint8_t> TxWire_{Mem_.Arena()}; ///< 发送缓冲（Arena 复用，热路径零分配）
    };

    /// 包连接共享指针（默认内存策略）
    using SharedDgram = std::shared_ptr<Dgram<>>;

} // namespace Preview::Trojan
