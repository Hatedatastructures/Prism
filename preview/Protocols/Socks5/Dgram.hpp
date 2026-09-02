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

#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Protocols/Common/Address.hpp>
#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Socks5/Codec.hpp>
#include <preview/Protocols/Socks5/Types.hpp>

namespace Preview::Socks5
{

    /**
     * @class Dgram
     * @brief SOCKS5 UDP 包连接对象（Transmission 装饰器）
     * @details 持有底层流连接（Socks5::Conn，已握手）的独占所有权，
     * 对外暴露包级 API（AsyncSendTo / AsyncReceiveFrom）。
     * 由工厂（ConnectPacket / AcceptPacket）创建。
     * @tparam Memory 会话内存策略（默认 8KB Arena；可注入自定义策略）
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Dgram : public Preview::Transmission, public std::enable_shared_from_this<Dgram<Memory>>
    {
    public:
        /// 内存策略类型（对外暴露）
        using MemoryType = Memory;

        /**
         * @brief 构造函数（工厂调用）
         * @param Stream 底层流连接（已握手，所有权移交）
         */
        explicit Dgram(SharedTransmission Stream) : NextLayer_(std::move(Stream))
        {
        }

        /**
         * @brief 获取执行器（委托底层流连接）
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
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
         * @param dest 目标地址
         * @param payload 载荷
         * @return 错误码
         * @details 报文格式 [RSV 2B][FRAG 1B][ATYP][ADDR][PORT][payload]。
         */
        [[nodiscard]] auto AsyncSendTo(const Address &dest, std::span<const std::uint8_t> payload)
            -> net::awaitable<Error>
        {
            BuildUdpDatagram(dest, payload, TxWire_);
            std::size_t Done = 0;
            while (Done < TxWire_.size())
            {
                std::error_code ec;
                const auto N = co_await NextLayer_->async_write_some(
                    AsBytes(std::span<const std::uint8_t>(TxWire_)).subspan(Done), ec);
                if (ec)
                {
                    co_return Error::IoError;
                }
                if (N == 0)
                {
                    co_return Error::BrokenPipe; // 底层零字节写入，防死循环
                }
                Done += N;
            }
            co_return Error::None;
        }

        /**
         * @brief 接收一个 UDP 数据报（ReadFrom 语义）
         * @param src 输出源地址
         * @param payload 输出载荷
         * @return 错误码
         * @details 经底层流连接预读缓冲精确分段读取：
         * RSV(2) + FRAG(1) + ATYP + ADDR + PORT(2) + payload。
         */
        [[nodiscard]] auto AsyncReceiveFrom(Address &src, std::vector<std::uint8_t> &payload)
            -> net::awaitable<Error>
        {
            // 1. RSV(2) + FRAG(1)
            std::array<std::uint8_t, 3> head{};
            if (co_await ReadExact(std::span<std::uint8_t>(head)))
            {
                co_return Error::IoError;
            }
            if (head[0] != 0 || head[1] != 0 || head[2] != 0)
            {
                co_return Error::BadMessage;
            }

            // 2. ATYP + ADDR + PORT
            std::array<std::uint8_t, 1> atyp{};
            if (co_await ReadExact(std::span<std::uint8_t>(atyp)))
            {
                co_return Error::IoError;
            }
            src.Type = static_cast<AddressType>(atyp[0]);
            auto Err = co_await ReadAddressBody(src);
            if (Err != Error::None)
            {
                co_return Err;
            }
            std::array<std::uint8_t, 2> port{};
            if (co_await ReadExact(std::span<std::uint8_t>(port)))
            {
                co_return Error::IoError;
            }
            src.Port = static_cast<std::uint16_t>(port[0]) << 8 | port[1];

            // 3. 剩余为 payload（单次读取，超读由流连接缓冲保留）
            std::array<std::uint8_t, 512> chunk{};
            std::error_code ec;
            const auto N =
                co_await NextLayer_->async_read_some(AsBytes(std::span<std::uint8_t>(chunk)), ec);
            if (ec)
            {
                co_return Error::IoError;
            }
            if (N == 0)
            {
                co_return Error::UnexpectedEof;
            }
            payload.assign(chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(N));
            co_return Error::None;
        }

        /**
         * @brief 透传读取（底层流原样）
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await NextLayer_->async_read_some(Buffer, ec);
        }

        /**
         * @brief 透传写入（底层流原样）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await NextLayer_->async_write_some(Buffer, ec);
        }

        /**
         * @brief 关闭底层流连接
         */
        void Close() override
        {
            NextLayer_->Close();
        }

        /**
         * @brief 取消挂起操作
         */
        void Cancel() override
        {
            NextLayer_->Cancel();
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
         * @param dst 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> dst) -> net::awaitable<bool>
        {
            std::size_t Done = 0;
            while (Done < dst.size())
            {
                std::error_code ec;
                const auto N = co_await NextLayer_->async_read_some(AsBytes(dst.subspan(Done)), ec);
                if (ec || N == 0)
                {
                    co_return true;
                }
                Done += N;
            }
            co_return false;
        }

        /**
         * @brief 读取地址体（ATYP 已由调用方解析）
         * @param addr 输出地址
         * @return 错误码
         * @note 转发层：统一实现见 Protocol/common::ReadAddressBody
         */
        [[nodiscard]] auto ReadAddressBody(Address &addr) -> net::awaitable<Error>
        {
            return Preview::Protocol::Common::ReadAddressBody(
                addr, [this](std::span<std::uint8_t> dst) -> net::awaitable<bool> { return ReadExact(dst); });
        }

        SharedTransmission NextLayer_; ///< 底层流连接（嵌入，同一条 TCP）
        Memory Mem_;                     ///< 会话内存策略（Arena，热路径零释放分配）
        typename Memory::template Buffer<std::uint8_t> TxWire_{Mem_.Arena()}; ///< 发送缓冲（Arena 复用，热路径零分配）
    };

    /// 包连接共享指针（默认内存策略）
    using SharedDgram = std::shared_ptr<Dgram<>>;

} // namespace Preview::Socks5
