/**
 * @file Dgram.hpp
 * @brief SS2022 UDP 包连接对象（Transmission 装饰器）
 * @details UDP 数据面连接：将底层数据报传输（Unreliable，
 * 或任意包边界的传输）包装为 SS2022（SIP022）逐包 AEAD 编解码层。
 * - 客户端：底层 Unreliable Connect(remote) 后，本类逐包加密发送
 * - 服务端：底层 Unreliable Bind(port) 后，本类逐包解密
 * 每个包独立加密（SeparateHeader 含 SessionID/PacketID，Nonce 派生），
 * 目标地址内嵌于包内，无状态。编解码逻辑复用 Codec.hpp 纯函数
 * （BuildUdpPacket / ParseUdpPacket）。
 * @note 继承 Preview::Transmission，构造函数传入底层传输（相当于
 * socket 收发的持有者），对齐 Conn 的装饰器链模式。
 * @note 对齐 mihomo adapter/Outbound/shadowsocks.go：
 *          ListenPacketContext 创建真实 UDP socket + DialPacketConn
 *          （逐包 AEAD），UDPOverTCP 才是可选的 TCP 封装模式。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include <common/Core/ByteSpan.hpp>
#include <common/Core/Error.hpp>
#include <common/Core/Memory/Container.hpp>
#include <common/Core/Memory/Pointer.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Protocols/Shadowsocks2022/Codec.hpp>
#include <common/Protocols/Shadowsocks2022/Types.hpp>

namespace Preview::Shadowsocks2022
{

    namespace ss = Preview::Shadowsocks2022;

    /**
     * @class Dgram
     * @brief SS2022 UDP 包连接对象（Transmission 装饰器）
     * @details 持有底层数据报传输的独占所有权，对外暴露包级 API
     * （AsyncSendTo / AsyncReceiveFrom），内部完成逐包 AEAD
     * 编解码（Codec.hpp 纯函数）。由工厂（ConnectPacket /
     * AcceptPacket）创建。
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Dgram : public Preview::Transmission, public std::enable_shared_from_this<Dgram<Memory>>
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param upstream 底层数据报传输（已 Connect/Bind，所有权移交）
         * @param key 16 字节 UDP 密钥（PSK 派生）
         */
        explicit Dgram(SharedTransmission upstream, std::array<std::uint8_t, 16> key)
            : next_layer_(std::move(upstream)), key_(key)
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return next_layer_->Executor();
        }

        /**
         * @brief 传输类型（数据报）
         */
        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::udp;
        }

        /**
         * @brief 发送一个 UDP 数据报（WriteTo 语义，逐包 AEAD）
         * @param dest 目标地址（内嵌于包）
         * @param payload 载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncSendTo(const ss::Address &dest, std::span<const std::uint8_t> payload)
            -> net::awaitable<Error>
        {
            if (!ss::BuildUdpPacket(ss::UdpBuildInput{key_, ++PacketId_, &dest, payload}, TxWire_))
            {
                co_return Error::bad_length;
            }
            std::error_code ec;
            const auto n = co_await next_layer_->AsyncWriteSome(
                AsBytes(std::span<const std::uint8_t>(TxWire_)), ec);
            if (ec || n != TxWire_.size())
            {
                co_return Error::io_error;
            }
            co_return Error::none;
        }

        /**
         * @brief 接收一个 UDP 数据报（ReadFrom 语义，逐包 AEAD）
         * @param src 输出源地址（包内目标）
         * @param payload 输出载荷
         * @return 错误码
         */
        [[nodiscard]] auto AsyncReceiveFrom(ss::Address &src, std::vector<std::uint8_t> &payload)
            -> net::awaitable<Error>
        {
            std::array<std::uint8_t, 64 * 1024> buf{};
            std::error_code ec;
            const auto n = co_await next_layer_->AsyncReadSome(AsBytes(std::span<std::uint8_t>(buf)), ec);
            if (ec)
            {
                co_return Error::io_error;
            }
            if (n == 0)
            {
                co_return Error::unexpected_eof;
            }
            co_return ss::ParseUdpPacket(
                ss::UdpParseInput{key_, std::span<const std::uint8_t>(buf.data(), n), &src, &payload});
        }

        /**
         * @brief 透传读取（底层数据报原样）
         */
        [[nodiscard]] auto AsyncReadSome(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await next_layer_->AsyncReadSome(Buffer, ec);
        }

        /**
         * @brief 透传写入（底层数据报原样）
         */
        [[nodiscard]] auto AsyncWriteSome(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await next_layer_->AsyncWriteSome(Buffer, ec);
        }

        /**
         * @brief 关闭底层传输
         */
        void Close() override
        {
            next_layer_->Close();
        }

        /**
         * @brief 取消挂起操作
         */
        void Cancel() override
        {
            next_layer_->Cancel();
        }

        /**
         * @brief 获取底层传输（装饰器链导航）
         */
        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto Release() -> SharedTransmission override
        {
            return std::move(next_layer_);
        }

        /**
         * @brief 获取底层传输
         */
        [[nodiscard]] auto Stream() const noexcept -> SharedTransmission
        {
            return next_layer_;
        }

    private:
        SharedTransmission next_layer_;   ///< 底层数据报传输（独占所有权）
        std::array<std::uint8_t, 16> key_; ///< UDP 会话密钥（PSK 派生）
        std::uint64_t PacketId_{0};       ///< 包序号（自增，Nonce 派生）
        Memory mem_;                       ///< 会话内存策略（Arena，热路径零释放分配）
        typename std::template Buffer<std::uint8_t> TxWire_{mem_.Arena()}; ///< 发送缓冲（Arena 复用，热路径零分配）
    };

    /// 包连接共享指针
    using SharedDgram = std::shared_ptr<Dgram<>>;

} // namespace Preview::Shadowsocks2022
