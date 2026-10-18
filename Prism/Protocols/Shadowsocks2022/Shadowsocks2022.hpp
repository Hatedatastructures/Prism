/**
 * @file Shadowsocks2022.hpp
 * @brief Shadowsocks 2022 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / ConnectPacket（客户端）、
 *   Accept / AcceptPacket（服务端）——握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp，chunk 加解密数据面）、
 *   Dgram（包，Dgram.hpp，逐包 AEAD）
 * - 编解码/密码学：Codec.hpp（头部编解码 + KDF + chunk + 握手 + UDP 数据报）
 */

#pragma once
#include <boost/asio/awaitable.hpp>
#include <array>
#include <cstddef>
#include <cstring>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Utility/Crypto/Base64.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Transport/Unreliable.hpp>
#include <Prism/Protocols/Shadowsocks2022/Conn.hpp>
#include <Prism/Protocols/Shadowsocks2022/Dgram.hpp>
#include <Prism/Protocols/Shadowsocks2022/Types.hpp>

namespace Prism::Shadowsocks2022
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct ClientConfig
     * @brief SS2022 客户端配置
     * @details 只保存已在配置冷路径解码完成的 16 字节 PSK。
     */
    struct ClientConfig
    {
        /// 唯一客户端预共享密钥；配置冷路径必须先通过 DecodePsk 解码。
        std::array<std::uint8_t, 16> Psk{};
    };

    /**
     * @struct ServerConfig
     * @brief SS2022 服务端配置
     * @details 只保存已在配置冷路径解码完成的 16 字节 PSK、时间戳窗口和
     *          独立 UDP 数据报开关。
     * 构造后只读。
     */
    struct ServerConfig
    {
        /// 唯一服务端预共享密钥；配置冷路径必须先通过 DecodePsk 解码。
        std::array<std::uint8_t, 16> Psk{};
        /// 时间戳容忍窗口（秒）
        std::uint64_t TimeWindow{90};
        /// 唯一 owning typed 认证器。
        Prism::SharedAuthenticator Authenticator{};
        /// 是否允许独立 UDP 数据报通道
        bool EnableUdp{true};

    };

    /**
     * @struct AcceptPacketParameters
     * @brief Shadowsocks 2022 服务端 UDP 装配参数
     * @details Executor、端口与 Config 按值拥有；Bound 只在成功返回前写入真实端点，
     *          调用方须保持输出地址有效至 awaitable 完成。
     */
    struct AcceptPacketParameters
    {
        Net::any_io_executor Executor;
        unsigned short Port;
        ServerConfig Config;
        Net::ip::udp::endpoint *Bound{nullptr};
    };

    /** @brief 握手成功后的唯一流会话和解析请求结果。 */
    struct AcceptedConnection final
    {
        Message Request;
        SharedConn Connection;
    };

    namespace Detail
    {
        /** @brief 失败工厂关闭原 socket 并等候活动退栈，不覆盖首个工厂错误。 */
        [[nodiscard]] inline auto RetireFailedPacketSocket(
            Prism::SharedTransmission Socket) -> Net::awaitable<void>
        {
            if (!Socket)
            {
                co_return;
            }
            (void)Socket->Close();
            (void)co_await Socket->Activity()->Drain();
        }
    }

    // =========================================================================
    // 工具
    // =========================================================================

    /**
     * @brief 解码配置中的 16 字节 PSK
     * @param Password Base64 编码的原始 PSK
     * @return 长度正确时返回 PSK，否则返回空
     */
    [[nodiscard]] inline auto DecodePsk(std::string_view Password)
        -> std::optional<std::array<std::uint8_t, 16>>
    {
        const auto Decoded = Prism::Crypto::Base64Decode(Password);
        if (Decoded.size() != 16)
        {
            return std::nullopt;
        }
        std::array<std::uint8_t, 16> Psk{};
        std::memcpy(Psk.data(), Decoded.data(), Psk.size());
        return Psk;
    }

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成 salt 握手
     * @param Upstream 上游传输（所有权移交）
     * @param Config 客户端配置
     * @param Target 目标地址
     * @return 成功时返回拥有型协议连接；失败时返回完整 Failure。
     */
    [[nodiscard]] inline auto Connect(
        SharedTransmission Upstream,
        const ClientConfig &Config,
        const Address &Target)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>
    {
        if (!Upstream)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Upstream);
        if (!Prepared)
        {
            co_return std::unexpected(Prepared.error());
        }
        auto Admission = std::move(*Prepared);
        std::shared_ptr<Conn<>> Connection;
        std::optional<Prism::Fault::Failure> CreationFailure;
        try
        {
            Connection = std::make_shared<Conn<>>(ConnOptions{
                .Executor = Upstream->Executor(), .Psk = Config.Psk});
        }
        catch (...)
        {
            CreationFailure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
        }
        if (CreationFailure)
        {
            co_return std::unexpected(co_await Admission.Retire(*CreationFailure));
        }
        auto Handshake = Prism::Fault::Failure{};
        try
        {
            Handshake = co_await Connection->WriteHandshake(Upstream, Target);
        }
        catch (...)
        {
            Handshake = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
        }
        if (Handshake.Failed())
        {
            co_return std::unexpected(co_await Admission.Retire(Handshake));
        }
        Admission.Release();
        co_return SharedConn(std::move(Connection));
    }

    /**
     * @brief 创建客户端独立 UDP 数据报连接。
     * @param Executor socket 固定使用的执行器。
     * @param Remote 按值接管的代理服务器端点文本。
     * @param Config 按值接管的客户端密钥配置。
     * @return 成功返回非空数据报连接；失败返回完整首个 Failure。
     * @details 直接创建 UDP socket 并逐包 AEAD 加密，无 TCP 握手。配置或连接失败后，
     *          工厂沿同一 socket 发起 Close 并等待 Activity 退栈；清理错误保留在载体 owner，
     *          不替换原始工厂 Failure。取消由关闭与 Activity 生命周期承接。
     */
    [[nodiscard]] inline auto ConnectPacket(
        Net::any_io_executor Executor,
        std::string Remote,
        ClientConfig Config)
        -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>
    {
        std::shared_ptr<Prism::Transport::Unreliable> Udp;
        try
        {
            Udp = std::make_shared<Prism::Transport::Unreliable>(Executor);
        }
        catch (...)
        {
            co_return std::unexpected(
                Prism::Contract::InboundAdmission::ExceptionFailure(std::current_exception()));
        }
        const auto Connected = Udp->Connect(Remote);
        if (!Connected)
        {
            const auto Failure = Connected.error();
            co_await Detail::RetireFailedPacketSocket(Udp);
            co_return std::unexpected(Failure);
        }
        SharedDgram Datagram;
        std::optional<Prism::Fault::Failure> CreationFailure;
        try
        {
            Datagram = std::make_shared<Dgram<>>(Udp, Config.Psk, UdpRole::Client);
        }
        catch (...)
        {
            CreationFailure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
        }
        if (CreationFailure)
        {
            co_await Detail::RetireFailedPacketSocket(Udp);
            co_return std::unexpected(*CreationFailure);
        }
        co_return Datagram;
    }

    /**
     * @brief 接收服务端流连接并完成首包握手
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 错误码、解析的请求与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Accept(
        SharedTransmission Upstream,
        const ServerConfig &Config)
        -> Net::awaitable<std::expected<AcceptedConnection, Prism::Fault::Failure>>
    {
        if (!Upstream)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        std::shared_ptr<Conn<>> Connection;
        try
        {
            Connection = std::make_shared<Conn<>>(ConnOptions{
                .Executor = Upstream->Executor(), .Psk = Config.Psk,
                .TimeWindow = Config.TimeWindow,
                .AuthenticatorOwner = Config.Authenticator});
        }
        catch (...)
        {
            co_return std::unexpected(
                Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception()));
        }
        std::expected<Message, Prism::Fault::Failure> Handshake{
            std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError})};
        try
        {
            Handshake = co_await Connection->ReadHandshake(std::move(Upstream));
        }
        catch (...)
        {
            Handshake = std::unexpected(
                Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception()));
        }
        if (!Handshake)
        {
            (void)Connection->Close();
            co_return std::unexpected(Handshake.error());
        }
        co_return AcceptedConnection{std::move(*Handshake), SharedConn(std::move(Connection))};
    }

    /**
     * @brief 创建服务端独立 UDP 数据报连接。
     * @param Params 按值接管执行器、端口与配置；Bound 仅作为短期输出借用。
     * @return 成功返回非空数据报连接；禁用 UDP、绑定或分配失败返回完整 Failure。
     * @details 绑定端口并逐包 AEAD 解密；无 TCP 握手。失败后沿同一 socket 发起 Close 并等待
     *          Activity 退栈，清理失败不覆盖绑定/构造首因，原载体控制 owner 保留未完成关闭。
     */
    [[nodiscard]] inline auto AcceptPacket(AcceptPacketParameters Params)
        -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>
    {
        if (!Params.Config.EnableUdp)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
        }
        std::shared_ptr<Prism::Transport::Unreliable> Udp;
        try
        {
            Udp = std::make_shared<Prism::Transport::Unreliable>(Params.Executor);
        }
        catch (...)
        {
            co_return std::unexpected(
                Prism::Contract::InboundAdmission::ExceptionFailure(std::current_exception()));
        }
        const auto Bound = Udp->Bind(Params.Port);
        if (!Bound)
        {
            const auto Failure = Bound.error();
            co_await Detail::RetireFailedPacketSocket(Udp);
            co_return std::unexpected(Failure);
        }
        // 独立 UDP 服务端必须按每个已认证数据报的来源回包，不能把
        // Unreliable 的首次来源捕获为全局共享远端。
        Udp->AllowAnyPeer();
        SharedDgram Datagram;
        std::optional<Prism::Fault::Failure> CreationFailure;
        try
        {
            Datagram = std::make_shared<Dgram<>>(Udp, Params.Config.Psk, UdpRole::Server);
        }
        catch (...)
        {
            CreationFailure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
        }
        if (CreationFailure)
        {
            co_await Detail::RetireFailedPacketSocket(Udp);
            co_return std::unexpected(*CreationFailure);
        }
        if (Params.Bound)
        {
            *Params.Bound = Udp->LocalEndpoint();
        }
        co_return Datagram;
    }

} // namespace Prism::Shadowsocks2022
