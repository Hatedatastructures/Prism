/**
 * @file Shadowsocks2022.hpp
 * @brief Shadowsocks 2022 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / ConnectPacket（客户端）、
 *   Accept / AcceptPacket（服务端）——握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp，chunk 加解密数据面）、
 *   Dgram（包，Dgram.hpp，逐包 AEAD）
 * - 编解码/密码学：ChunkCodec.hpp、KeyDerivation.hpp、RequestWire.hpp、
 *   RequestState.hpp、ResponseCodec.hpp
 */

#pragma once
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Shadowsocks2022/ChunkCodec.hpp>
#include <Prism/Protocols/Shadowsocks2022/Conn.hpp>
#include <Prism/Protocols/Shadowsocks2022/Dgram.hpp>
#include <Prism/Protocols/Shadowsocks2022/KeyDerivation.hpp>
#include <Prism/Protocols/Shadowsocks2022/RequestState.hpp>
#include <Prism/Protocols/Shadowsocks2022/RequestWire.hpp>
#include <Prism/Protocols/Shadowsocks2022/ResponseCodec.hpp>
#include <Prism/Protocols/Shadowsocks2022/Types.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>

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
        Net::ip::udp::endpoint* Bound{nullptr};
    };

    /** @brief 握手成功后的唯一流会话和解析请求结果。 */
    struct AcceptedConnection final
    {
        Message Request;
        SharedConn Connection;
    };

    // =========================================================================
    // 工具
    // =========================================================================

    /**
     * @brief 解码配置中的 16 字节 PSK
     * @param Password Base64 编码的原始 PSK
     * @return 长度正确时返回 PSK，否则返回空
     */
    [[nodiscard]] auto DecodePsk(std::string_view Password) -> std::optional<std::array<std::uint8_t, 16>>;

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
    [[nodiscard]] auto Connect(SharedTransmission Upstream, const ClientConfig& Config, const Address& Target)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>;

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
    [[nodiscard]] auto ConnectPacket(Net::any_io_executor Executor, std::string Remote, ClientConfig Config)
        -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>;

    /**
     * @brief 接收服务端流连接并完成首包握手
     * @param Upstream 上游传输（所有权移交）
     * @param Config 服务端配置
     * @return 错误码、解析的请求与协议连接（失败时连接为空）
     */
    [[nodiscard]] auto Accept(SharedTransmission Upstream, const ServerConfig& Config)
        -> Net::awaitable<std::expected<AcceptedConnection, Prism::Fault::Failure>>;

    /**
     * @brief 创建服务端独立 UDP 数据报连接。
     * @param Params 按值接管执行器、端口与配置；Bound 仅作为短期输出借用。
     * @return 成功返回非空数据报连接；禁用 UDP、绑定或分配失败返回完整 Failure。
     * @details 绑定端口并逐包 AEAD 解密；无 TCP 握手。失败后沿同一 socket 发起 Close 并等待
     *          Activity 退栈，清理失败不覆盖绑定/构造首因，原载体控制 owner 保留未完成关闭。
     */
    [[nodiscard]] auto AcceptPacket(AcceptPacketParameters Params)
        -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>;

} // namespace Prism::Shadowsocks2022
