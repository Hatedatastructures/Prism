/**
 * @file request.hpp
 * @brief TLS ClientHello 解析器
 * @details 解析 TLS 记录层的 ClientHello 消息，提取 SNI、key_share 公钥、
 * session_id 和 supported_versions 等关键字段，用于 Reality 协议的认证
 * 前置步骤：从客户端的 ClientHello 中获取认证所需的全部信息。
 * @note 解析器是无状态的，所有方法均为纯函数
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <prism/memory/container.hpp>
#include <prism/fault/code.hpp>
#include <boost/asio.hpp>

namespace psm::channel::transport
{
    class transmission;
} // namespace psm::channel::transport

namespace psm::stealth::reality
{
    namespace net = boost::asio;

    /**
     * @struct client_hello_info
     * @brief ClientHello 解析结果
     * @details 存储从 TLS ClientHello 消息中提取的认证所需字段
     */
    struct client_hello_info
    {
        memory::vector<std::uint8_t> raw_message;         // 完整 ClientHello handshake 消息字节，用于 transcript hash 计算
        std::array<std::uint8_t, 32> random{};            // 客户端随机数（32 字节）
        memory::vector<std::uint8_t> session_id;          // session_id（包含 Reality 的 short_id 和认证数据）
        memory::string server_name;                       // SNI 服务器名称
        std::array<std::uint8_t, 32> client_public_key{}; // key_share 扩展中的 X25519 公钥（32 字节）
        bool has_client_public_key = false;               // 是否包含客户端公钥
        memory::vector<std::uint16_t> supported_versions; // 客户端支持的 TLS 版本列表
    };

    /**
     * @brief 读取完整的 TLS 记录
     * @details 从传输层读取完整的 TLS 记录，处理已预读的初始数据和剩余数据
     * @param transport 底层 TCP 传输
     * @param initial_data probe 阶段已读取的前 24 字节
     * @return net::awaitable<std::pair<fault::code, memory::vector<std::uint8_t>>>
     * 异步操作，返回错误码和完整 TLS 记录（含 5 字节 record header）
     */
    auto read_tls_record(channel::transport::transmission &transport, std::span<const std::byte> initial_data)
        -> net::awaitable<std::pair<fault::code, memory::vector<std::uint8_t>>>;

    /**
     * @brief 解析 ClientHello
     * @details 从完整的 TLS 记录中提取 ClientHello 消息的关键字段，
     * 包括 SNI、key_share 公钥、session_id 和 supported_versions
     * @param raw_tls_record 完整的 TLS 记录（含 record header）
     * @return std::pair<fault::code, client_hello_info> 错误码和解析结果
     */
    [[nodiscard]] auto parse_client_hello(std::span<const std::uint8_t> raw_tls_record)
        -> std::pair<fault::code, client_hello_info>;
} // namespace psm::stealth::reality
