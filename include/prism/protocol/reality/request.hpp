/**
 * @file request.hpp
 * @brief TLS ClientHello 解析器
 * @details 解析 TLS 记录层的 ClientHello 消息，提取 SNI、key_share 公钥、
 * session_id 和 supported_versions 等关键字段。用于 Reality 协议的认证
 * 前置步骤：从客户端的 ClientHello 中获取认证所需的全部信息。
 * @note 解析器是无状态的，所有方法均为纯函数。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <prism/memory/container.hpp>
#include <prism/fault/code.hpp>
#include <prism/channel/transport/transmission.hpp>
#include <boost/asio.hpp>

namespace psm::protocol::reality
{
    namespace net = boost::asio;

    /**
     * @struct client_hello_info
     * @brief ClientHello 解析结果
     * @details 包含从 TLS ClientHello 中提取的所有关键字段。
     * raw_message 保存完整的 handshake 消息（用于 transcript hash），
     * 其他字段是解析后的结构化数据。
     */
    struct client_hello_info
    {
        /// 完整 ClientHello handshake 消息字节
        /// 格式：HandshakeType(1) + Length(3) + ClientHello body
        /// 用于 TLS 1.3 transcript hash 计算
        memory::vector<std::uint8_t> raw_message;

        /// 客户端随机数（32 字节）
        std::array<std::uint8_t, 32> random{};

        /// session_id（包含 Reality 的 short_id 和认证数据）
        memory::vector<std::uint8_t> session_id;

        /// SNI 服务器名称
        memory::string server_name;

        /// key_share 扩展中的 X25519 公钥（32 字节）
        std::array<std::uint8_t, 32> client_public_key{};
        bool has_client_public_key = false;

        /// 客户端支持的 TLS 版本列表
        memory::vector<std::uint16_t> supported_versions;

    };

    /**
     * @brief 读取完整的 TLS 记录
     * @param transport 底层 TCP 传输
     * @param initial_data probe 阶段已读取的前 24 字节
     * @return 错误码和完整 TLS 记录（含 5 字节 record header）
     * @details 从 transport 读取完整的 TLS 记录。
     * initial_data 包含 TLS 记录的前 24 字节（已由 probe 读取），
     * 函数从 record header 中解析出总长度，然后继续读取剩余数据。
     * @note 协程函数，使用 co_await 进行异步读取。
     */
    auto read_tls_record(channel::transport::transmission &transport, std::span<const std::byte> initial_data)
        -> net::awaitable<std::pair<fault::code, memory::vector<std::uint8_t>>>;

    /**
     * @brief 解析 ClientHello
     * @param raw_tls_record 完整的 TLS 记录（含 record header）
     * @return 错误码和解析结果的配对
     * @details 从 TLS 记录中解析 ClientHello handshake 消息。
     * 提取 session_id、SNI、key_share、supported_versions 等字段。
     * raw_message 字段保存完整的 handshake 消息用于后续 transcript hash。
     */
    [[nodiscard]] auto parse_client_hello(std::span<const std::uint8_t> raw_tls_record)
        -> std::pair<fault::code, client_hello_info>;
} // namespace psm::protocol::reality
