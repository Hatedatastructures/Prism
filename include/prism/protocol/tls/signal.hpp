/**
 * @file signal.hpp
 * @brief TLS ClientHello 解析器
 * @details 解析 TLS 记录层的 ClientHello 消息，提取 SNI、key_share 公钥、
 * session_id 和 supported_versions 等关键字段。解析器是无状态的，
 * 所有方法均为纯函数。该模块是中立的共享层，供 recognition 和 stealth
 * 模块共同使用。
 */

#pragma once

#include <cstdint>
#include <span>
#include <utility>
#include <prism/protocol/tls/types.hpp>
#include <prism/memory/container.hpp>
#include <prism/fault/code.hpp>
#include <boost/asio.hpp>

namespace psm::channel::transport
{
    class transmission;
} // namespace psm::channel::transport

namespace psm::protocol::tls
{
    namespace net = boost::asio;

    /**
     * @brief 读取完整的 TLS 记录
     * @details 从传输层读取完整的 TLS 记录（含 5 字节 record header）。
     * 调用方应确保 transport 已包装 preview（如有预读数据）。
     * @param transport 底层传输（应包含预读数据）
     * @return 异步操作，返回错误码和完整 TLS 记录
     */
    auto read_tls_record(channel::transport::transmission &transport)
        -> net::awaitable<std::pair<fault::code, memory::vector<std::uint8_t>>>;

    /**
     * @brief 读取完整的 TLS 记录（带已预读数据）
     * @details 从传输层读取完整的 TLS 记录，使用已预读的数据作为前缀。
     * @param transport 底层传输
     * @param preread 已预读的数据
     * @return 异步操作，返回错误码和完整 TLS 记录
     */
    auto read_tls_record(channel::transport::transmission &transport, std::span<const std::byte> preread)
        -> net::awaitable<std::pair<fault::code, memory::vector<std::uint8_t>>>;

    /**
     * @brief 解析 ClientHello 并提取特征
     * @details 从完整的 TLS 记录中提取 ClientHello 消息的关键字段，
     * 包括 SNI、key_share 公钥、session_id 和 supported_versions
     * @param record 完整的 TLS 记录（含 record header）
     * @return 错误码和解析后的特征结构
     */
    [[nodiscard]] auto parse_client_hello(std::span<const std::uint8_t> record)
        -> std::pair<fault::code, client_hello_features>;

} // namespace psm::protocol::tls
