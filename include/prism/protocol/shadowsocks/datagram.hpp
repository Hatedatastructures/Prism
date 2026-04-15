/**
 * @file datagram.hpp
 * @brief SS2022 UDP 数据报中继器
 * @details 无状态的逐包 AEAD 加解密，用于 SS2022 UDP 传输。
 * 与 TCP relay（transmission 子类）不同，udp_relay 是独立组件，
 * 每个 UDP 包独立加解密，无流状态。
 */

#pragma once

#include <prism/protocol/shadowsocks/constants.hpp>
#include <prism/protocol/shadowsocks/config.hpp>
#include <prism/protocol/shadowsocks/message.hpp>
#include <prism/protocol/shadowsocks/format.hpp>
#include <prism/protocol/shadowsocks/tracker.hpp>
#include <prism/crypto/aead.hpp>
#include <prism/crypto/block.hpp>
#include <prism/memory.hpp>
#include <boost/asio.hpp>
#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace psm::protocol::shadowsocks
{
    namespace net = boost::asio;

    /**
     * @struct udp_decrypted_packet
     * @brief 解密后的 UDP 数据包
     * @details payload 以 span 零拷贝指向 buffer 内的子区间，
     *          buffer 使用 PMR vector 持有解密后的明文数据。
     */
    struct udp_decrypted_packet
    {
        /// 会话标识
        std::array<std::uint8_t, session_id_len> session_id{};

        /// 目标地址
        address destination_address;

        /// 目标端口
        std::uint16_t destination_port{0};

        /// 解密明文缓冲区（PMR），payload span 指向其子区间
        memory::vector<std::uint8_t> buffer{memory::current_resource()};

        /// 载荷数据（零拷贝，指向 buffer 内偏移）
        std::span<const std::uint8_t> payload;

        /// 发送者端点
        net::ip::udp::endpoint sender_endpoint;
    };

    /**
     * @class udp_relay
     * @brief SS2022 UDP 无状态加解密器
     * @details 处理 SS2022 UDP 数据包的加解密，支持两种变体：
     * - AES-GCM：双层加密（AES-ECB SeparateHeader + AES-GCM body）
     * - ChaCha20：单层 XChaCha20-Poly1305 加密
     */
    class udp_relay : public std::enable_shared_from_this<udp_relay>
    {
    public:
        explicit udp_relay(const config &cfg,
                           std::shared_ptr<session_tracker> sessions)
            : config_(cfg), session_tracker_(std::move(sessions))
        {
            const auto [ec, psk_bytes] = format::decode_psk(config_.psk);
            if (ec == fault::code::success)
            {
                psk_ = std::move(psk_bytes);
            }
            method_ = format::resolve_cipher_method(config_.method, psk_.size());
        }

        /**
         * @brief 解密入站 UDP 数据包
         * @param packet 原始密文数据包
         * @param sender 发送者端点
         * @return 错误码和解密结果
         */
        auto decrypt_inbound(std::span<const std::byte> packet,
                             const net::ip::udp::endpoint &sender)
            -> std::pair<fault::code, udp_decrypted_packet>;

        /**
         * @brief 加密出站 UDP 数据包
         * @param payload 明文载荷
         * @param session_id 目标会话 ID
         * @param entry 目标会话条目
         * @return 错误码和密文数据包
         */
        auto encrypt_outbound(std::span<const std::byte> payload,
                              const std::array<std::uint8_t, session_id_len> &session_id,
                              const std::shared_ptr<udp_session_entry> &entry)
            -> std::pair<fault::code, std::vector<std::byte>>;

        /**
         * @brief 获取加密方法
         */
        [[nodiscard]] auto method() const noexcept -> cipher_method { return method_; }

    private:
        config config_;
        std::vector<std::uint8_t> psk_;
        cipher_method method_{cipher_method::aes_128_gcm};
        std::shared_ptr<session_tracker> session_tracker_;

        // === AES-GCM 变体 ===

        auto decrypt_aes_gcm(std::span<const std::byte> packet,
                             const net::ip::udp::endpoint &sender)
            -> std::pair<fault::code, udp_decrypted_packet>;

        auto encrypt_aes_gcm(std::span<const std::byte> payload,
                             const std::array<std::uint8_t, session_id_len> &session_id,
                             const std::shared_ptr<udp_session_entry> &entry)
            -> std::pair<fault::code, std::vector<std::byte>>;

        // === ChaCha20 变体 ===

        auto decrypt_chacha20(std::span<const std::byte> packet,
                              const net::ip::udp::endpoint &sender)
            -> std::pair<fault::code, udp_decrypted_packet>;

        auto encrypt_chacha20(std::span<const std::byte> payload,
                              const std::array<std::uint8_t, session_id_len> &session_id,
                              const std::shared_ptr<udp_session_entry> &entry)
            -> std::pair<fault::code, std::vector<std::byte>>;

        // === 工具函数 ===

        /// 构造 AES-GCM 12 字节 nonce：sessionID[4..8] + packetID[0..8]
        [[nodiscard]] static auto construct_nonce_aes(
            const std::array<std::uint8_t, session_id_len> &session_id,
            const std::array<std::uint8_t, packet_id_len> &packet_id)
            -> std::array<std::uint8_t, 12>;

        /// 从缓冲区读取 8 字节大端序 uint64
        [[nodiscard]] static auto read_u64_be(const std::uint8_t *data) -> std::uint64_t;

        /// 写入 8 字节大端序 uint64
        static void write_u64_be(std::uint8_t *data, std::uint64_t value);
    };

    using shared_udp_relay = std::shared_ptr<udp_relay>;

    inline auto make_udp_relay(const config &cfg,
                               std::shared_ptr<session_tracker> sessions) -> shared_udp_relay
    {
        return std::make_shared<udp_relay>(cfg, std::move(sessions));
    }
} // namespace psm::protocol::shadowsocks
