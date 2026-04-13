/**
 * @file tracker.hpp
 * @brief SS2022 UDP 会话跟踪器
 * @details 按 SessionID 跟踪 UDP 客户端地址，管理 AEAD 派生密钥缓存
 * 和 PacketID 滑动窗口。每个 worker 持有独立实例，避免跨线程竞争。
 */

#pragma once

#include <prism/protocol/shadowsocks/constants.hpp>
#include <prism/protocol/shadowsocks/replay.hpp>
#include <prism/protocol/shadowsocks/format.hpp>
#include <prism/crypto/aead.hpp>
#include <prism/crypto/blake3.hpp>
#include <boost/asio.hpp>
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace psm::protocol::shadowsocks
{
    namespace net = boost::asio;

    /**
     * @struct udp_session_entry
     * @brief 单个 UDP 会话的运行时状态
     */
    struct udp_session_entry
    {
        /// 客户端最新端点地址（NAT 遍历用）
        net::ip::udp::endpoint client_endpoint;

        /// 最后活跃时间
        std::chrono::steady_clock::time_point last_seen;

        /// 缓存的 AEAD 上下文（AES-GCM 变体用派生密钥）
        std::unique_ptr<crypto::aead_context> aead_ctx;

        /// PacketID 滑动窗口重放过滤器
        replay_window packet_ids;

        /// 服务端 PacketID 计数器
        std::uint64_t server_packet_id{0};
    };

    /**
     * @class session_tracker
     * @brief UDP 会话管理器
     * @details 按 SessionID 管理所有活跃 UDP 会话，提供 TTL 自动过期。
     * 线程安全，可跨多个 relay 共享。
     */
    class session_tracker
    {
    public:
        explicit session_tracker(std::int64_t ttl_seconds = 60)
            : ttl_(std::chrono::seconds(ttl_seconds))
        {
        }

        /**
         * @brief 查找或创建会话
         * @param session_id 8 字节 SessionID
         * @param endpoint 客户端端点
         * @param psk PSK 字节
         * @param method 加密方法
         * @return 会话条目共享指针
         */
        auto get_or_create(const std::array<std::uint8_t, session_id_len> &session_id,
                           const net::ip::udp::endpoint &endpoint,
                           const std::vector<std::uint8_t> &psk,
                           cipher_method method)
            -> std::shared_ptr<udp_session_entry>
        {
            std::lock_guard lock(mutex_);
            cleanup_locked();

            const auto key = to_key(session_id);

            if (const auto it = sessions_.find(key); it != sessions_.end())
            {
                it->second->client_endpoint = endpoint;
                it->second->last_seen = std::chrono::steady_clock::now();
                return it->second;
            }

            auto entry = std::make_shared<udp_session_entry>();
            entry->client_endpoint = endpoint;
            entry->last_seen = std::chrono::steady_clock::now();

            // AES-GCM 变体需要派生会话子密钥
            if (method != cipher_method::chacha20_poly1305)
            {
                entry->aead_ctx = derive_session_aead(session_id, psk, method);
            }

            sessions_.emplace(key, entry);
            return entry;
        }

        /**
         * @brief 查找已有会话（不创建）
         */
        auto find(const std::array<std::uint8_t, session_id_len> &session_id)
            -> std::shared_ptr<udp_session_entry>
        {
            std::lock_guard lock(mutex_);
            const auto key = to_key(session_id);

            if (const auto it = sessions_.find(key); it != sessions_.end())
            {
                return it->second;
            }
            return nullptr;
        }

        /**
         * @brief 清理过期会话
         */
        void cleanup()
        {
            std::lock_guard lock(mutex_);
            cleanup_locked();
        }

    private:
        void cleanup_locked()
        {
            const auto now = std::chrono::steady_clock::now();
            for (auto it = sessions_.begin(); it != sessions_.end();)
            {
                if (now - it->second->last_seen > ttl_)
                {
                    it = sessions_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }

        static auto to_key(const std::array<std::uint8_t, session_id_len> &session_id) -> std::string
        {
            return {reinterpret_cast<const char *>(session_id.data()), session_id.size()};
        }

        /// 为 AES-GCM 会话派生 AEAD 上下文
        static auto derive_session_aead(const std::array<std::uint8_t, session_id_len> &session_id,
                                        const std::vector<std::uint8_t> &psk,
                                        cipher_method method)
            -> std::unique_ptr<crypto::aead_context>
        {
            // 密钥材料：PSK + SessionID
            std::vector<std::uint8_t> material(psk.size() + session_id_len);
            std::memcpy(material.data(), psk.data(), psk.size());
            std::memcpy(material.data() + psk.size(), session_id.data(), session_id_len);

            constexpr auto ctx_str = kdf_context; // SIP022: "shadowsocks 2022 session subkey"
            const auto key_len = format::key_salt_length(method);
            const auto key = crypto::derive_key(
                ctx_str, std::span<const std::uint8_t>(material), key_len);

            const auto cipher = method == cipher_method::aes_128_gcm
                                    ? crypto::aead_cipher::aes_128_gcm
                                    : crypto::aead_cipher::aes_256_gcm;

            return std::make_unique<crypto::aead_context>(cipher, std::span(key));
        }

        std::unordered_map<std::string, std::shared_ptr<udp_session_entry>> sessions_;
        std::mutex mutex_;
        std::chrono::seconds ttl_;
    };
} // namespace psm::protocol::shadowsocks
