/**
 * @file tracker.hpp
 * @brief SS2022 UDP 会话跟踪器
 * @details 按 SessionID 跟踪 UDP 客户端地址，管理 AEAD 派生密钥缓存
 * 和 PacketID 滑动窗口。每个 worker 持有独立实例，无需线程同步
 */
#pragma once

#include <prism/crypto/aead.hpp>
#include <prism/crypto/blake3.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/protocol/shadowsocks/constants.hpp>
#include <prism/protocol/shadowsocks/framing.hpp>
#include <prism/protocol/shadowsocks/util/replay.hpp>

#include <boost/asio.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>


namespace psm::protocol::shadowsocks
{

    namespace net = boost::asio;

    /**
     * @struct udp_session_entry
     * @brief 单个 UDP 会话的运行时状态
     * @details 包含客户端端点、AEAD 上下文缓存、PacketID 滑动窗口等
     */
    struct udp_session
    {
        net::ip::udp::endpoint client_endpoint; // 客户端最新端点地址（NAT 遍历用）
        std::chrono::steady_clock::time_point last_seen; // 最后活跃时间
        std::unique_ptr<crypto::aead_context> aead_ctx; // 缓存的 AEAD 上下文（AES-GCM 变体用派生密钥）
        std::unique_ptr<crypto::aead_context> chacha20_ctx; // 缓存的 XChaCha20 AEAD 上下文（避免逐包创建）
        replay_window packet_ids; // PacketID 滑动窗口重放过滤器
        std::uint64_t srv_pkt_id{0}; // 服务端 PacketID 计数器
    };

    /**
     * @struct session_create_opts
     * @brief get_or_create 参数聚合
     * @details 将 get_or_create 的 4 个参数收敛到单结构体，
     * 符合 Rule 1（函数参数不超过 3 个）。
     */
    struct session_create_opts
    {
        const std::array<std::uint8_t, session_id_len> &relay_id; ///< SS2022 8-byte relay session identifier
        const net::ip::udp::endpoint &endpoint;                     ///< 客户端端点
        const memory::vector<std::uint8_t> &psk;                    ///< PSK 字节
        cipher_method method;                                        ///< 加密方法
    };

    /**
     * @class session_tracker
     * @brief UDP 会话管理器
     * @details 按 SessionID 管理所有活跃 UDP 会话，提供 TTL 自动过期。
     * 每个 worker 线程持有独立实例，无需线程同步
     * @note 使用固定 8 字节 array 作为 key，避免 string 堆分配
     */
    class session_tracker
    {
        using sess_key = std::array<std::uint8_t, session_id_len>;

        struct sess_hash
        {
            [[nodiscard]] auto operator()(const sess_key &k) const noexcept
                -> std::size_t
            {
                std::size_t h = 0xcbf29ce484222325ULL;
                for (auto b : k)
                {
                    h ^= static_cast<std::size_t>(b);
                    h *= 0x100000001b3ULL;
                }
                return h;
            }
        };

    public:
        /**
         * @brief 构造会话跟踪器
         * @param ttl_seconds 会话空闲超时时间（秒）
         */
        explicit session_tracker(std::int64_t ttl_seconds = 60)
            : ttl_(std::chrono::seconds(ttl_seconds))
        {
        }

        /**
         * @brief 查找或创建会话
         * @details 如果会话已存在则更新端点和活跃时间并返回，
         * 否则创建新会话。AES-GCM 变体需要派生会话子密钥
         * @param opts 创建选项（relay_id + endpoint + psk + method）
         * @return 会话条目共享指针
         */
        [[nodiscard]] auto get_or_create(const session_create_opts &opts)
            -> std::shared_ptr<udp_session>
        {
            // 分摊清理：仅当距上次清理超过 1 秒时才执行
            const auto now = std::chrono::steady_clock::now();
            if (now - last_cleanup_ >= std::chrono::seconds(1))
            {
                cleanup();
                last_cleanup_ = now;
            }

            if (const auto it = sessions_.find(opts.relay_id); it != sessions_.end())
            {
                it->second->client_endpoint = opts.endpoint;
                it->second->last_seen = now;
                return it->second;
            }

            auto entry = std::make_shared<udp_session>();
            entry->client_endpoint = opts.endpoint;
            entry->last_seen = now;

            // AES-GCM 变体需要派生会话子密钥
            if (opts.method != cipher_method::chacha20_poly1305)
            {
                entry->aead_ctx = derive_aead(opts.relay_id, opts.psk, opts.method);
            }

            sessions_.emplace(opts.relay_id, entry);
            return entry;
        }

        /**
         * @brief 查找已有会话（不创建）
         * @param relay_id 8-byte SS2022 relay session identifier
         * @return 会话条目共享指针，不存在则返回 nullptr
         */
        [[nodiscard]] auto find(const std::array<std::uint8_t, session_id_len> &relay_id)
            -> std::shared_ptr<udp_session>
        {
            if (const auto it = sessions_.find(relay_id); it != sessions_.end())
            {
                return it->second;
            }
            return nullptr;
        }

        /**
         * @brief 清理过期会话
         * @details 移除超过 TTL 的会话条目
         */
        void cleanup()
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

    private:
        /**
         * @brief 为 AES-GCM 会话派生 AEAD 上下文
         * @details 密钥材料为 PSK + SessionID，使用 BLAKE3 KDF 派生
         * @param relay_id 8-byte SS2022 relay session identifier
         * @param psk PSK 字节
         * @param method 加密方法
         * @return AEAD 上下文智能指针
         */
        [[nodiscard]] static auto derive_aead(const std::array<std::uint8_t, session_id_len> &relay_id, const memory::vector<std::uint8_t> &psk, cipher_method method)
            -> std::unique_ptr<crypto::aead_context>
        {
            // 密钥材料：PSK + relay session ID（栈分配避免堆分配）
            std::array<std::uint8_t, 64> material{}; // 足够容纳最大 PSK(32) + relay_id(8)
            const auto total = psk.size() + session_id_len;
            std::memcpy(material.data(), psk.data(), psk.size());
            std::memcpy(material.data() + psk.size(), relay_id.data(), session_id_len);

            constexpr auto ctx_str = kdf_context; // SIP022: "shadowsocks 2022 session subkey"
            const auto key_len = format::keysalt_len(method);
            const auto key = crypto::derive_key(
                ctx_str, std::span<const std::uint8_t>(material.data(), total), key_len);

            crypto::aead_cipher cipher;
            if (method == cipher_method::aes_128_gcm)
            {
                cipher = crypto::aead_cipher::aes_128_gcm;
            }
            else
            {
                cipher = crypto::aead_cipher::aes_256_gcm;
            }

            return std::make_unique<crypto::aead_context>(cipher, std::span(key));
        }

        memory::unordered_map<sess_key, std::shared_ptr<udp_session>,
                           sess_hash>
            sessions_; // 会话映射表
        std::chrono::seconds ttl_; // 会话 TTL
        std::chrono::steady_clock::time_point last_cleanup_{}; // 上次清理时间
    };
} // namespace psm::protocol::shadowsocks
