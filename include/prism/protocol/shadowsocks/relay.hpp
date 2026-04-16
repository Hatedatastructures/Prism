/**
 * @file relay.hpp
 * @brief SS2022 (SIP022) 协议中继器声明
 * @details SS2022 relay 是一个 AEAD 加密传输层装饰器。与 Trojan/VLESS 不同，
 * SS2022 relay 在整个会话生命周期内保持活跃，因为所有数据都经过 AEAD 加解密。
 * handshake() 解密请求头、验证时间戳、解析地址后，relay 继续作为 transmission
 * 提供加解密的读写操作。
 */

#pragma once

#include <boost/asio.hpp>
#include <prism/channel/transport/transmission.hpp>
#include <prism/protocol/shadowsocks/constants.hpp>
#include <prism/protocol/shadowsocks/message.hpp>
#include <prism/protocol/shadowsocks/config.hpp>
#include <prism/protocol/shadowsocks/salts.hpp>
#include <prism/protocol/shadowsocks/format.hpp>
#include <prism/protocol/analysis.hpp>
#include <prism/crypto/aead.hpp>
#include <prism/crypto/blake3.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/memory/container.hpp>
#include <memory>
#include <span>
#include <tuple>
#include <random>

namespace psm::protocol::shadowsocks
{
    namespace net = boost::asio;
    using shared_transmission = psm::channel::transport::shared_transmission;

    /**
     * @class relay
     * @brief SS2022 AEAD 流加密中继器
     * @details 继承 transmission，在底层传输层之上添加 SS2022 协议的 AEAD
     * 加解密功能。handshake() 完成后，async_read_some/async_write_some
     * 自动处理 AEAD 分帧加密/解密。
     *
     * 读取状态机：
     *   header → 解密 2B 长度 → payload → 解密 payload → 返回数据
     *
     * 写入：
     *   将数据分块 → 加密长度+payload → scatter-gather 写入底层
     */
    class relay : public channel::transport::transmission, public std::enable_shared_from_this<relay>
    {
    public:
        explicit relay(shared_transmission next_layer, const config &cfg,
                       std::shared_ptr<salt_pool> salts);

        // --- transmission 接口 ---
        auto executor() const -> executor_type override;
        auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;
        auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;
        void close() override;
        void cancel() override;

        // --- SS2022 接口 ---

        /**
         * @brief 执行 SS2022 握手
         * @details 读取请求 salt，派生会话密钥，解密固定/变长头，
         * 验证时间戳和 salt 唯一性，解析目标地址。
         * 握手成功后需调用 acknowledge() 发送响应。
         * @return 错误码和请求信息
         */
        auto handshake() -> net::awaitable<std::pair<fault::code, request>>;

        /**
         * @brief 发送 SS2022 握手响应
         * @details 必须在 handshake() 成功后调用。将响应发送延迟到上游拨号成功后，
         * 避免拨号失败时客户端收到误导性的成功响应。
         */
        auto acknowledge() -> net::awaitable<fault::code>;

        /**
         * @brief 获取解析后的目标地址
         */
        [[nodiscard]] auto target() const noexcept -> const analysis::target &
        {
            return target_;
        }

    private:
        shared_transmission next_layer_;
        config config_;
        std::shared_ptr<salt_pool> salt_pool_;

        // 加密状态
        std::unique_ptr<crypto::aead_context> decrypt_ctx_;
        std::unique_ptr<crypto::aead_context> encrypt_ctx_;
        cipher_method method_{cipher_method::aes_128_gcm};
        std::size_t key_salt_length_{16};

        // 解码后的 PSK
        std::vector<std::uint8_t> psk_;

        // 读取状态
        enum class read_phase
        {
            header, ///< 等待读取加密长度块
            payload ///< 等待读取加密 payload 块
        };
        read_phase read_phase_{read_phase::header};

        // 解密后的数据缓冲区
        memory::vector<std::byte> decrypted_;
        std::size_t decrypted_offset_{0};

        // 加密长度块缓冲区（2 + 16 = 18 字节）
        std::array<std::byte, length_block_size> length_buf_{};

        // 加密 payload 块缓冲区
        memory::vector<std::byte> chunk_buf_;

        // 当前 chunk 的 payload 长度（从长度块解密得到）
        std::uint16_t current_payload_len_{0};

        // 握手中的初始 payload（可能为空）
        memory::vector<std::byte> initial_payload_;
        std::size_t initial_offset_{0};

        // 发送加密缓冲区（复用，避免每次 send_chunk 堆分配）
        memory::vector<std::uint8_t> payload_enc_buf_;

        // 目标地址
        protocol::analysis::target target_;

        // 延迟响应所需的握手参数
        memory::vector<std::uint8_t> client_salt_;
        std::int64_t handshake_ts_{0};

        // 随机数生成器（用于生成 server salt）
        std::mt19937 rng_{std::random_device{}()};

        /// 从 PSK + salt 派生 AEAD 上下文
        [[nodiscard]] auto derive_aead_context(std::span<const std::uint8_t> salt) const
            -> std::unique_ptr<crypto::aead_context>;

        /// 读取并验证加密固定头（type + timestamp + varHeaderLen）
        auto read_fixed_header() const
            -> net::awaitable<std::tuple<fault::code, std::uint16_t, std::int64_t>>;

        /// 读取并解析加密变长头（地址 + padding + 初始 payload）
        auto read_variable_header(std::uint16_t var_header_len, request &req)
            -> net::awaitable<fault::code>;

        /// 构建并发送服务端响应
        auto send_response(std::span<const std::uint8_t> client_salt, std::int64_t server_ts)
            -> net::awaitable<fault::code>;

        /// 读取并解密下一个数据块到 decrypted_
        auto fetch_chunk(std::error_code &ec) -> net::awaitable<void>;

        /// 加密并写入一个数据块
        auto send_chunk(std::span<const std::byte> data, std::error_code &ec)
            -> net::awaitable<std::size_t>;
    };

    using shared_relay = std::shared_ptr<relay>;

    inline auto make_relay(shared_transmission next_layer, const config &cfg,
                           std::shared_ptr<salt_pool> salts) -> shared_relay
    {
        return std::make_shared<relay>(std::move(next_layer), cfg, std::move(salts));
    }
} // namespace psm::protocol::shadowsocks
