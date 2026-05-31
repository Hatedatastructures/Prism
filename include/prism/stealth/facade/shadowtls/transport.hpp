/**
 * @file transport.hpp
 * @brief ShadowTLS v3 传输层包装器
 * @details 持续处理 ShadowTLS 协议的数据流：
 * - 读取：解包 TLS frame + HMAC 验证 → 返回裸数据
 * - 写入：XOR 加密 + 累积 HMAC 标签 + TLS frame → 发送
 */

#pragma once

#include <prism/memory/container.hpp>
#include <prism/transport/transmission.hpp>

#include <boost/asio.hpp>
#include <openssl/hmac.h>

#include <array>
#include <memory>
#include <span>
#include <string_view>


namespace psm::stealth::shadowtls
{

    namespace net = boost::asio;

    /**
     * @struct shadowtls_handover
     * @brief ShadowTLS 传输层构造参数包
     * @details 将握手阶段产出的配置参数打包，使 transport 构造函数参数 ≤3。
     */
    struct shadowtls_handover
    {
        std::string_view password;                              ///< ShadowTLS 密码
        std::span<const std::byte> server_random;               ///< ServerHello 的 ServerRandom（32 字节）
        std::span<const std::byte> initial_data;                ///< 初始数据（handshake 期间已读取的第一帧 payload）
        std::shared_ptr<HMAC_CTX> hmac_write_ctx;               ///< 写入方向累积 HMAC 上下文（初始：password + SR + "S"）
        std::shared_ptr<HMAC_CTX> hmac_read_ctx;                ///< 读取方向累积 HMAC 上下文（初始：password + SR + "C" + payload + HMAC[:4]）
    };

    /**
     * @class shadowtls_transport
     * @brief ShadowTLS v3 传输层包装器
     * @details 包装原始 TCP socket，持续处理 ShadowTLS 协议：
     * - 客户端→服务端：读取 TLS ApplicationData frame，验证累积 HMAC 标签，剥离 TLS header 和 HMAC 后返回 payload
     *   HMAC 验证：累积 HMAC-SHA1(password, SR + "C" + all_payloads + all_HMACs)[:4]
     *   参照 sing-shadowtls verifyApplicationData，验证后将 HMAC[:4] 加入累积状态
     * - 服务端→客户端：XOR 加密 payload，添加累积 HMAC 标签，包装成 TLS ApplicationData frame 发送
     *   HMAC 计算：累积 HMAC-SHA1(password, SR + "S" + all_payloads)[:4]
     *   参照 sing-shadowtls verifiedConn.write
     * XOR 密钥：SHA256(password + serverRandom)
     * @note 写入方向 HMAC 初始状态 = password + SR + "S"（从 handshake 阶段继承）
     *       读取方向 HMAC 初始状态 = password + SR + "C" + first_frame_payload + HMAC[:4]（从 handshake 阶段继承）
     */
    class shadowtls_transport final : public transport::transmission
    {
    public:
        /**
         * @brief 构造 ShadowTLS 传输层包装器
         * @param socket 原始 TCP socket（所有权转移）
         * @param handover 握手阶段产出的参数包（password, server_random, initial_data, HMAC 上下文）
         */
        explicit shadowtls_transport(net::ip::tcp::socket socket,
                                     shadowtls_handover handover);

        ~shadowtls_transport() noexcept override;

        [[nodiscard]] auto transport_type() const noexcept
            -> type override
        {
            return type::tcp;
        }

        [[nodiscard]] auto next_layer() noexcept -> transmission * override
        {
            return nullptr;
        }

        [[nodiscard]] auto next_layer() const noexcept -> const transmission * override
        {
            return nullptr;
        }

        [[nodiscard]] auto executor() const -> executor_type override
        {
            // socket_ 是 mutable，因为 get_executor() 是非 const 的
            return const_cast<net::ip::tcp::socket &>(socket_).get_executor();
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        [[nodiscard]] auto async_write(std::span<const std::byte> data, std::error_code &ec)
            -> net::awaitable<std::size_t>;

        /**
         * @brief 半关闭写方向
         * @details 关闭底层 TCP socket 的写半端，通知对端不再发送数据。
         * 读取方向仍可继续接收数据。
         * @note 非 virtual，仅 shadowtls_transport 自身持有此能力
         */
        void shutdown_write()
        {
            boost::system::error_code ec;
            socket_.shutdown(net::ip::tcp::socket::shutdown_send, ec);
        }

        void close() override;
        void cancel() override;

    private:
        /// [[nodiscard]] 读取一个完整的 TLS frame 并验证累积 HMAC
        [[nodiscard]] auto read_tls_frame(std::error_code &ec)
            -> net::awaitable<std::optional<memory::vector<std::byte>>>;

        /// [[nodiscard]] 写入一个带累积 HMAC 标签的 TLS frame
        [[nodiscard]] auto write_tls_frame(std::span<const std::byte> payload, std::error_code &ec)
            -> net::awaitable<std::size_t>;

        net::ip::tcp::socket socket_;
        std::array<std::byte, 32> server_random_;
        memory::vector<std::uint8_t> write_key_; // XOR 密钥：SHA256(password + serverRandom)

        // 初始数据缓冲区（handshake 期间已读取的第一帧）
        memory::vector<std::byte> initial_buffer_;
        std::size_t initial_offset_{0};

        // TLS frame 剩余数据缓冲区（当 frame > user buffer 时存储多余数据）
        memory::vector<std::byte> pending_buffer_;
        std::size_t pending_offset_{0};

        // 写入方向累积 HMAC 上下文（初始：password + SR + "S"）
        std::shared_ptr<HMAC_CTX> hmac_write_ctx_;

        // 读取方向累积 HMAC 上下文（初始：password + SR + "C" + payload + HMAC[:4]）
        std::shared_ptr<HMAC_CTX> hmac_read_ctx_;

        // TLS frame 常量
        static constexpr std::size_t tls_hdrsize = 5;
        static constexpr std::size_t hmac_size = 4;
        static constexpr std::size_t tls_hmac_hdrsize = tls_hdrsize + hmac_size;
        static constexpr std::uint8_t content_appdata = 0x17;
    };
} // namespace psm::stealth::shadowtls