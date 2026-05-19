/**
 * @file transport.hpp
 * @brief ShadowTLS v3 传输层包装器
 * @details 持续处理 ShadowTLS 协议的数据流：
 * - 读取：解包 TLS frame + HMAC 验证 → 返回裸数据
 * - 写入：XOR 加密 + 累积 HMAC 标签 + TLS frame → 发送
 */

#pragma once

#include <prism/channel/transport/transmission.hpp>
#include <prism/memory/container.hpp>
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
    class shadowtls_transport final : public channel::transport::transmission
    {
    public:
        /**
         * @brief 构造 ShadowTLS 传输层包装器
         * @param socket 原始 TCP socket（所有权转移）
         * @param password ShadowTLS 密码
         * @param server_random ServerHello 中的 ServerRandom（32 字节）
         * @param initial_data 初始数据（handshake 期间已读取的第一帧 payload）
         * @param hmac_write_ctx 写入方向累积 HMAC 上下文（初始：password + SR + "S"）
         * @param hmac_read_ctx 读取方向累积 HMAC 上下文（初始：password + SR + "C" + payload + HMAC[:4]）
         */
        explicit shadowtls_transport(net::ip::tcp::socket socket,
                                     std::string_view password,
                                     std::span<const std::byte> server_random,
                                     std::span<const std::byte> initial_data,
                                     std::shared_ptr<HMAC_CTX> hmac_write_ctx,
                                     std::shared_ptr<HMAC_CTX> hmac_read_ctx);

        ~shadowtls_transport() override;

        [[nodiscard]] bool is_reliable() const noexcept override { return true; }
        [[nodiscard]] executor_type executor() const override
        {
            // socket_ 是 mutable，因为 get_executor() 是非 const 的
            return const_cast<net::ip::tcp::socket &>(socket_).get_executor();
        }

        auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        auto async_write(std::span<const std::byte> data, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief Scatter-gather 写入（关键优化）
         * @details 将多个 buffer 合并成一个完整 payload，一次性封装成 TLS frame 发送。
         * ShadowTLS 协议要求：每个 TLS frame 包含一个完整的 HMAC+payload 单元。
         * 如果使用默认实现（循环调用 async_write），会导致 SS2022 等协议的响应被分成多个 TLS frame，
         * 破坏协议语义，客户端无法正确解析。
         * @param buffers 多个数据缓冲区
         * @param count 缓冲区数量
         * @param ec 错误码输出参数
         * @return 实际写入的总字节数
         */
        auto async_write_scatter(const std::span<const std::byte> *buffers, std::size_t count, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        void close() override;
        void shutdown_write() override;
        void cancel() override;

    private:
        /// 读取一个完整的 TLS frame 并验证累积 HMAC
        auto read_tls_frame(std::error_code &ec)
            -> net::awaitable<std::optional<memory::vector<std::byte>>>;

        /// 写入一个带累积 HMAC 标签的 TLS frame
        auto write_tls_frame(std::span<const std::byte> payload, std::error_code &ec)
            -> net::awaitable<std::size_t>;

        net::ip::tcp::socket socket_;
        std::string password_;
        std::array<std::byte, 32> server_random_;
        memory::vector<std::uint8_t> write_key_; // XOR 密钥：SHA256(password + serverRandom)

        // 初始数据缓冲区（handshake 期间已读取的第一帧）
        memory::vector<std::byte> initial_buffer_;
        std::size_t initial_offset_{0};

        // TLS frame 剩余数据缓冲区（当 frame > user buffer 时存储多余数据）
        memory::vector<std::byte> pending_buffer_;
        std::size_t pending_offset_{0};

        // 写入方向累积 HMAC 上下文（初始：password + SR + "S"）
        HMAC_CTX *hmac_write_ctx_{nullptr};
        std::shared_ptr<HMAC_CTX> hmac_write_ctx_owner_; // shared_ptr 持有所有权

        // 读取方向累积 HMAC 上下文（初始：password + SR + "C" + payload + HMAC[:4]）
        HMAC_CTX *hmac_read_ctx_{nullptr};
        std::shared_ptr<HMAC_CTX> hmac_read_ctx_owner_; // shared_ptr 持有所有权

        // TLS frame 常量
        static constexpr std::size_t tls_header_size = 5;
        static constexpr std::size_t hmac_size = 4;
        static constexpr std::size_t tls_hmac_header_size = tls_header_size + hmac_size;
        static constexpr std::uint8_t content_type_application_data = 0x17;
    };
} // namespace psm::stealth::shadowtls