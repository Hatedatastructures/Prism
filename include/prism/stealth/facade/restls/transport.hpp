/**
 * @file transport.hpp
 * @brief Restls 传输层包装器
 * @details 持续处理 Restls 协议的应用数据流：
 * - 读取：TLS record → auth_mac 验证 → mask XOR 解码 → 提取用户数据
 * - 写入：script 分配 → 拼接明文 → mask XOR → auth_mac 计算 → TLS record 发送
 *
 * 应用数据帧布局（auth_header = 12 字节）：
 *   [TLS Header 5B][auth_mac 8B][masked_len 2B][masked_cmd 2B][data][padding]
 *
 * 写阻塞机制：script 行含 <N 时阻塞后续写入，直到读端收到响应后解除。
 */
#pragma once

#include <prism/memory/container.hpp>
#include <prism/stealth/facade/restls/crypto.hpp>
#include <prism/stealth/facade/restls/script.hpp>
#include <prism/transport/transmission.hpp>

#include <boost/asio.hpp>

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>


namespace psm::stealth::restls
{

    namespace net = boost::asio;

    /**
     * @brief TLS 版本标识
     * @details 标识后端连接使用的 TLS 协议版本。
     */
    enum class tls_version : std::uint8_t
    {
        v12,  ///< TLS 1.2
        v13   ///< TLS 1.3
    };

    /**
     * @struct restls_handover
     * @brief Restls 传输层构造参数包
     * @details 将握手阶段产出的配置参数打包，使 transport 构造函数参数 ≤3。
     */
    struct restls_handover
    {
        std::span<const std::uint8_t, 32> secret;        ///< RestlsSecret（32 字节）
        std::span<const std::uint8_t, 32> server_random;  ///< ServerHello 的 server_random（32 字节）
        std::span<const std::uint8_t> client_finished;    ///< 客户端 Finished（完整加密 TLS record）
        script_engine script;                              ///< Restls script 引擎
        std::span<const std::byte> initial_data;           ///< 初始预读数据（握手后首帧 payload）
        tls_version version;                               ///< 后端 TLS 版本
    };

    /**
     * @class restls_transport
     * @brief Restls 传输层包装器
     * @details 包装原始 TCP socket，持续处理 Restls 协议。
     * 读取方向逐记录验证 auth_mac 并用 mask XOR 解码 masked_len/masked_cmd。
     * 写入方向通过 script 引擎控制填充，并注入 auth_mac 和 mask。
     */
    class restls_transport final : public transport::transmission
    {
    public:
        /**
         * @brief 构造 Restls 传输层包装器
         * @param socket 原始 TCP socket（所有权转移）
         * @param handover 握手阶段产出的参数包（secret, server_random, client_finished, script, initial_data, version）
         */
        explicit restls_transport(
            net::ip::tcp::socket socket,
            restls_handover handover);

        ~restls_transport() noexcept override;

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
            return const_cast<net::ip::tcp::socket &>(socket_).get_executor();
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        [[nodiscard]] auto async_write(std::span<const std::byte> data, std::error_code &ec)
            -> net::awaitable<std::size_t>;

        void close() override;
        void cancel() override;

    private:
        /// [[nodiscard]] 读取一个完整的 Restls 应用数据记录
        [[nodiscard]] auto read_restls_frame(std::error_code &ec)
            -> net::awaitable<std::optional<memory::vector<std::byte>>>;

        /// [[nodiscard]] 写入一个 Restls 应用数据记录
        [[nodiscard]] auto write_restls_frame(std::span<const std::byte> data, std::error_code &ec)
            -> net::awaitable<std::size_t>;

        /// 发送随机响应帧
        [[nodiscard]] auto send_random_response(std::uint8_t count, std::error_code &ec)
            -> net::awaitable<void>;

        /// flush 待发送缓冲区
        [[nodiscard]] auto flush_pending(std::error_code &ec)
            -> net::awaitable<void>;

        net::ip::tcp::socket socket_;
        std::array<std::uint8_t, 32> secret_;
        std::array<std::uint8_t, 32> server_random_;
        memory::vector<std::uint8_t> client_finished_;
        script_engine script_;
        tls_version tls_version_;

        // 读写计数器
        std::uint64_t read_counter_{0};
        std::uint64_t write_counter_{0};
        bool first_write_{true};

        // 写阻塞机制
        bool write_pending_{false};
        memory::vector<std::byte> send_buf_;

        // 预读缓冲区
        memory::vector<std::byte> initial_buffer_;
        std::size_t initial_offset_{0};

        // TLS frame 剩余数据缓冲区
        memory::vector<std::byte> pending_buffer_;
        std::size_t pending_offset_{0};

    }; // class restls_transport
} // namespace psm::stealth::restls
