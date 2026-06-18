/**
 * @file transport.hpp
 * @brief Restls 传输层包装器（中间人代理模式）
 * @details 在 raw TCP socket 之上处理 Restls 协议的应用数据流：
 * - 读取：raw TCP → read_tls_frame → 验证 type=0x17 → auth_mac 验证 → mask XOR 解码 → 提取用户数据
 * - 写入：script 分配 → 拼接明文 → mask XOR → auth_mac 计算 → 包装 TLS record header → raw TCP async_write
 *
 * 应用数据帧布局（auth_header = 12 字节，作为 TLS 1.3 ApplicationData record 的 payload）：
 *   [auth_mac 8B][masked_len 2B][masked_cmd 2B][data][padding]
 *
 * 写阻塞机制：script 行含 <N 时阻塞后续写入，直到读端收到响应后解除。
 */
#pragma once

#include <prism/core/memory/container.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/stealth/facade/restls/crypto.hpp>
#include <prism/stealth/facade/restls/script.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>


namespace psm::stealth::restls
{

    namespace net = boost::asio;

    /**
     * @brief TLS 版本标识
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
        script_engine script;                              ///< Restls script 引擎
        tls_version version;                               ///< TLS 版本
        memory::vector<std::byte> client_finished;        ///< 客户端 Finished（完整 TLS record，首次 c2s authMac 用）
    };

    /**
     * @class restls_transport
     * @brief Restls 传输层包装器（中间人代理模式）
     * @details 包装 reliable transport（raw TCP socket），持续处理 Restls 协议。
     * 读取方向逐 TLS record 验证 auth_mac 并用 mask XOR 解码 masked_len/masked_cmd。
     * 写入方向通过 script 引擎控制填充，构造完整 TLS record 后写入。
     */
    class restls_transport final : public transport::transmission
    {
    public:
        /**
         * @brief 构造 Restls 传输层包装器
         * @param raw_trans raw TCP reliable transport（所有权转移）
         * @param handover 握手阶段产出的参数包（secret, server_random, script, version, client_finished, first_encrypted）
         */
        explicit restls_transport(
            std::shared_ptr<transport::reliable> raw_trans,
            restls_handover handover);

        ~restls_transport() noexcept override;

        [[nodiscard]] auto transport_type() const noexcept
            -> type override
        {
            return type::tcp;
        }

        [[nodiscard]] auto next_layer() noexcept -> transmission * override
        {
            return raw_trans_.get();
        }

        [[nodiscard]] auto next_layer() const noexcept -> const transmission * override
        {
            return raw_trans_.get();
        }

        [[nodiscard]] auto executor() const -> executor_type override
        {
            return raw_trans_->executor();
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        void close() override;
        void cancel() override;

    private:
        /// 读取一个完整的 Restls 应用数据记录（封装为 TLS ApplicationData record）
        [[nodiscard]] auto read_restls_frame(std::error_code &ec)
            -> net::awaitable<std::optional<memory::vector<std::byte>>>;

        /// 写入一个 Restls 应用数据记录（封装为 TLS ApplicationData record）
        /// @param force_noop 强制 cmd=ActNoop（用于 random-response，避免误触发 client 回 random-response）
        [[nodiscard]] auto write_restls_frame(std::span<const std::byte> data, std::error_code &ec, bool force_noop = false)
            -> net::awaitable<std::size_t>;

        /// 发送随机响应帧
        [[nodiscard]] auto send_random_response(std::uint8_t count, std::error_code &ec)
            -> net::awaitable<void>;

        /// 获取 s→c write 互斥锁（协程级 mutex）
        /// write_restls_frame 入口 acquire，co_return 时由 write_lock_guard RAII 释放
        [[nodiscard]] auto acquire_write_lock() -> net::awaitable<void>;

        /// 释放 s→c write 互斥锁
        void release_write_lock() noexcept;

        std::shared_ptr<transport::reliable> raw_trans_;
        std::array<std::uint8_t, 32> secret_;
        std::array<std::uint8_t, 32> server_random_;
        script_engine script_;
        tls_version tls_version_;
        memory::vector<std::byte> client_finished_;  ///< 首次 c2s authMac 计算用，用后清空

        // 读写计数器（方向独立的 restls 帧计数器）
        std::uint64_t to_client_counter_{0};
        std::uint64_t to_server_counter_{0};
        std::uint64_t read_counter_{0};
        std::uint64_t write_counter_{0};
        bool first_write_{true};
        int skip_count_{0};  // authMac 失败时跳过的帧计数

        // 写阻塞机制
        bool write_pending_{false};
        net::steady_timer write_waiter_;

        // s→c write 互斥锁：read 路径(send_random_response)和 write 路径(send_loop)
        // 都会调 write_restls_frame，两者交错会导致 counter 与 TCP 发送顺序不一致，
        // client authMac 验证失败。此锁保证 write_restls_frame 从读 counter 到
        // co_await async_write 到 ++counter 整个过程串行。
        std::atomic<bool> write_busy_{false};
        net::steady_timer write_signal_;

        // 预读缓冲区
        memory::vector<std::byte> pending_buffer_;
        std::size_t pending_offset_{0};

    }; // class restls_transport

} // namespace psm::stealth::restls
