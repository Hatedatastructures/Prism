/**
 * @file StressUtil.hpp
 * @brief 压力测试共享工具
 * @details 提供端到端压力测试所需的本地 socket 配对、RTT 延迟模拟传输、
 * 流量报文协议、进程内存采样等公共设施，供各压力测试工具复用。
 */

#pragma once

#include <prism/net/transport/reliable.hpp>
#include <prism/foundation/memory/pool.hpp>
#include <prism/foundation/fault/compatible.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <utility>

#if defined(_WIN32)
#include <windows.h>
#ifndef PSAPI_VERSION
#define PSAPI_VERSION 2
#endif
#include <psapi.h>
#endif

namespace psm::stress
{
    namespace net = boost::asio;

    /**
     * @brief 流量报文头
     * @details 8 字节 payload 长度 + 8 字节序号，共 16 字节。
     * 所有端到端压力测试使用该报文协议进行写入与校验。
     */
    struct packet_header
    {
        std::uint64_t length; ///< payload 长度
        std::uint64_t seq;    ///< 报文序号
    };
    static_assert(sizeof(packet_header) == 16);

    /**
     * @brief 异步建立本地 TCP socket 对
     * @details 通过 loopback acceptor + connect 建立一对已连接的 socket，
     * 用于模拟代理链路的两端。
     * @param ex 执行器
     * @return 已连接的 socket 对（client, server）
     */
    inline auto make_socket_pair(net::any_io_executor ex)
        -> net::awaitable<std::pair<net::ip::tcp::socket, net::ip::tcp::socket>>
    {
        net::ip::tcp::acceptor acceptor(ex, net::ip::tcp::endpoint(net::ip::address_v4::loopback(), 0));
        auto client_socket = net::ip::tcp::socket(ex);
        co_await client_socket.async_connect(acceptor.local_endpoint(), net::use_awaitable);
        auto server_socket = co_await acceptor.async_accept(net::use_awaitable);
        co_return std::make_pair(std::move(client_socket), std::move(server_socket));
    }

    /**
     * @brief 异步等待指定时长
     * @param ex 执行器
     * @param dur 等待时长
     */
    inline auto async_wait(net::any_io_executor ex, const std::chrono::milliseconds dur)
        -> net::awaitable<void>
    {
        net::steady_timer timer(ex);
        timer.expires_after(dur);
        boost::system::error_code ec;
        co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
    }

    /**
     * @class delayed_transport
     * @brief RTT 延迟模拟传输
     * @details 包装内层传输，在异步写入提交前插入固定延迟，
     * 用于模拟局域网/跨城/跨洋链路的单向传播延迟（RTT 的一半）。
     * 读取方向直通不延迟。写延迟 + 对端 ACK 传播延迟构成完整 RTT。
     */
    class delayed_transport final : public transport::transmission
    {
    public:
        /**
         * @brief 构造函数
         * @param inner 内层传输
         * @param one_way_delay 单向传播延迟（RTT 的一半）
         */
        delayed_transport(transport::shared_transmission inner, std::chrono::microseconds one_way_delay)
            : inner_(std::move(inner)), delay_(one_way_delay)
        {
        }

        /**
         * @brief 获取传输类型
         * @return type 内层传输类型
         */
        [[nodiscard]] auto transport_type() const noexcept
            -> type override
        {
            return inner_->transport_type();
        }

        /**
         * @brief 获取执行器
         * @return executor_type 内层传输执行器
         */
        [[nodiscard]] auto executor() const
            -> executor_type override
        {
            return inner_->executor();
        }

        /**
         * @brief 异步读取（直通内层）
         * @param buffer 接收缓冲区
         * @param ec 错误码
         * @return 实际读取字节数
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await inner_->async_read_some(buffer, ec);
        }

        /**
         * @brief 异步写入（延迟 delay_ 后提交）
         * @param buffer 发送缓冲区
         * @param ec 错误码
         * @return 实际写入字节数
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (delay_.count() > 0)
            {
                net::steady_timer timer(co_await net::this_coro::executor);
                timer.expires_after(delay_);
                boost::system::error_code sys_ec;
                co_await timer.async_wait(net::redirect_error(net::use_awaitable, sys_ec));
                if (sys_ec)
                {
                    ec = psm::fault::make_error_code(psm::fault::to_code(sys_ec));
                    co_return 0;
                }
            }
            co_return co_await inner_->async_write_some(buffer, ec);
        }

        /**
         * @brief 异步写入（completion-handler 版，延迟后提交）
         * @param buffer 发送缓冲区
         * @param handler 完成处理器
         */
        void async_write_some(std::span<const std::byte> buffer,
                              net::any_completion_handler<void(boost::system::error_code, std::size_t)> handler) override
        {
            if (delay_.count() <= 0)
            {
                inner_->async_write_some(buffer, std::move(handler));
                return;
            }
            auto ex = executor();
            auto h = std::make_shared<net::any_completion_handler<void(boost::system::error_code, std::size_t)>>(std::move(handler));
            auto timer = std::make_shared<net::steady_timer>(ex);
            timer->expires_after(delay_);
            timer->async_wait(
                [inner = inner_, timer, h, buffer](const boost::system::error_code &ec) mutable
                {
                    if (ec)
                    {
                        std::move(*h)(ec, 0);
                        return;
                    }
                    inner->async_write_some(buffer, std::move(*h));
                });
        }

        /**
         * @brief 关闭传输（直通内层）
         */
        void close() override
        {
            inner_->close();
        }

        /**
         * @brief 取消异步操作（直通内层）
         */
        void cancel() override
        {
            inner_->cancel();
        }

        /**
         * @brief 获取内层传输
         * @return transmission* 内层传输指针
         */
        [[nodiscard]] auto next_layer() noexcept
            -> transmission * override
        {
            return inner_.get();
        }

        /**
         * @brief 获取内层传输（const 版）
         * @return const transmission* 内层传输指针
         */
        [[nodiscard]] auto next_layer() const noexcept
            -> const transmission * override
        {
            return inner_.get();
        }

    private:
        transport::shared_transmission inner_;       ///< 内层传输
        std::chrono::microseconds delay_;            ///< 单向传播延迟
    };

    /**
     * @brief 获取当前进程私有内存占用
     * @details 通过 GetProcessMemoryInfo 采样进程私有提交内存（MB），
     * 用于稳定性测试的泄漏趋势判定。PagefileUsage 与 PrivateUsage 等价。
     * @return double 私有内存 MB，采样失败返回 0
     */
    inline auto process_private_mb() -> double
    {
#if defined(_WIN32)
        PROCESS_MEMORY_COUNTERS pmc{};
        pmc.cb = sizeof(pmc);
        if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)))
        {
            return static_cast<double>(pmc.PagefileUsage) / (1024.0 * 1024.0);
        }
#endif
        return 0.0;
    }

    /**
     * @brief 生成随机报文写入数据
     * @details 预生成随机字节池，按 payload 大小从池中循环取用，
     * 避免热路径反复调用随机数生成器。
     * @param pool_size 随机池大小
     * @return 随机字节池
     */
    inline auto make_payload_pool(const std::size_t pool_size) -> memory::vector<std::byte>
    {
        memory::vector<std::byte> pool(pool_size, memory::effective_mr(memory::system::local_pool()));
        std::mt19937 rng(20260811);
        for (auto &b : pool)
        {
            b = static_cast<std::byte>(rng() & 0xFF);
        }
        return pool;
    }

} // namespace psm::stress
