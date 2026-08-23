/**
 * @file relay.hpp
 * @brief 双向转发中间件
 * @details 在 inbound 与 outbound 之间建立双向隧道：
 * inbound → outbound（上行）+ outbound → inbound（下行）并发执行。
 * 空闲超时自动关闭，结束时上报流量统计。
 * 对应生产库 net/connection/tunnel/tunnel_relay 的中间件化。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <exception>
#include <memory>
#include <string_view>
#include <vector>

#include <common/core/fault/code.hpp>
#include <common/core/fault/handling.hpp>
#include <common/core/diagnose/log.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/middleware/pipeline.hpp>
#include <common/core/transmission.hpp>

namespace preview::middleware::builtin
{

    namespace net = boost::asio;

    namespace detail
    {

        /**
         * @struct relay_state
         * @brief 双向 relay 的共享运行状态
         * @details 两个方向的协程都持有该对象，确保缓冲区、计数器、定时器和
         * 关闭标志在所有异步操作完成前保持有效。上下行必须使用不同缓冲区，
         * 避免一个方向挂起读操作时被另一个方向覆盖数据。
         */
        struct relay_state
        {
            relay_state(preview::shared_transmission in, preview::shared_transmission out,
                        std::size_t buffer_size, std::chrono::milliseconds idle)
                : inbound(std::move(in)), outbound(std::move(out)), up_buffer(buffer_size),
                  down_buffer(buffer_size), idle_timer(inbound->executor()), idle_timeout(idle)
            {
            }

            preview::shared_transmission inbound;
            preview::shared_transmission outbound;
            std::vector<std::byte> up_buffer;
            std::vector<std::byte> down_buffer;
            std::array<std::size_t, 2> total{0, 0};
            net::steady_timer idle_timer;
            std::chrono::milliseconds idle_timeout;
            std::atomic_size_t completed_directions{0};
            std::atomic_bool closed{false};
            std::exception_ptr direction_error{}; ///< 方向协程异常（诊断用，正常完成时为空）
        };

        /**
         * @brief 幂等关闭 relay 两端
         * @param state relay 共享状态
         */
        auto close_relay(const std::shared_ptr<relay_state> &state) -> void
        {
            if (state->closed.exchange(true, std::memory_order_acq_rel))
            {
                return;
            }
            state->inbound->close();
            state->outbound->close();
            state->idle_timer.cancel();
        }

        /**
         * @brief 记录一个 relay 方向已完成
         * @param state relay 共享状态
         */
        auto complete_direction(const std::shared_ptr<relay_state> &state) -> void
        {
            state->completed_directions.fetch_add(1, std::memory_order_release);
        }

        /**
         * @brief 重置 relay 空闲计时器
         * @param state relay 共享状态
         */
        auto reset_idle_timer(const std::shared_ptr<relay_state> &state) -> void
        {
            if (state->idle_timeout > std::chrono::milliseconds::zero())
            {
                state->idle_timer.expires_after(state->idle_timeout);
            }
        }

        /**
         * @brief 执行单向转发（src → dst）
         * @tparam Idx 方向索引（0 = 上行 inbound→outbound，1 = 下行 outbound→inbound）
         * @param state relay 共享状态
         * @param name 方向名（异常日志）
         * @details 上下行唯一差异为方向索引与日志文案，统一实现消除镜像重复。
         */
        template <std::size_t Idx>
        auto relay_direction(std::shared_ptr<relay_state> state, std::string_view name)
            -> net::awaitable<void>
        {
            auto &src = Idx == 0 ? state->inbound : state->outbound;
            auto &dst = Idx == 0 ? state->outbound : state->inbound;
            auto &buf = Idx == 0 ? state->up_buffer : state->down_buffer;
            try
            {
                while (true)
                {
                    std::error_code read_ec;
                    const auto n = co_await src->async_read_some(
                        std::span<std::byte>(buf), read_ec);
                    if (n == 0)
                    {
                        if (read_ec)
                        {
                            close_relay(state);
                        }
                        else
                        {
                            dst->shutdown();
                        }
                        complete_direction(state);
                        co_return;
                    }
                    reset_idle_timer(state);

                    std::error_code write_ec;
                    co_await dst->async_write(
                        std::span<const std::byte>(buf.data(), n), write_ec);
                    // 流量按实际写入计：写失败不计入，避免错误路径虚增统计
                    if (!write_ec)
                    {
                        state->total[Idx] += n;
                    }
                    if (write_ec)
                    {
                        close_relay(state);
                        complete_direction(state);
                        co_return;
                    }
                    reset_idle_timer(state);

                    if (read_ec)
                    {
                        dst->shutdown();
                        complete_direction(state);
                        co_return;
                    }
                }
            }
            catch (const std::exception &e)
            {
                state->direction_error = std::current_exception();
                diagnose::error("{}: {}", name, e.what());
                close_relay(state);
                complete_direction(state);
            }
            catch (...)
            {
                state->direction_error = std::current_exception();
                diagnose::error("{}: unknown", name);
                close_relay(state);
                complete_direction(state);
            }
        }

        /**
         * @brief 执行上行转发（inbound → outbound）
         * @param state relay 共享状态
         * @note 转发层：统一实现见 relay_direction
         */
        auto relay_up(const std::shared_ptr<relay_state> &state)
            -> net::awaitable<void>
        {
            co_await relay_direction<0>(state, "relay uplink terminated by exception");
        }

        /**
         * @brief 执行下行转发（outbound → inbound）
         * @param state relay 共享状态
         * @note 转发层：统一实现见 relay_direction
         */
        auto relay_down(const std::shared_ptr<relay_state> &state)
            -> net::awaitable<void>
        {
            co_await relay_direction<1>(state, "relay downlink terminated by exception");
        }

        /**
         * @brief 等待 relay 空闲超时
         * @param state relay 共享状态
         */
        auto relay_idle(const std::shared_ptr<relay_state> &state)
            -> net::awaitable<void>
        {
            if (state->idle_timeout <= std::chrono::milliseconds::zero())
            {
                net::steady_timer hold(state->inbound->executor());
                hold.expires_after(std::chrono::hours(24));
                boost::system::error_code hold_ec;
                co_await hold.async_wait(net::redirect_error(net::use_awaitable, hold_ec));
                co_return;
            }

            while (true)
            {
                boost::system::error_code timer_ec;
                co_await state->idle_timer.async_wait(
                    net::redirect_error(net::use_awaitable, timer_ec));
                if (timer_ec == net::error::operation_aborted)
                {
                    if (state->closed.load(std::memory_order_acquire) ||
                        state->completed_directions.load(std::memory_order_acquire) == 2)
                    {
                        co_return;
                    }
                    continue;
                }
                close_relay(state);
                co_return;
            }
        }

    } // namespace detail

    /**
     * @class relay_middleware
     * @brief 双向转发中间件
     * @details 消费 ctx.inbound（客户端侧）并拨号 outbound（上游侧），
     * 建立双向隧道。outbound 由 dial_middleware 或调用方预置。
     * @note 本中间件为管线终点（handle 后隧道运行至关闭）。
     */
    class relay_middleware final : public middleware
    {
    public:
        /**
         * @brief 构造函数
         * @param outbound 上游传输（已拨号；可为空，由管线前序注入）
         * @param idle_timeout 空闲超时（0 = 禁用）
         */
        explicit relay_middleware(preview::shared_transmission outbound,
                                  std::chrono::milliseconds idle_timeout = std::chrono::seconds(300))
            : outbound_(std::move(outbound)), idle_timeout_(idle_timeout)
        {
        }

        /**
         * @brief 获取中间件名称
         */
        [[nodiscard]] auto name() const -> std::string_view override
        {
            return "relay";
        }

        /**
         * @brief 获取最近一次 relay 方向协程异常
         * @return 异常指针（正常完成/正常半关闭时为空）
         */
        [[nodiscard]] auto last_direction_error() const -> std::exception_ptr
        {
            return last_direction_error_;
        }

        /**
         * @brief 建立双向隧道并运行至关闭
         * @param inbound 入站传输
         * @param ctx 管线上下文
         * @return 隧道结束码（success = 正常关闭）
         */
        auto handle(preview::shared_transmission &inbound, context &ctx)
            -> net::awaitable<preview::fault::code> override
        {
            // 优先使用管线上下文注入的 outbound（dial 中间件产出）
            auto outbound = outbound_;
            if (ctx.outbound)
            {
                outbound = ctx.outbound;
            }
            if (!inbound || !outbound)
            {
                co_return preview::fault::code::bad_gateway;
            }

            const auto buffer_size = (std::max)(ctx.buffer_size, std::size_t{2});

            // 空闲超时：ctx.timeout 优先（>0），否则构造参数（0 = 禁用）
            auto effective_timeout = idle_timeout_;
            if (ctx.timeout > std::chrono::milliseconds::zero())
            {
                effective_timeout = ctx.timeout;
            }

            auto state = std::make_shared<detail::relay_state>(inbound, outbound, buffer_size,
                                                               effective_timeout);
            detail::reset_idle_timer(state);

            // 正常路径等待上下行都完成；任一方向发生 I/O 错误时由该方向关闭双方。
            using boost::asio::experimental::awaitable_operators::operator&&;
            using boost::asio::experimental::awaitable_operators::operator||;
            co_await ((detail::relay_up(state) && detail::relay_down(state)) ||
                      detail::relay_idle(state));

            detail::close_relay(state);

            // 方向协程异常留痕：正常半关闭路径应为空（诊断可观测）
            last_direction_error_ = state->direction_error;

            if (ctx.traffic)
            {
                ctx.traffic->report(ctx.identity, state->total[0], state->total[1]);
            }
            co_return preview::fault::code::success;
        }

    private:
        preview::shared_transmission outbound_; ///< 上游传输
        std::chrono::milliseconds idle_timeout_;       ///< 空闲超时
        std::exception_ptr last_direction_error_{};    ///< 最近一次方向协程异常（诊断用）
    };

} // namespace preview::middleware::builtin
