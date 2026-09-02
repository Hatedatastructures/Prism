/**
 * @file Relay.hpp
 * @brief 双向转发中间件
 * @details 在 Inbound 与 Outbound 之间建立双向隧道：
 * Inbound → Outbound（上行）+ Outbound → Inbound（下行）并发执行。
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

#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Foundation/Fault/Handling.hpp>
#include <preview/Foundation/Utility/Diagnose/Log.hpp>
#include <preview/Runtime/Middleware/Context.hpp>
#include <preview/Runtime/Middleware/Pipeline.hpp>
#include <preview/Transport/Transmission.hpp>

namespace Preview::Middleware::Builtin
{

    namespace net = boost::asio;

    namespace detail
    {

        /**
         * @struct RelayState
         * @brief 双向 relay 的共享运行状态
         * @details 两个方向的协程都持有该对象，确保缓冲区、计数器、定时器和
         * 关闭标志在所有异步操作完成前保持有效。上下行必须使用不同缓冲区，
         * 避免一个方向挂起读操作时被另一个方向覆盖数据。
         */
        struct RelayState
        {
            RelayState(Preview::SharedTransmission in, Preview::SharedTransmission out,
                        std::size_t BufferSize, std::chrono::milliseconds idle)
                : Inbound(std::move(in)), Outbound(std::move(out)), UpBuffer(BufferSize),
                  DownBuffer(BufferSize), IdleTimer(Inbound->Executor()), IdleTimeout(idle)
            {
            }

            Preview::SharedTransmission Inbound;
            Preview::SharedTransmission Outbound;
            std::vector<std::byte> UpBuffer;
            std::vector<std::byte> DownBuffer;
            std::array<std::size_t, 2> Total{0, 0};
            net::steady_timer IdleTimer;
            std::chrono::milliseconds IdleTimeout;
            std::atomic_size_t CompletedDirections{0};
            std::atomic_bool closed{false};
            std::atomic_bool TimedOut{false};
            std::array<std::error_code, 2> DirectionFault{};
            std::exception_ptr DirectionError{}; ///< 方向协程异常（诊断用，正常完成时为空）
        };

        /**
         * @brief 幂等关闭 relay 两端
         * @param State relay 共享状态
         */
        auto CloseRelay(const std::shared_ptr<RelayState> &State) -> void
        {
            if (State->closed.exchange(true, std::memory_order_acq_rel))
            {
                return;
            }
            State->Inbound->Close();
            State->Outbound->Close();
            State->IdleTimer.cancel();
        }

        /**
         * @brief 记录一个 relay 方向已完成
         * @param State relay 共享状态
         */
        auto CompleteDirection(const std::shared_ptr<RelayState> &State) -> void
        {
            State->CompletedDirections.fetch_add(1, std::memory_order_release);
        }

        /**
         * @brief 重置 relay 空闲计时器
         * @param State relay 共享状态
         */
        auto ResetIdleTimer(const std::shared_ptr<RelayState> &State) -> void
        {
            if (State->IdleTimeout > std::chrono::milliseconds::zero())
            {
                State->IdleTimer.expires_after(State->IdleTimeout);
            }
        }

        /**
         * @brief 执行单向转发（src → dst）
         * @tparam Idx 方向索引（0 = 上行 Inbound→Outbound，1 = 下行 Outbound→Inbound）
         * @param State relay 共享状态
         * @param Name 方向名（异常日志）
         * @details 上下行唯一差异为方向索引与日志文案，统一实现消除镜像重复。
         */
        template <std::size_t Idx>
        auto RelayDirection(std::shared_ptr<RelayState> State, std::string_view Name)
            -> net::awaitable<void>
        {
            auto &src = Idx == 0 ? State->Inbound : State->Outbound;
            auto &dst = Idx == 0 ? State->Outbound : State->Inbound;
            auto &buf = Idx == 0 ? State->UpBuffer : State->DownBuffer;
            try
            {
                while (true)
                {
                    std::error_code ReadEc;
                    const auto N = co_await src->async_read_some(
                        std::span<std::byte>(buf), ReadEc);
                    if (N == 0)
                    {
                        // 真实 TCP 将 FIN 映射为 Fault::Code::Eof；它和内存传输的
                        // 空错误码都表示干净半关闭，不能因此关闭反向数据流。
                        const bool CleanEof = ReadEc == Preview::Fault::Code::Eof;
                        if (ReadEc && !CleanEof)
                        {
                            State->DirectionFault[Idx] = ReadEc;
                            CloseRelay(State);
                        }
                        else
                        {
                            dst->Shutdown();
                        }
                        CompleteDirection(State);
                        co_return;
                    }
                    ResetIdleTimer(State);

                    std::error_code WriteEc;
                    co_await dst->AsyncWrite(
                        std::span<const std::byte>(buf.data(), N), WriteEc);
                    // 流量按实际写入计：写失败不计入，避免错误路径虚增统计
                    if (!WriteEc)
                    {
                        State->Total[Idx] += N;
                    }
                    if (WriteEc)
                    {
                        State->DirectionFault[Idx] = WriteEc;
                        CloseRelay(State);
                        CompleteDirection(State);
                        co_return;
                    }
                    ResetIdleTimer(State);

                    if (ReadEc)
                    {
                        dst->Shutdown();
                        CompleteDirection(State);
                        co_return;
                    }
                }
            }
            catch (const std::exception &e)
            {
                State->DirectionError = std::current_exception();
                Diagnose::Error("{}: {}", Name, e.what());
                CloseRelay(State);
                CompleteDirection(State);
            }
            catch (...)
            {
                State->DirectionError = std::current_exception();
                Diagnose::Error("{}: unknown", Name);
                CloseRelay(State);
                CompleteDirection(State);
            }
        }

        /**
         * @brief 执行上行转发（Inbound → Outbound）
         * @param State relay 共享状态
         * @note 转发层：统一实现见 RelayDirection
         */
        auto RelayUp(const std::shared_ptr<RelayState> &State)
            -> net::awaitable<void>
        {
            co_await RelayDirection<0>(State, "relay uplink terminated by exception");
        }

        /**
         * @brief 执行下行转发（Outbound → Inbound）
         * @param State relay 共享状态
         * @note 转发层：统一实现见 RelayDirection
         */
        auto RelayDown(const std::shared_ptr<RelayState> &State)
            -> net::awaitable<void>
        {
            co_await RelayDirection<1>(State, "relay downlink terminated by exception");
        }

        /**
         * @brief 等待 relay 空闲超时
         * @param State relay 共享状态
         */
        auto RelayIdle(const std::shared_ptr<RelayState> &State)
            -> net::awaitable<void>
        {
            if (State->IdleTimeout <= std::chrono::milliseconds::zero())
            {
                net::steady_timer hold(State->Inbound->Executor());
                hold.expires_after(std::chrono::hours(24));
                boost::system::error_code HoldEc;
                co_await hold.async_wait(net::redirect_error(net::use_awaitable, HoldEc));
                co_return;
            }

            while (true)
            {
                boost::system::error_code TimerEc;
                co_await State->IdleTimer.async_wait(
                    net::redirect_error(net::use_awaitable, TimerEc));
                if (TimerEc == net::error::operation_aborted)
                {
                    if (State->closed.load(std::memory_order_acquire) ||
                        State->CompletedDirections.load(std::memory_order_acquire) == 2)
                    {
                        co_return;
                    }
                    continue;
                }
                State->TimedOut.store(true, std::memory_order_release);
                CloseRelay(State);
                co_return;
            }
        }

    } // namespace detail

    /**
     * @class RelayMiddleware
     * @brief 双向转发中间件
     * @details 消费 ctx.Inbound（客户端侧）并拨号 Outbound（上游侧），
     * 建立双向隧道。Outbound 由 DialMiddleware 或调用方预置。
     * @note 本中间件为管线终点（Handle 后隧道运行至关闭）。
     */
    class RelayMiddleware final : public Middleware
    {
    public:
        /**
         * @brief 构造函数
         * @param Outbound 上游传输（已拨号；可为空，由管线前序注入）
         * @param IdleTimeout 空闲超时（0 = 禁用）
         */
        explicit RelayMiddleware(Preview::SharedTransmission Outbound,
                                  std::chrono::milliseconds IdleTimeout = std::chrono::seconds(300))
            : Outbound_(std::move(Outbound)), IdleTimeout_(IdleTimeout)
        {
        }

        /**
         * @brief 获取中间件名称
         */
        [[nodiscard]] auto Name() const -> std::string_view override
        {
            return "relay";
        }

        /**
         * @brief 获取最近一次 relay 方向协程异常
         * @return 异常指针（正常完成/正常半关闭时为空）
         */
        [[nodiscard]] auto LastDirectionError() const -> std::exception_ptr
        {
            return LastDirectionError_;
        }

        /**
         * @brief 建立双向隧道并运行至关闭
         * @param Inbound 入站传输
         * @param ctx 管线上下文
         * @return 隧道结束码（success = 正常关闭）
         */
        auto Handle(Preview::SharedTransmission &Inbound, Context &ctx)
            -> net::awaitable<Preview::Fault::Code> override
        {
            // 优先使用管线上下文注入的 Outbound（Dial 中间件产出）
            auto Outbound = Outbound_;
            if (ctx.Outbound)
            {
                Outbound = ctx.Outbound;
            }
            if (!Inbound || !Outbound)
            {
                co_return Preview::Fault::Code::BadGateway;
            }

            const auto BufferSize = (std::max)(ctx.BufferSize, std::size_t{2});

            // 空闲超时：ctx.timeout 优先（>0），否则构造参数（0 = 禁用）
            auto EffectiveTimeout = IdleTimeout_;
            if (ctx.timeout > std::chrono::milliseconds::zero())
            {
                EffectiveTimeout = ctx.timeout;
            }

            auto State = std::make_shared<detail::RelayState>(Inbound, Outbound, BufferSize,
                                                               EffectiveTimeout);
            detail::ResetIdleTimer(State);

            // 正常路径等待上下行都完成；任一方向发生 I/O 错误时由该方向关闭双方。
            using boost::asio::experimental::awaitable_operators::operator&&;
            using boost::asio::experimental::awaitable_operators::operator||;
            co_await ((detail::RelayUp(State) && detail::RelayDown(State)) ||
                      detail::RelayIdle(State));

            detail::CloseRelay(State);

            // 方向协程异常留痕：正常半关闭路径应为空（诊断可观测）
            LastDirectionError_ = State->DirectionError;

            if (ctx.traffic)
            {
                ctx.traffic->Report(ctx.identity, State->Total[0], State->Total[1]);
            }
            if (State->TimedOut.load(std::memory_order_acquire))
            {
                co_return Preview::Fault::Code::Timeout;
            }
            for (const auto &Ec : State->DirectionFault)
            {
                if (Ec)
                {
                    co_return Preview::Fault::ToCode(Ec);
                }
            }
            if (State->DirectionError)
            {
                co_return Preview::Fault::Code::IoError;
            }
            co_return Preview::Fault::Code::Success;
        }

    private:
        Preview::SharedTransmission Outbound_; ///< 上游传输
        std::chrono::milliseconds IdleTimeout_;       ///< 空闲超时
        std::exception_ptr LastDirectionError_{};    ///< 最近一次方向协程异常（诊断用）
    };

} // namespace Preview::Middleware::Builtin
