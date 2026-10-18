/**
 * @file EndpointRetirement.hpp
 * @brief UDP relay 两端 Transmission 的类型化退休 owner。
 * @details 方向任务完成后依次交付 Cancel/Close 并等待两端 Activity::Drain；首个业务、取消、
 *          原生或退休失败优先返回。该 owner 不启动 socket I/O，也不定义 UDP 半关闭。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Unreliable.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/system/system_error.hpp>

#include <array>
#include <exception>
#include <expected>
#include <memory>
#include <system_error>
#include <utility>

namespace Prism::Network::Udp::Detail
{
    namespace Net = boost::asio;
    using RelayResult = std::expected<void, Prism::Fault::Failure>;

    /**
     * @class EndpointRetirement
     * @brief 持有两个 Unreliable 的唯一控制退休与活动排空 owner。
     * @details 方向协程组返回后调用 Finish。控制与排空的失败不会覆盖已记录的业务/取消/native 首因；
     *          未知致命异常在两端可达的退休步骤结束后重抛。
     */
    class EndpointRetirement final
    {
    public:
        /**
         * @brief 接管两个端点。
         * @param First A 端点；允许为空以返回 InvalidArgument。
         * @param Second B 端点；允许为空以返回 InvalidArgument。
         */
        EndpointRetirement(
            std::shared_ptr<Prism::Transport::Unreliable> First,
            std::shared_ptr<Prism::Transport::Unreliable> Second)
            : Endpoints_{std::move(First), std::move(Second)}
        {
        }

        /**
         * @brief 取消调用方取消并完成两端 Close/Drain。
         * @param Primary 方向操作的首个 typed/native 失败；成功时为空。
         * @param FatalException 非普通 Fault 异常；退休后重抛。
         * @return 首个 typed/native cause；所有交付及 drain 成功时返回成功。
         */
        [[nodiscard]] auto Finish(
            Prism::Fault::Failure Primary,
            std::exception_ptr FatalException) -> Net::awaitable<RelayResult>
        {
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            Record(std::move(Primary));
            RecordException(std::move(FatalException));
            SubmitRetirement();
            co_await DrainRetired();
            if (FatalException_)
            {
                std::rethrow_exception(FatalException_);
            }
            if (Failure_.Failed())
            {
                co_return std::unexpected(Failure_);
            }
            co_return RelayResult{};
        }

    private:
        auto Record(Prism::Fault::Failure Value) noexcept -> void
        {
            if (Failure_.Succeeded() && Value.Failed())
            {
                Failure_ = std::move(Value);
            }
        }

        auto RecordException(std::exception_ptr Error) noexcept -> void
        {
            if (!Error)
            {
                return;
            }
            try
            {
                std::rethrow_exception(Error);
            }
            catch (const boost::system::system_error &NativeError)
            {
                Record(Prism::Fault::FromNative(
                    static_cast<std::error_code>(NativeError.code())));
            }
            catch (const std::system_error &NativeError)
            {
                Record(Prism::Fault::FromNative(NativeError.code()));
            }
            catch (...)
            {
                if (!FatalException_)
                {
                    FatalException_ = std::move(Error);
                }
            }
        }

        auto SubmitRetirement() -> void
        {
            for (const auto &Endpoint : Endpoints_)
            {
                if (!Endpoint)
                {
                    continue;
                }
                try
                {
                    const auto CancelResult = Endpoint->Cancel();
                    if (!CancelResult)
                    {
                        Record(CancelResult.error());
                    }
                }
                catch (...)
                {
                    RecordException(std::current_exception());
                }
                try
                {
                    const auto CloseResult = Endpoint->Close();
                    if (!CloseResult)
                    {
                        Record(CloseResult.error());
                    }
                }
                catch (...)
                {
                    RecordException(std::current_exception());
                }
            }
        }

        [[nodiscard]] auto DrainRetired() -> Net::awaitable<void>
        {
            for (const auto &Endpoint : Endpoints_)
            {
                if (!Endpoint)
                {
                    continue;
                }
                try
                {
                    const auto Activity = Endpoint->Activity();
                    if (!Activity)
                    {
                        Record({Prism::Fault::Code::Blocked});
                        continue;
                    }
                    const auto DrainResult = co_await Activity->Drain();
                    if (!DrainResult)
                    {
                        Record(DrainResult.error());
                    }
                }
                catch (...)
                {
                    RecordException(std::current_exception());
                }
            }
            co_return;
        }

        std::array<std::shared_ptr<Prism::Transport::Unreliable>, 2> Endpoints_;
        Prism::Fault::Failure Failure_;
        std::exception_ptr FatalException_;
    };
} // namespace Prism::Network::Udp::Detail
