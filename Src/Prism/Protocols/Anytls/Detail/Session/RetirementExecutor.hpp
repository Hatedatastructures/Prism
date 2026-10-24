/** @file RetirementExecutor.hpp @brief AnyTLS 传输链退休的原 executor 与 Activity 层选择。 */
#pragma once

#include <Prism/Contract/Ingress/MuxSession.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>
#include <boost/system/system_error.hpp>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <new>
#include <system_error>

namespace Prism::Anytls::Detail
{
    namespace Net = boost::asio;

    /** @brief 将同一异常 cause 映射为完整 typed failure。 */
    [[nodiscard]] inline auto FailureFromRetirementException(
        const std::exception_ptr Exception) noexcept -> Prism::Fault::Failure
    {
        try
        {
            if (Exception)
            {
                std::rethrow_exception(Exception);
            }
        }
        catch (const boost::system::system_error& Error)
        {
            const auto Native = static_cast<std::error_code>(Error.code());
            return {Prism::Fault::ToCode(Native), Native};
        }
        catch (const std::system_error& Error)
        {
            return {Prism::Fault::ToCode(Error.code()), Error.code()};
        }
        catch (const std::bad_alloc&)
        {
            return {Prism::Fault::Code::ResourceUnavailable};
        }
        catch (...)
        {
            return {Prism::Fault::Code::IoError};
        }
        return {Prism::Fault::Code::IoError};
    }

    /** @brief 将 executor exception 发布到所属 Context，并返回原生 typed cause。 */
    [[nodiscard]] inline auto FailureFromExecutorException(
        const boost::asio::any_io_executor& Executor,
        const std::exception_ptr Exception) noexcept -> Prism::Fault::Failure
    {
        try
        {
            if (const auto Owner = Prism::Executor::ContextOwner::Find(Executor);
                Owner && Owner->Fatal)
            {
                Owner->Fatal->Publish(Exception);
            }
        }
        catch (...)
        {
        }
        return FailureFromRetirementException(Exception);
    }

    /** @brief 保留首个完整关闭失败。 */
    inline auto PreserveRetirementFailure(
        Prism::Fault::Failure& Primary,
        const Prism::Fault::Failure& Next) noexcept -> void
    {
        if (!Primary.Failed() && Next.Failed())
        {
            Primary = Next;
        }
    }

    /** @brief 合并一次关闭尝试的首个失败，不替换已有 Native cause。 */
    inline auto KeepFirstRetirementFailure(
        std::expected<void, Prism::Fault::Failure>& FirstFailure,
        const Prism::Fault::Failure& Failure) -> void
    {
        if (FirstFailure)
        {
            FirstFailure = std::unexpected(Failure);
            return;
        }
        auto Primary = FirstFailure.error();
        PreserveRetirementFailure(Primary, Failure);
        FirstFailure = std::unexpected(Primary);
    }

    /** @brief 向所属 Context 的 fatal owner 发布不可恢复清理异常。 */
    inline auto PublishRetirementFatal(
        const boost::asio::any_io_executor& Executor,
        const std::exception_ptr Exception) noexcept -> void
    {
        try
        {
            if (const auto Owner = Prism::Executor::ContextOwner::Find(Executor);
                Owner && Owner->Fatal)
            {
                Owner->Fatal->Publish(Exception);
            }
        }
        catch (...)
        {
        }
    }

    /** @brief 某一轮 AnyTLS 根 mux 关闭与物理排空的共享回执状态。 */
    struct MuxRetirementAttempt final
    {
        std::shared_ptr<Prism::Contract::MuxSession> Session;
        bool &CancelAttempted;
        bool &CloseAttempted;
        bool &AllDrained;
        std::expected<void, Prism::Fault::Failure> &FirstFailure;
        std::exception_ptr &FirstException;
    };

    /** @brief 只对 mux 根投递一次取消/关闭，并以 Activity 和 Session 双回执判定排空。 */
    [[nodiscard]] inline auto RetireMuxSession(MuxRetirementAttempt &Attempt)
        -> Net::awaitable<void>
    {
        if (!Attempt.CancelAttempted)
        {
            Attempt.CancelAttempted = true;
            try { Attempt.Session->Cancel(); }
            catch (...)
            {
                const auto Exception = std::current_exception();
                if (!Attempt.FirstException) Attempt.FirstException = Exception;
                KeepFirstRetirementFailure(Attempt.FirstFailure,
                    FailureFromRetirementException(Exception));
            }
        }
        if (!Attempt.CloseAttempted)
        {
            Attempt.CloseAttempted = true;
            try { Attempt.Session->Close(); }
            catch (...)
            {
                const auto Exception = std::current_exception();
                if (!Attempt.FirstException) Attempt.FirstException = Exception;
                KeepFirstRetirementFailure(Attempt.FirstFailure,
                    FailureFromRetirementException(Exception));
            }
        }

        const auto Activity = Attempt.Session->Activity();
        if (!Activity)
        {
            Attempt.AllDrained = false;
            KeepFirstRetirementFailure(Attempt.FirstFailure,
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            co_return;
        }
        std::expected<void, Prism::Fault::Failure> Drained;
        try { Drained = co_await Activity->Drain(); }
        catch (...)
        {
            const auto Exception = std::current_exception();
            if (!Attempt.FirstException) Attempt.FirstException = Exception;
            Drained = std::unexpected(FailureFromRetirementException(Exception));
        }
        if (!Drained) KeepFirstRetirementFailure(Attempt.FirstFailure, Drained.error());
        if (!Activity->IsRetired() || !Attempt.Session->IsRetired())
        {
            Attempt.AllDrained = false;
            KeepFirstRetirementFailure(Attempt.FirstFailure,
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
    }

    /** @brief 在第一次关闭前绑定原传输 executor，失败时不丢失调用者持有的实物。 */
    [[nodiscard]] inline auto PrepareRetirementExecutor(
        const SharedTransmission &Transport,
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> &Reclaimer) noexcept
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (Reclaimer) return {};
        if (!Transport)
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        try
        {
            Reclaimer = std::make_shared<Prism::Executor::ExecutorReclaimer>(
                boost::asio::make_strand(Transport->Executor()));
            return {};
        }
        catch (...)
        {
            return std::unexpected(
                FailureFromRetirementException(std::current_exception()));
        }
    }

    /** @brief await 前按层索引选出 Activity，不跨挂起保存 transmission 裸指针。 */
    [[nodiscard]] inline auto RetirementActivityAt(
        const SharedTransmission &Transport,
        const std::size_t Index,
        bool &Found) noexcept -> std::shared_ptr<Prism::Contract::CarrierActivity>
    {
        auto *Layer = Transport.get();
        auto Remaining = Index;
        while (Layer && Remaining != 0U)
        {
            Layer = Layer->NextLayer();
            --Remaining;
        }
        Found = Layer != nullptr;
        if (!Layer) return {};
        return Layer->Activity();
    }
}
