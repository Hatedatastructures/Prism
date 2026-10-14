/** @file RetirementFailure.hpp @brief AnyTLS 关闭回收的首因转换与 executor fatal 发布。 */
#pragma once

#include <Preview/Foundation/Executor/ContextOwner.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/system/system_error.hpp>
#include <exception>
#include <expected>
#include <new>
#include <system_error>

namespace Preview::Anytls::Detail
{
    /** @brief 将同一异常 cause 映射为一个完整的 typed failure。 */
    [[nodiscard]] inline auto FailureFromRetirementException(
        const std::exception_ptr Exception) noexcept -> Preview::Fault::Failure
    {
        try
        {
            if (Exception) std::rethrow_exception(Exception);
        }
        catch (const boost::system::system_error &Error)
        {
            const auto Native = static_cast<std::error_code>(Error.code());
            return {Preview::Fault::ToCode(Native), Native};
        }
        catch (const std::system_error &Error)
        {
            return {Preview::Fault::ToCode(Error.code()), Error.code()};
        }
        catch (const std::bad_alloc &)
        {
            return {Preview::Fault::Code::ResourceUnavailable};
        }
        catch (...)
        {
            return {Preview::Fault::Code::IoError};
        }
        return {Preview::Fault::Code::IoError};
    }

    /** @brief 将 executor exception 发布至所属 Context，并返回原生 typed cause。 */
    [[nodiscard]] inline auto FailureFromExecutorException(
        const boost::asio::any_io_executor &Executor,
        const std::exception_ptr Exception) noexcept -> Preview::Fault::Failure
    {
        try
        {
            if (const auto Owner = Preview::Executor::ContextOwner::Find(Executor);
                Owner && Owner->Fatal)
                Owner->Fatal->Publish(Exception);
        }
        catch (...)
        {
        }
        return FailureFromRetirementException(Exception);
    }

    /** @brief 保留最先确定的完整 Failure，不拼接不同操作的 Native cause。 */
    inline auto PreserveRetirementFailure(
        Preview::Fault::Failure &Primary,
        const Preview::Fault::Failure &Next) noexcept -> void
    {
        if (!Primary.Failed() && Next.Failed()) Primary = Next;
    }

    /** @brief 收敛一条 close/drain attempt 的唯一首因。 */
    inline auto KeepFirstRetirementFailure(
        std::expected<void, Preview::Fault::Failure> &FirstFailure,
        const Preview::Fault::Failure &Failure) -> void
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

    /** @brief 向原 execution_context 的 Fatal owner 发布无法恢复的清理异常。 */
    inline auto PublishRetirementFatal(
        const boost::asio::any_io_executor &Executor,
        const std::exception_ptr Exception) noexcept -> void
    {
        try
        {
            if (const auto Owner = Preview::Executor::ContextOwner::Find(Executor);
                Owner && Owner->Fatal)
                Owner->Fatal->Publish(Exception);
        }
        catch (...)
        {
        }
    }
}
