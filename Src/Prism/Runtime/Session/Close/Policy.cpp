/** @file Policy.cpp @brief 会话关闭动作安装和一次性提交实现。 */
#include <Prism/Runtime/Session/ClosePolicy.hpp>

#include <memory>

namespace Prism::Runtime
{
    auto SessionClosePolicy::CloseActive(const std::shared_ptr<ActiveTransports>& Active)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Active)
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        return Active->RequestClose();
    }

    auto SessionClosePolicy::CloseAndLog(const SessionCloseRequest& Request)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Request.Control)
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        return Request.Control->CloseOnce();
    }

    auto SessionClosePolicy::InstallCancelHook(const SessionCancellationRequest& Request)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Request.Control || !Request.Active || !Request.Cancellation)
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto Closed = Request.Control->SetCloseAction(
            [Active = Request.Active, Log = Request.LogState]()
                -> std::expected<void, Prism::Fault::Failure>
            {
                auto Result = Active->RequestClose();
                if (Result && Log) Log->LogClose();
                return Result;
            });
        if (!Closed)
        {
            return Closed;
        }
        return Request.Control->AddCancelHook(
            [Active = Request.Active, Signal = Request.Cancellation]
            {
                Active->MarkCancelRequested();
                (void)Signal->try_send(boost::system::error_code{});
            });
    }
}
