/** @file ClosePolicy.hpp @brief 安装预建会话关闭动作，调用线程不接管传输关闭权。 */
#pragma once
#include <Preview/Runtime/ActiveTransports.hpp>
#include <Preview/Runtime/SessionControl.hpp>
#include <Preview/Runtime/Session/LogState.hpp>
#include <boost/asio/experimental/channel.hpp>
namespace Preview::Runtime
{
    struct SessionCloseRequest final
    {
        std::shared_ptr<SessionControl> Control;
        std::shared_ptr<ActiveTransports> Active;
        std::shared_ptr<SessionSupport::SessionLogState> LogState;
    };
    struct SessionCancellationRequest final
    {
        std::shared_ptr<SessionControl> Control;
        std::shared_ptr<ActiveTransports> Active;
        std::shared_ptr<SessionSupport::SessionLogState> LogState;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> Cancellation;
        Net::any_io_executor Executor;
    };
    /** @brief 安装阶段绑定 owner；运行阶段只提交预建动作，最终 drain 由会话编排等待。 */
    class SessionClosePolicy final
    {
    public:
        /** @brief 请求各原 executor 关闭；失败由槽保活，不在调用线程做 fallback。 */
        [[nodiscard]] static auto CloseActive(const std::shared_ptr<ActiveTransports>& Active)
            -> std::expected<void, Preview::Fault::Failure>
        {
            if (!Active) return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            return Active->RequestClose();
        }
        /** @brief 只提交安装的动作，日志在动作实际执行时由原 executor 发布。 */
        [[nodiscard]] static auto CloseAndLog(const SessionCloseRequest& Request)
            -> std::expected<void, Preview::Fault::Failure>
        {
            if (!Request.Control) return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            return Request.Control->CloseOnce();
        }
        /** @brief 冷安装拥有传输和日志的关闭动作；取消 hook 仅弱持 control。
         * @details channel 借用在拥有闭包内保持至交付，失败关闭槽永久保留真实 owner。
         * 无半关闭；之后调用方等待 Active::Finalize 才能宣称资源退休。
         */
        [[nodiscard]] static auto InstallCancelHook(const SessionCancellationRequest& Request)
            -> std::expected<void, Preview::Fault::Failure>
        {
            if (!Request.Control || !Request.Active || !Request.Cancellation)
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            auto Closed = Request.Control->SetCloseAction(
                [Active = Request.Active, Log = Request.LogState]() -> std::expected<void, Preview::Fault::Failure>
                { auto Result = Active->RequestClose(); if (Result && Log) Log->LogClose(); return Result; });
            if (!Closed) return Closed;
            return Request.Control->AddCancelHook(
                [Active = Request.Active,
                 Weak = std::weak_ptr<SessionControl>(Request.Control),
                 Signal = Request.Cancellation]
                {
                    Active->MarkCancelRequested();
                    if (auto Control = Weak.lock()) (void)Control->CloseOnce();
                    (void)Signal->try_send(boost::system::error_code{});
                });
        }
    };
}
