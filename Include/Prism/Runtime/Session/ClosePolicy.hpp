/** @file ClosePolicy.hpp @brief 安装预建会话关闭动作，调用线程不接管传输关闭权。 */
#pragma once
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Runtime/ActiveTransports.hpp>
#include <Prism/Runtime/SessionControl.hpp>
#include <Prism/Runtime/Session/LogState.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/system/error_code.hpp>
#include <expected>
#include <memory>
namespace Prism::Runtime
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
        std::shared_ptr<boost::asio::experimental::channel<void(boost::system::error_code)>> Cancellation;
        boost::asio::any_io_executor Executor;
    };
    /** @brief 安装阶段绑定 owner；运行阶段只提交预建动作，最终 drain 由会话编排等待。 */
    class SessionClosePolicy final
    {
    public:
        /** @brief 请求各原 executor 关闭；失败由槽保活，不在调用线程做 fallback。 */
        [[nodiscard]] static auto CloseActive(const std::shared_ptr<ActiveTransports>& Active)
            -> std::expected<void, Prism::Fault::Failure>;
        /** @brief 只提交安装的动作，日志在动作实际执行时由原 executor 发布。 */
        [[nodiscard]] static auto CloseAndLog(const SessionCloseRequest& Request)
            -> std::expected<void, Prism::Fault::Failure>;
        /** @brief 冷安装取消 hook；hook 只记录取消意图并通知会话 runner，不持有 control。
         * @details channel 借用在拥有闭包内保持至交付，失败关闭槽永久保留真实 owner。
         * 最终 close 仍由 runner 执行；之后调用方等待 Active::Finalize 才能宣称资源退休。
         */
        [[nodiscard]] static auto InstallCancelHook(const SessionCancellationRequest& Request)
            -> std::expected<void, Prism::Fault::Failure>;
    };
}
