/**
 * @file OperationsApi.hpp
 * @brief Preview 查询与命令组合 API。
 */

#pragma once

#include <Preview/Operations/Operations.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <functional>
#include <utility>

namespace Preview::Composition::Api
{

    class OperationsApi final
    {
    public:
        using CommandHandler =
            std::function<Preview::Operations::CommandResult(const Preview::Operations::Command &)>;
        using QueryHandler =
            std::function<Preview::Operations::QueryResult(const Preview::Operations::Query &)>;
        using OperationsRouter = Preview::Operations::Router;

        auto SetCommandHandler(CommandHandler Handler) -> void
        {
            CommandHandler_ = std::move(Handler);
        }

        auto SetQueryHandler(QueryHandler Handler) -> void
        {
            QueryHandler_ = std::move(Handler);
        }

        /**
         * @brief 创建独立管理 executor 上的 typed router。
         * @param Executor 管理面专用 executor，不占用数据面 worker。
         * @param Options listener 预留配置及 Operation 保留上限。
         * @return 不携带本对象指针的值路由器。
         */
        [[nodiscard]] auto MakeRouter(
            boost::asio::any_io_executor Executor,
            Preview::Operations::RouterOptions Options = {}) const -> OperationsRouter
        {
            return OperationsRouter(std::move(Executor), QueryHandler_, CommandHandler_,
                                    std::move(Options));
        }

        [[nodiscard]] auto Execute(const Preview::Operations::Command &CommandValue)
            const -> Preview::Operations::CommandResult
        {
            const auto Correlation = Preview::Operations::CorrelationOf(CommandValue);
            if (!CommandHandler_)
            {
                return Preview::Operations::CommandResult::Unavailable(Correlation);
            }
            try
            {
                auto Result = CommandHandler_(CommandValue);
                return Preview::Operations::Redact(std::move(Result));
            }
            catch (...)
            {
                return Preview::Operations::CommandResult::Failed(Correlation);
            }
        }

        [[nodiscard]] auto Query(const Preview::Operations::Query &QueryValue) const
            -> Preview::Operations::QueryResult
        {
            const auto Correlation = Preview::Operations::CorrelationOf(QueryValue);
            if (!QueryHandler_)
            {
                return Preview::Operations::QueryResult::Unavailable(Correlation);
            }
            try
            {
                auto Result = QueryHandler_(QueryValue);
                return Preview::Operations::Redact(std::move(Result));
            }
            catch (...)
            {
                return Preview::Operations::QueryResult::Failed(Correlation);
            }
        }

    private:
        CommandHandler CommandHandler_;
        QueryHandler QueryHandler_;
    };

} // namespace Preview::Composition::Api
