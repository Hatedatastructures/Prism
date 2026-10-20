/**
 * @file RouterState.hpp
 * @brief Operations Router 的私有状态与终态发布 seam。
 */
#pragma once

#include <Prism/Operations/Router.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>

#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <utility>

namespace Prism::Operations::Detail
{
    /** @brief Router 独占 strand 上的命令状态与等待者通知 owner。 */
    struct State final
    {
        State(boost::asio::any_io_executor Executor,
              RouterOptions OptionsValue,
              RouterHandlers Handlers)
            : Strand_(boost::asio::make_strand(std::move(Executor))),
              OperationChangeTimer_(Strand_),
              Configuration_(std::move(OptionsValue)),
              QueryHandler_(std::move(Handlers.Query)),
              CommandHandler_(std::move(Handlers.Command))
        {
            if (Configuration_.MaxOperations == 0)
            {
                Configuration_.MaxOperations = 1;
            }
        }

        boost::asio::strand<boost::asio::any_io_executor> Strand_;
        boost::asio::steady_timer OperationChangeTimer_;
        RouterOptions Configuration_;
        std::function<boost::asio::awaitable<QueryResult>(Query)> QueryHandler_;
        std::function<boost::asio::awaitable<CommandResult>(Command, OperationCompletion)>
            CommandHandler_;
        std::map<std::uint64_t, CommandResult> Operations_;
        std::uint64_t NextOperation_{1};
        bool OperationWaiterActive_{false};
        std::optional<Prism::Fault::Failure> OperationSignalFailure_;
    };

    [[nodiscard]] auto CompleteOperation(
        State &StateValue,
        OperationId Operation,
        CommandResult Result)
        -> std::expected<OperationPublicationReceipt, Prism::Fault::Failure>;
}
