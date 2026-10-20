/**
 * @file Router.hpp
 * @brief Prism 管理面 typed 查询、命令和异步 Operation 路由。
 * @details Router 只处理值模型。所有可变路由状态在独立 strand 上访问，
 *          因此管理面不会把 handler、快照或控制器引用暴露给调用方。
 */

#pragma once
#include <Prism/Operations/OperationPublicationReceipt.hpp>

#include <Prism/Operations/Models.hpp>
#include <Prism/Operations/Redaction.hpp>
#include <Prism/Operations/ResponseDeliveryReceipt.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <functional>
#include <memory>
#include <string>

namespace Prism::Operations
{

    namespace Net = boost::asio;
    namespace Detail
    {
        struct State;
    }

    /** @brief 独立管理面监听端点的值配置；实际 HTTP listener 由外层单独拥有。 */
    struct ManagementEndpoint final
    {
        std::string Address{"127.0.0.1"};
        std::uint16_t Port{9090};
    };

    /** @brief typed in-process router 的冷路径配置。 */
    struct RouterOptions final
    {
        ManagementEndpoint Endpoint{};
        std::size_t MaxOperations{1024};
    };

    /**
     * @brief 一个已登记 Accepted 命令的唯一终态 owner。
     * @details Router 在调用命令 handler 前创建并登记 OperationId；真实业务 owner
     *          只持有此值句柄并提交终态，不拥有 Router、HTTP connection 或业务数据面。
     */
    class OperationCompletion final
    {
    public:
        using Deadline = ResponseDeliveryReceipt::Deadline;

        /** @brief 返回由 Router 预先登记的稳定 operation identity。 */
        [[nodiscard]] auto Id() const noexcept -> OperationId;

        /** @brief 提交真实终态；成功回执证明已提交，失败表示未提交，通知失败独立保留。 */
        [[nodiscard]] auto CompleteAsync(CommandResult Result) const
            -> Net::awaitable<std::expected<OperationPublicationReceipt, Prism::Fault::Failure>>;

        /** @brief 等待对应 HTTP 初始命令响应真实写完；失败只作为观察回执返回。 */
        [[nodiscard]] auto WaitForResponseDeliveryAsync(const Deadline Limit) const
            -> Net::awaitable<ResponseDeliveryReceipt::Outcome>;

        /** @brief 等待此前已接受的其它命令终态后再启动 ProcessDrain。 */
        [[nodiscard]] auto WaitForPriorOperationsAsync(const Deadline Limit) const
            -> Net::awaitable<ResponseDeliveryReceipt::Outcome>;

    private:
        friend class Router;

        OperationCompletion(std::weak_ptr<Detail::State> StateValue,
                            OperationId OperationValue,
                            ResponseDeliveryReceipt DeliveryValue);

        std::weak_ptr<Detail::State> State_;
        OperationId Operation_{};
        ResponseDeliveryReceipt Delivery_;
    };

    /** @brief 同一管理路由的查询与命令绑定；冷构造按值接管，后续调用均在 router strand。 */
    struct RouterHandlers final
    {
        std::function<Net::awaitable<QueryResult>(Query)> Query;
        std::function<Net::awaitable<CommandResult>(Command, OperationCompletion)> Command;
    };

    inline auto OperationCompletion::Id() const noexcept -> OperationId
    {
        return Operation_;
    }

    inline auto OperationCompletion::WaitForResponseDeliveryAsync(const Deadline Limit) const
        -> Net::awaitable<ResponseDeliveryReceipt::Outcome>
    {
        co_return co_await Delivery_.WaitAsync(Limit);
    }

    /**
     * @class Router
     * @brief 独立 executor 上运行的 typed Operations 路由器。
     * @details 查询 handler 和命令 handler 都在 router strand 上调用。命令 handler
     *          收到预先登记的 OperationCompletion；实际业务 owner 只能通过该句柄提交
     *          终态。该类不提供 HTTP 解析或 listener 所有权。
     */
    class Router final
    {
    public:
        using QueryHandler = std::function<Net::awaitable<QueryResult>(Query)>;
        using CommandHandler =
            std::function<Net::awaitable<CommandResult>(Command, OperationCompletion)>;

        /** @brief 在独立 strand 构造路由；接管绑定与配置，未绑定操作返回 unavailable。 */
        Router(Net::any_io_executor Executor,
               RouterHandlers Handlers = {},
               RouterOptions Options = {});

        Router(const Router &Other) noexcept;
        auto operator=(const Router &Other) noexcept -> Router &;
        Router(Router &&Other) noexcept;
        auto operator=(Router &&Other) noexcept -> Router &;

        [[nodiscard]] auto Endpoint() const -> ManagementEndpoint;

        [[nodiscard]] auto QueryAsync(Query QueryValue) const -> Net::awaitable<QueryResult>;

        [[nodiscard]] auto ExecuteAsync(Command CommandValue,
                                        ResponseDeliveryReceipt Delivery) const
            -> Net::awaitable<CommandResult>;

        [[nodiscard]] auto StatusAsync(const OperationId Operation,
                                       const Prism::RequestId Correlation = {}) const
            -> Net::awaitable<CommandResult>;

    private:
        [[nodiscard]] static auto QueryFailureFromException(
            std::exception_ptr Error) noexcept -> Prism::Fault::Failure;

        [[nodiscard]] static auto QueryOnStrand(
            const std::shared_ptr<Detail::State> &StateValue,
            Query QueryValue) -> Net::awaitable<QueryResult>;

        [[nodiscard]] static auto ExecuteOnStrand(
            const std::shared_ptr<Detail::State> &StateValue,
            Command CommandValue,
            ResponseDeliveryReceipt Delivery) -> Net::awaitable<CommandResult>;

        [[nodiscard]] static auto StatusOnStrand(
            const std::shared_ptr<Detail::State> &StateValue,
            const OperationId Operation,
            const Prism::RequestId Correlation) -> Net::awaitable<CommandResult>;

        std::shared_ptr<Detail::State> State_;
    };

} // namespace Prism::Operations
