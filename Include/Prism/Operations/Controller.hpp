/**
 * @file Controller.hpp
 * @brief Operations 管理面的独立 io_context、线程、Router 与 HTTP server owner。
 */

#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Operations/HttpServer.hpp>
#include <Prism/Operations/HttpServerStartResult.hpp>
#include <Prism/Operations/Models.hpp>
#include <Prism/Operations/Router.hpp>
#include <Prism/Operations/Web/Catalog.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/system/error_code.hpp>

#include <chrono>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <thread>

namespace Prism::Operations
{

    namespace Net = boost::asio;

    /**
     * @class Controller
     * @brief 独立拥有管理查询路由、HTTP listener 与管理线程的进程级控制器。
     * @details Start 只在 Application 冷启动路径同步执行；Drain 在调用方 executor
     *          提交到管理 io_context，并以原始绝对 deadline 等待 HTTP 响应退栈。
     *          只有 Drain 成功且管理 io.run 自然返回后才允许 Join。
     */
    class Controller final
    {
    public:
        using Endpoint = HttpServer::Endpoint;
        using Deadline = HttpServer::Deadline;
        using DrainResult = HttpServer::DrainResult;

        struct Options final
        {
            Endpoint BindEndpoint{Net::ip::address_v4::loopback(), 9090};
            RouterHandlers Handlers{};
            std::size_t MaxOperations{1024};
            std::chrono::milliseconds ReadDeadline{std::chrono::milliseconds{5000}};
            std::chrono::milliseconds DrainTimeout{std::chrono::milliseconds{5000}};
            std::shared_ptr<const BootstrapIdentity> Bootstrap;
            std::shared_ptr<const Web::Catalog> WebResources;
        };

        /** @brief 按值接管管理配置并创建独立路由器与 listener 状态。 */
        explicit Controller(Options OptionsValue);

        ~Controller() noexcept = default;

        Controller(const Controller&) = delete;
        auto operator=(const Controller&) -> Controller& = delete;
        Controller(Controller&&) = delete;
        auto operator=(Controller&&) -> Controller& = delete;

        /**
         * @brief 冷启动时绑定 HTTP endpoint 并启动独立管理线程。
         * @details 只由非协程 Application::Start 调用；返回实际绑定端点或 listener 错误。
         *          启动协程在管理 io_context 上完成，不借用应用 control executor。
         */
        [[nodiscard]] auto Start() -> HttpServerStartResult;

        /**
         * @brief 封闭 HTTP 准入并按绝对 deadline 等待活动响应完整退栈。
         * @param Limit 调用方提供的同一停机绝对期限，不在此处延长。
         * @return listener 的真实 drain 失败和剩余连接数。
         * @note 一次 Drain 开始后不接受第二次尝试；失败或取消后调用方必须保留 Controller
         *       并将失败交给应用停机 owner，不能通过 Join 释放其管理线程。
         */
        [[nodiscard]] auto Drain(const Deadline Limit) -> Net::awaitable<DrainResult>;
        /**
         * @brief 在 Application::Run 返回后回收已自然结束的管理线程。
         * @details 不等待仍在运行的 io.run；调用顺序要求先成功 Drain，且 run 已自然返回。
         */
        [[nodiscard]] auto Join() noexcept -> std::expected<void, Prism::Fault::Failure>;

        /** @brief 返回 Start 成功绑定的管理端点值。 */
        [[nodiscard]] auto LocalEndpoint() const -> Endpoint;

    private:
        struct State;

        [[nodiscard]] static auto MakeRouterOptions(const Options& OptionsValue) -> RouterOptions;

        [[nodiscard]] static auto MakeServerOptions(Net::any_io_executor Executor,
            const Options& OptionsValue, const Router& OperationsRouter) -> HttpServer::Options;

        static auto RecordIoFailure(State& StateValue, Prism::Fault::Failure Failure) noexcept -> void;

        static auto RunManagementIo(const std::shared_ptr<State>& StateValue) noexcept -> void;

        [[nodiscard]] static auto FailureFromException(const std::exception_ptr& Exception) noexcept
            -> Prism::Fault::Failure;

        [[nodiscard]] static auto WaitUntil(const Deadline Limit)
            -> Net::awaitable<boost::system::error_code>;
        [[nodiscard]] static auto DrainOnManagementIo(const std::shared_ptr<State>& StateValue,
            const Deadline Limit) -> Net::awaitable<DrainResult>;

        static auto PublishIoExit(const std::shared_ptr<State>& StateValue) noexcept -> void;

        static auto CloseFailedStart(const std::shared_ptr<State>& StateValue) noexcept -> void;

        std::shared_ptr<State> State_;
        std::thread ManagementThread_;
    };

} // namespace Prism::Operations
