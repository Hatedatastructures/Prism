/**
 * @file HttpServer.hpp
 * @brief Prism Operations loopback HTTP/1.1 管理监听器。
 */

#pragma once

#include <Prism/Operations/Router.hpp>
#include <Prism/Operations/Web/Catalog.hpp>
#include <Prism/Operations/Http/Limits.hpp>
#include <Prism/Operations/HttpRequest.hpp>
#include <Prism/Operations/HttpRequestSecurity.hpp>
#include <Prism/Operations/HttpServerStartResult.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <chrono>
#include <atomic>
#include <memory>
#include <optional>
#include <utility>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>

namespace Prism::Operations
{

    struct HttpServerTestAccess;

    namespace Net = boost::asio;


    /**
     * @class HttpServer
     * @brief executor-affine、单请求单连接的 Operations HTTP/1.1 listener。
     * @details StateStrand 拥有 listener、连接 registry 和 drain 状态；每个连接的
     *          socket 操作由独立 connection strand 串行化，connection owner 负责 socket
     *          最终关闭。Executor/context 由调用方持有，必须运行至 Drain 成功或失败被
     *          上层 owner 保留。析构只投递强制关闭，不等待连接任务退栈。
     */
    class HttpServer final
    {
    public:
        using Endpoint = Net::ip::tcp::endpoint;
        using Deadline = std::chrono::steady_clock::time_point;

        struct DrainResult final
        {
            Prism::Fault::Failure Failure{};
            std::size_t RemainingConnections{0};
        };

        /**
         * @brief listener 冷启动配置。
         * @details Executor 只借用其调度域，不拥有 io_context；Router 按值复制，
         *          Bootstrap 与 WebResources 共享只读 owner，直至 listener 退栈。
         */
        struct Options final
        {
            Net::any_io_executor Executor;
            Endpoint BindEndpoint;
            Router OperationsRouter;
            std::chrono::milliseconds ReadDeadline{std::chrono::milliseconds{5000}};
            std::chrono::milliseconds DrainTimeout{std::chrono::milliseconds{5000}};
            std::shared_ptr<const BootstrapIdentity> Bootstrap;
            std::shared_ptr<const Web::Catalog> WebResources;
        };

        /** @brief 按值语义复制冷配置并创建 listener state owner。 */
        explicit HttpServer(const Options &OptionsValue);

        /** @brief 投递最佳努力关闭；不等待连接退栈，正常关闭必须先 await Drain。 */
        ~HttpServer() noexcept;

        HttpServer(const HttpServer &) = delete;
        auto operator=(const HttpServer &) -> HttpServer & = delete;
        HttpServer(HttpServer &&) = delete;
        auto operator=(HttpServer &&) -> HttpServer & = delete;

        /**
         * @brief 在 Options.Executor 上绑定 endpoint 并启动 accept loop。
         * @details listener 接管已接受 socket 和连接任务；expected 返回值报告 loopback
         *          验证或 socket setup 错误。executor 调度产生的异常沿协程异常路径传播。
         *          调用方须持有 HttpServer 与外部 executor 至 Drain 完成。
         */
        [[nodiscard]] auto Start() -> Net::awaitable<HttpServerStartResult>;

        /**
         * @brief 向唯一 state strand 提交关闭新连接准入。
         * @details 成功只表示关闭命令已排队；不会关闭已接受 socket，最终完成由 Drain 回报。
         */
        [[nodiscard]] auto CloseAdmission() noexcept
            -> std::expected<void, Prism::Fault::Failure>;

        /**
         * @brief 关闭准入、等待活动请求真实退栈，deadline 后才强制关闭剩余连接。
         * @param Limit 调用方持有的绝对停机截止时间；本操作不会延长该预算。
         * @return Drained 表示所有连接完成响应并退栈；其他状态保留真实失败和剩余数。
         * @note awaitable 被调用方取消时，已关闭的 admission 不会重开；调用方仍须持有
         *       server，并继续 Drain 或把失败 owner 保留到进程终态处理。
         */
        [[nodiscard]] auto Drain(Deadline Limit) -> Net::awaitable<DrainResult>;

        /** @brief 按值读取最近一次成功 Start 的绑定端点；不转移 acceptor 所有权。 */
        [[nodiscard]] auto LocalEndpoint() const -> Endpoint;

        /** @brief 读取 listener admission/running 状态；不代表连接任务已退栈。 */
        [[nodiscard]] auto IsRunning() const noexcept -> bool;

    private:
        friend struct HttpServerTestAccess;
        struct State;

        [[nodiscard]] static auto DrainOnState(std::shared_ptr<State> StateValue,
                                               Deadline Limit)
            -> Net::awaitable<DrainResult>;
        auto ForceCloseOnDestruction() noexcept -> void;

        std::shared_ptr<State> State_;
    };

} // namespace Prism::Operations
