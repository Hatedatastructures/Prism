/**
 * @file Upstream.hpp
 * @brief DNS 多上游解析的公开持有型门面。
 * @details 公开对象持有内部共享状态；Resolve 在返回 awaitable 前复制域名并固定状态所有者，
 *          因此调用方可在协程启动前释放外部引用。查询状态仍要求在同一 strand 上串行访问。
 */
#pragma once

#include <Prism/Net/Dns/Detail/UpstreamState.hpp>
#include <Prism/Net/Dns/Types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Prism::Network::Dns
{
    namespace Net = boost::asio;

    /**
     * @class Upstream
     * @brief 拥有异步 DNS 上游查询状态的公开门面。
     * @details 构造时接管执行器和配置；设置操作在同一串行执行器/strand 上同步执行。
     *          Resolve 在返回 awaitable 前固定自有域名和查询状态所有者；结果保留 DNS 响应及原始传输错误。
     *          取消由调用方协程与多上游未选中任务的取消收束；最终 socket 关闭由 QueryExecutor/ConnPool
     *          持有，DNS 请求没有流式半关闭接口。门面不拥有 executor context；调用方须保持 context 运行
     *          至查询完成。单个 io_context 的多线程 run 不替代串行调用合同。
     */
    class Upstream : public std::enable_shared_from_this<Upstream>
    {
    public:
        /**
         * @brief 创建上游查询门面。
         * @param Executor 所有查询与上游状态使用的执行器。
         * @param Options 上游服务器、查询策略、超时与连接池配置快照。
         */
        explicit Upstream(Net::any_io_executor Executor, UpstreamOptions Options = {})
            : State_(std::make_shared<Detail::UpstreamState>(
                  std::move(Executor), std::move(Options)))
        {
        }

        Upstream(const Upstream &) = delete;
        auto operator=(const Upstream &) -> Upstream & = delete;

        /** @brief 替换服务器快照；须与 Resolve 在同一串行 executor/strand 调用。 */
        auto SetServers(const std::vector<Server> &Servers) -> void
        {
            State_->SetServers(Servers);
        }

        /** @brief 设置 Fallback、First 或 Fastest 策略；须在同一串行域调用。 */
        auto SetMode(const Mode QueryMode) -> void
        {
            State_->SetMode(QueryMode);
        }

        /** @brief 设置后续上游尝试的默认超时；须在同一串行域调用。 */
        auto SetTimeout(const std::chrono::milliseconds Timeout) -> void
        {
            State_->SetTimeout(Timeout);
        }

        /** @brief 返回配置的服务器数量。 */
        [[nodiscard]] auto ServerCount() const -> std::size_t
        {
            return State_->ServerCount();
        }

        /** @brief 返回 TCP、DoT、DoH 连接池中的空闲连接数。 */
        [[nodiscard]] auto IdleConnCount() const -> std::size_t
        {
            return State_->IdleConnCount();
        }

        /** @brief 清理所有过期的空闲上游连接。 */
        auto ClearIdleConns() -> std::size_t
        {
            return State_->ClearIdleConns();
        }

        /**
         * @brief 在返回 awaitable 前固定查询状态和自有域名，再开始异步解析。
         * @param Domain 待解析域名；本方法返回前复制，不借用至协程启动。
         * @param QueryType DNS 查询类型。
         * @return DNS 响应；NXDOMAIN 是成功空结果，传输失败保留原始错误类别和值。
         * @note 单服务器和 Fallback 可由栈对象调用；既有多服务器并发策略要求调用对象原本由 shared_ptr 持有。
         */
        [[nodiscard]] auto Resolve(const std::string_view Domain, const QType QueryType)
            -> Net::awaitable<QueryResult>
        {
            return Detail::UpstreamState::ResolveOwned(
                State_, Detail::UpstreamResolveRequest{
                            std::string(Domain), QueryType, weak_from_this().lock()});
        }

    private:
        std::shared_ptr<Detail::UpstreamState> State_;
    };
} // namespace Prism::Network::Dns
