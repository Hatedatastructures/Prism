/**
 * @file Resolver.hpp
 * @brief DNS 解析服务的轻量公开门面。
 * @details 门面只持有共享 ResolverState；异步调用返回 awaitable 前复制输入并固定状态所有者。
 */
#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Net/Dns/AddressList.hpp>
#include <Preview/Net/Dns/Config.hpp>
#include <Preview/Net/Dns/Detail/ResolverState.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace Preview::Network::Dns
{
    namespace Net = boost::asio;

    /**
     * @class Resolver
     * @brief DNS 解析服务门面。
     * @details ResolverState 拥有缓存、规则、上游、执行器 owner 和维护任务；调用方停止新查询
     *          并排空在途查询后等待 Shutdown。完成前解析状态、维护协程和受管理 Context 均保持有效。
     *          只有由 ContextOwner 注册的 executor 才会自动固定 Context；外部 executor 的 context 由调用方
     *          保持运行至 Shutdown 完成。Resolver 不拥有上游 socket 的最终关闭权；TCP、DoT、DoH 连接由
     *          QueryExecutor/ConnPool 持有。
     */
    class Resolver
    {
    public:
        /** @brief 用默认 DNS 策略构造解析器。 */
        explicit Resolver(Net::any_io_executor Executor)
            : Resolver(std::move(Executor), Config{})
        {
        }

        /** @brief 接管执行器与配置快照；共享状态持有解析状态及 Context owner。 */
        explicit Resolver(Net::any_io_executor Executor, const Config &ConfigValue)
            : State_(std::make_shared<Detail::ResolverState>(
                  std::move(Executor), ConfigValue))
        {
        }

        Resolver(const Resolver &) = delete;
        auto operator=(const Resolver &) -> Resolver & = delete;

        /**
         * @brief 停止维护协程并等待其真实退栈。
         * @return 维护停止结果；调度拒绝、执行异常或未真实完成均作为 类型化失败 保留。
         * @note 调用方必须先停止新解析并排空在途查询；executor context 至少存活到 awaitable 完成。
         */
        [[nodiscard]] auto Shutdown()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            return Detail::ResolverState::ShutdownOwned(State_);
        }

        /**
         * @brief 解析域名或 IP 字面量。
         * @param Host 域名或数值地址；在返回 awaitable 前复制为自有字符串。
         * @return 独占、有界地址列表，或保留领域类别和原生 cause 的失败；规则 Negative 为成功空表。
         * @details 查询在 Resolver 的串行 executor 执行，并在完成前切回调用者 executor；取消作为 typed
         *          Canceled 返回，状态 owner 与复制后的输入存活到 awaitable 结束。
         */
        [[nodiscard]] auto AsyncResolve(std::string_view Host)
            -> Net::awaitable<std::expected<AddressList, Preview::Fault::Failure>>
        {
            return Detail::ResolverState::ResolveOwned(
                State_, std::string(Host));
        }

        /** @brief 按数值地址检查已冻结规则中的黑名单。 */
        [[nodiscard]] auto IsBlacklisted(const Net::ip::address &Address) const -> bool
        {
            return State_->IsBlacklisted(Address);
        }

        /** @brief 返回域名规范化结果；不访问共享解析状态。 */
        [[nodiscard]] static auto Normalize(std::string_view Domain) -> std::string
        {
            return Detail::ResolverState::Normalize(Domain);
        }

        /** @brief 返回缓存命中数；须在 解析器的串行执行域读取。 */
        [[nodiscard]] auto HitCount() const noexcept -> std::uint64_t
        {
            return State_->HitCount();
        }

        /** @brief 返回当前缓存条目数；须在 解析器的串行执行域读取。 */
        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return State_->Size();
        }

        /** @brief 清空缓存；须在 解析器的串行执行域调用。 */
        auto Clear() -> void
        {
            State_->Clear();
        }

    private:
        std::shared_ptr<Detail::ResolverState> State_;
    };
} // namespace Preview::Network::Dns
