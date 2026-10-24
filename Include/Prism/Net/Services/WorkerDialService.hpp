/**
 * @file WorkerDialService.hpp
 * @brief Worker-owned 唯一 DNS + TCP 拨号端口。
 * @details Resolver 与拨号 engine 在 Worker executor 上冷建；调用者只提交 owner-held
 *          Target，不接触 resolver、socket 或内部缓存。域名不会落回系统解析器，
 *          全部候选共享 engine 的总 deadline。
 */

#pragma once

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Net/Dns/Resolver.hpp>
#include <Prism/Net/Target.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <chrono>
#include <expected>
#include <memory>
#include <system_error>
#include <utility>

namespace Prism::Network::Services
{

    namespace Net = boost::asio;

    /** @brief Worker 拨号冷参数：executor、DNS 配置、总 deadline 与族别策略。 */
    struct WorkerDialOptions final
    {
        Net::any_io_executor Executor;
        Prism::Network::Dns::Config Dns;
        std::chrono::milliseconds Timeout{std::chrono::seconds(10)};
        bool EnableIpv6{true};
        Prism::Network::Dialer::ObservationOwner Observation{};
    };

    /**
     * @class WorkerDialService
     * @brief Worker 拥有的唯一拨号端口；内部只使用一个 Dialer engine 与一个 Resolver。
     */
    class WorkerDialService final
    {
    public:
        explicit WorkerDialService(WorkerDialOptions Options);

        /** @brief 一次拨号：目标按值交给 engine，失败保留领域类别与原生 cause。 */
        [[nodiscard]] auto Connect(Prism::Network::Target Target)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>;

        /** @brief admission 已关闭且调用者已排空 Connect 后，等待 Resolver 维护协程真实退栈。 */
        [[nodiscard]] auto Shutdown()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        [[nodiscard]] auto Resolver() const noexcept
            -> const std::shared_ptr<Prism::Network::Dns::Resolver> &
        {
            return Resolver_;
        }

        /** @brief Worker 启动前绑定进程统计 owner；后续各阶段只发送数值报告。 */
        auto AttachObservations(Prism::Network::Dialer::ObservationOwner Owner) -> void
        { Dialer_.AttachObservations(std::move(Owner)); }

    private:
        std::shared_ptr<Prism::Network::Dns::Resolver> Resolver_;
        Prism::Network::Dialer::Dialer Dialer_;
        std::atomic<bool> Stopping_{false};
    };

} // namespace Prism::Network::Services
