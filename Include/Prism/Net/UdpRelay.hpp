/** @file UdpRelay.hpp @brief UDP 双向中继的配置与 owning facade。 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <expected>
#include <memory>

namespace Prism::Transport
{
    class Unreliable;
}

namespace Prism::Network::Udp
{
    namespace Net = boost::asio;

    /** @brief UDP 中继的空闲回收与关联数量限制。 */
    struct RelayOptions
    {
        std::chrono::milliseconds IdleTimeout{std::chrono::seconds(60)};
        std::size_t MaxAssociations{256};
    };

    /**
     * @brief 拥有关联表并执行双向 UDP 中继。
     * @details 关联表和回收 timer 由 Run 的 coroutine executor 驱动；调用方须串行执行 Run，
     *          保持两端 socket executor 的 context 运行，并避免从外部并发修改端点。任一方向结束后
     *          组合协程会取消并等待其余任务退出，再提交两端 Cancel/Close 并等待 Activity::Drain。
     */
    class UdpRelay final
    {
        struct AssocTable;
        struct RelayDirection;
        using RelayResult = std::expected<void, Prism::Fault::Failure>;

    public:
        UdpRelay(std::shared_ptr<Prism::Transport::Unreliable> EndpointA,
            std::shared_ptr<Prism::Transport::Unreliable> EndpointB,
            RelayOptions Options = {});

        /** @brief 运行双向中继；awaitable 不借用本对象。 */
        [[nodiscard]] auto Run()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

    private:
        [[nodiscard]] static auto RunDirections(
            std::shared_ptr<Prism::Transport::Unreliable> EndpointA,
            std::shared_ptr<Prism::Transport::Unreliable> EndpointB,
            std::shared_ptr<AssocTable> Assoc) -> Net::awaitable<RelayResult>;

        [[nodiscard]] static auto RunOwned(
            std::shared_ptr<Prism::Transport::Unreliable> EndpointA,
            std::shared_ptr<Prism::Transport::Unreliable> EndpointB,
            RelayOptions Options) -> Net::awaitable<RelayResult>;

        [[nodiscard]] static auto RelayOne(RelayDirection Direction)
            -> Net::awaitable<RelayResult>;

        [[nodiscard]] static auto RecycleLoop(
            std::shared_ptr<AssocTable> Table,
            std::chrono::milliseconds IdleTimeout) -> Net::awaitable<RelayResult>;

        std::shared_ptr<Prism::Transport::Unreliable> A_;
        std::shared_ptr<Prism::Transport::Unreliable> B_;
        RelayOptions Opts_;
    };
} // namespace Prism::Network::Udp
