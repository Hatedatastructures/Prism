/** @file Dialer.hpp @brief 唯一 typed TCP 拨号 engine：注入 DNS、候选共享总 deadline、可取消地址竞速与败者回收。 */

#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Dns/Resolver.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Transport/Reliable.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/system/error_code.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace Prism::Network::Dialer
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    struct ObservationOwner final
    {
        std::weak_ptr<Prism::Foundation::TrafficSink> Sink;
        Prism::WorkerId Worker;
    };

    /** @brief 每次 DNS 或 socket connect 的局部阶段；退出而未完成时记录取消。 */
    class StageObservation final
    {
    public:
        StageObservation(const ObservationOwner &Owner, Prism::Foundation::NetworkLatencyStage Stage);
        StageObservation(const StageObservation &) = delete;
        auto operator=(const StageObservation &) -> StageObservation & = delete;
        ~StageObservation();

        auto Complete(Prism::Fault::Failure Failure = {}) noexcept -> void;

    private:
        std::shared_ptr<Prism::Foundation::TrafficSink> Sink_;
        Prism::WorkerId Worker_;
        Prism::Foundation::NetworkLatencyStage Stage_;
        std::chrono::steady_clock::time_point Started_{};
    };

    /**
     * @brief 拨号选项：全部候选共享同一个总 deadline，域名只走注入的 DNS owner。
     * @details Resolver 为空时域名目标直接返回 DnsFailed，不落回系统解析器；
     *          数值地址不经过任何解析，只按数值端口构造 endpoint。
     */
    struct DialOptions final
    {
        /** @brief 单候选连接的借用输入；socket 与 endpoint 在 awaitable 完成前保持有效。 */
        struct ConnectRequest final
        {
            Tcp::socket &Socket;
            const Tcp::endpoint &Endpoint;
        };

        /**
         * @brief 单候选连接函数；借用连接输入至 awaitable 完成。
         * @details cancellation slot 必须绑定到内部待决操作，使总 deadline 能中断连接。
         *          返回原生错误；默认空函数使用 socket.async_connect。
         */
        using ConnectFn = std::function<Net::awaitable<boost::system::error_code>(
            ConnectRequest, Net::cancellation_slot)>;

        std::chrono::milliseconds Timeout{std::chrono::seconds(10)}; ///< 全部候选共享的总预算。
        bool EnableIpv6{true};                                       ///< 关闭时只保留 IPv4 候选。
        std::shared_ptr<Prism::Network::Dns::Resolver> Resolver{}; ///< 域名解析 owner，可为空。
        ObservationOwner Observation{};
        ConnectFn Connect{}; ///< 可选候选连接注入；空值使用真实 socket 连接。
    };

    /**
     * @class Dialer
     * @brief 唯一 TCP 拨号 owner：同一 typed 目标、同一竞速操作、同一总 deadline。
     * @details Connect() 在自身 executor 上并发启动全部候选；首个成功者胜出，其余候选以
     *          cancellation_type::all 取消，并在返回前等待每个候选的真实退栈，因此失败者
     *          socket 不会晚于调用者收口。总 deadline 到期取消所有候选并返回 Timeout；
     *          调用者取消传播为 Canceled。目标、解析 owner 与超时由调用者冷注入。
     */
    class Dialer final
    {
    public:
        explicit Dialer(Net::any_io_executor Executor, DialOptions Options = {})
            : Executor_(std::move(Executor)), Options_(std::move(Options))
        {
        }

        /**
         * @brief 拨号并返回首个成功传输；失败返回唯一领域失败值。
         * @param Target 按值接管 typed 主机与数值端口；域名需要已注入的 Resolver。
         * @return 成功返回 Reliable 传输 owner；失败返回 `Failure{Code, Native}` 且不携带传输，
         *         Native 保留引擎实际观察到的原生 cause，所有失败者 socket 在返回前已关闭。
         * @details 在构造时的 executor 上执行；调用者取消传播为 Canceled。成功传输的半关闭与
         *          最终关闭由返回的 owner 负责，本 engine 不保留任何候选资源。
         */
        [[nodiscard]] auto Connect(Prism::Network::Target Target)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>;

        /** @brief 冷装配阶段调用，必须先于任何 Connect；不拥有 sink 的最终关闭权。 */
        auto AttachObservations(ObservationOwner Owner) -> void { Options_.Observation = std::move(Owner); }

    private:
        /** @brief 竞速事件：候选结果、总 deadline 或全部候选退栈标记。 */
        struct RaceEvent final
        {
            std::size_t Index{0};
            boost::system::error_code Error{};
            bool Expired{false};
            bool Retired{false};
        };

        using EventChannel = Net::experimental::channel<void(boost::system::error_code, RaceEvent)>;

        /** @brief 单个候选的 socket 与取消槽；两者都由竞速 owner 保活到该候选退栈。 */
        struct Attempt final
        {
            explicit Attempt(Net::any_io_executor Executor);
            Tcp::socket Socket;
            Net::cancellation_signal Signal;
        };

        /** @brief 一次拨号竞速的共享材料；候选、事件通道与 deadline watcher 集中拥有。 */
        struct Race final
        {
            explicit Race(Net::any_io_executor Value) : Executor(std::move(Value)) {}
            Net::any_io_executor Executor;
            std::vector<Tcp::endpoint> Candidates;
            std::vector<std::shared_ptr<Attempt>> Attempts;
            std::shared_ptr<EventChannel> Events;
            std::shared_ptr<Net::cancellation_signal> Watch;
            ObservationOwner Observation;
            DialOptions::ConnectFn Connect;
            std::atomic<std::size_t> Retired{0};
        };

        struct RaceOutcome final
        {
            std::optional<std::size_t> Winner;
            boost::system::error_code LastError;
            bool Expired{false};
            bool Aborted{false};
        };

        /** @brief 字面地址直接构造候选；域名只经注入 Resolver，空结果保留解析 cause。 */
        [[nodiscard]] static auto ResolveCandidates(const DialOptions &Options,
                                                   const Prism::Network::Target &Target)
            -> Net::awaitable<std::expected<std::vector<Tcp::endpoint>, Prism::Fault::Failure>>;

        /** @brief 单候选先发布原连接结果；co_spawn completion 再发布实际退栈标记。 */
        [[nodiscard]] static auto RunAttempt(std::shared_ptr<Race> State, const std::size_t Index)
            -> Net::awaitable<void>;

        [[nodiscard]] static auto RunRace(
            std::shared_ptr<Race> State, std::chrono::milliseconds Timeout)
            -> Net::awaitable<RaceOutcome>;

        static auto CompleteAttempt(std::shared_ptr<Race> State,
                                    std::size_t Index,
                                    bool Failed) -> void;

        /** @brief 总 deadline owner：到期取消全部候选并投递一次 Expired 事件。 */
        [[nodiscard]] static auto WatchDeadline(std::shared_ptr<Race> State,
                                                const std::chrono::milliseconds Timeout)
            -> Net::awaitable<void>;

        /** @brief 关闭除 Keep 之外的全部候选 socket；Keep 为空时关闭全部。 */
        static auto CloseAttempts(const Race &State, const std::optional<std::size_t> Keep) -> void;

        Net::any_io_executor Executor_;
        DialOptions Options_;
    };

} // namespace Prism::Network::Dialer
