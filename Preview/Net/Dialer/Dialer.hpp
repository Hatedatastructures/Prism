/** @file Dialer.hpp @brief 唯一 typed TCP 拨号 engine：注入 DNS、候选共享总 deadline、可取消地址竞速与败者回收。 */

#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Net/Dns/Resolver.hpp>
#include <Preview/Net/Dialer/Observation.hpp>
#include <Preview/Net/Target.hpp>
#include <Preview/Transport/Reliable.hpp>
#include <Preview/Transport/Transmission.hpp>

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

#include <chrono>
#include <cstddef>
#include <expected>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace Preview::Network::Dialer
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    /**
     * @brief 拨号选项：全部候选共享同一个总 deadline，域名只走注入的 DNS owner。
     * @details Resolver 为空时域名目标直接返回 DnsFailed，不落回系统解析器；
     *          数值地址不经过任何解析，只按数值端口构造 endpoint。
     */
    struct DialOptions final
    {
        std::chrono::milliseconds Timeout{std::chrono::seconds(10)}; ///< 全部候选共享的总预算。
        bool EnableIpv6{true};                                       ///< 关闭时只保留 IPv4 候选。
        std::shared_ptr<Preview::Network::Dns::Resolver> Resolver{}; ///< 域名解析 owner，可为空。
        ObservationOwner Observation{};
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
        [[nodiscard]] auto Connect(Preview::Network::Target Target)
            -> Net::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>;

        /** @brief 冷装配阶段调用，必须先于任何 Connect；不拥有 sink 的最终关闭权。 */
        auto AttachObservations(ObservationOwner Owner) -> void { Options_.Observation = std::move(Owner); }

    private:
        /** @brief 竞速事件：某个候选的完成结果，或总 deadline 到期标记。 */
        struct RaceEvent final
        {
            std::size_t Index{0};
            boost::system::error_code Error{};
            bool Expired{false};
        };

        using EventChannel = Net::experimental::channel<void(boost::system::error_code, RaceEvent)>;

        /** @brief 单个候选的 socket 与取消槽；两者都由竞速 owner 保活到该候选退栈。 */
        struct Attempt final
        {
            explicit Attempt(Net::any_io_executor Executor) : Socket(std::move(Executor)) {}
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
        };

        /** @brief 字面地址直接构造候选；域名只经注入 Resolver，空结果保留解析 cause。 */
        [[nodiscard]] static auto ResolveCandidates(const DialOptions &Options,
                                                   const Preview::Network::Target &Target)
            -> Net::awaitable<std::expected<std::vector<Tcp::endpoint>, Preview::Fault::Failure>>;

        /** @brief 单个候选的真实连接尝试；完成或取消都以一个事件退栈。 */
        [[nodiscard]] static auto RunAttempt(std::shared_ptr<Race> State, const std::size_t Index)
            -> Net::awaitable<void>;

        /** @brief 总 deadline owner：到期取消全部候选并投递一次 Expired 事件。 */
        [[nodiscard]] static auto WatchDeadline(std::shared_ptr<Race> State,
                                                const std::chrono::milliseconds Timeout)
            -> Net::awaitable<void>;

        /** @brief 关闭除 Keep 之外的全部候选 socket；Keep 为空时关闭全部。 */
        static auto CloseAttempts(const Race &State, const std::optional<std::size_t> Keep) -> void;

        Net::any_io_executor Executor_;
        DialOptions Options_;
    };

    inline auto Dialer::ResolveCandidates(const DialOptions &Options, const Preview::Network::Target &Target)
        -> Net::awaitable<std::expected<std::vector<Tcp::endpoint>, Preview::Fault::Failure>>
    {
        std::vector<Tcp::endpoint> Candidates;
        if (const auto Literal = Preview::Network::IpAddress(Target.Host))
        {
            if (Literal->is_v6() && !Options.EnableIpv6)
            {
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::NotSupported, {}});
            }
            Candidates.emplace_back(*Literal, Target.Port);
            co_return Candidates;
        }
        const auto *Domain = std::get_if<Preview::Network::DomainName>(&Target.Host.Get());
        if (Domain == nullptr || !Options.Resolver)
        {
            co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::DnsFailed, {}});
        }
        StageObservation Observation(Options.Observation, Preview::Foundation::NetworkLatencyStage::DnsResolution);
        const auto Addresses = co_await Options.Resolver->AsyncResolve(Domain->View());
        Observation.Complete(Addresses ? Preview::Fault::Failure{} : Addresses.error());
        if (!Addresses)
        {
            co_return std::unexpected(Addresses.error());
        }
        for (const auto &Address : *Addresses)
        {
            if (Address.is_v6() && !Options.EnableIpv6)
            {
                continue;
            }
            Candidates.emplace_back(Address, Target.Port);
        }
        if (Candidates.empty())
        {
            co_return std::unexpected(Preview::Fault::Failure{
                Preview::Fault::Code::DnsFailed, {}});
        }
        co_return Candidates;
    }

    inline auto Dialer::RunAttempt(std::shared_ptr<Race> State, const std::size_t Index) -> Net::awaitable<void>
    {
        auto &Value = *State->Attempts[Index];
        StageObservation Observation(State->Observation, Preview::Foundation::NetworkLatencyStage::TcpConnect);
        boost::system::error_code ConnectError;
        co_await Value.Socket.async_connect(
            State->Candidates[Index],
            Net::bind_cancellation_slot(Value.Signal.slot(), Net::redirect_error(Net::use_awaitable, ConnectError)));
        Observation.Complete(ConnectError ? Preview::Fault::Failure{Preview::Fault::ToCode(ConnectError), ConnectError}
            : Preview::Fault::Failure{});
        boost::system::error_code SendError;
        co_await State->Events->async_send(boost::system::error_code{}, RaceEvent{Index, ConnectError, false},
            Net::redirect_error(Net::use_awaitable, SendError));
    }

    inline auto Dialer::WatchDeadline(std::shared_ptr<Race> State, const std::chrono::milliseconds Timeout)
        -> Net::awaitable<void>
    {
        Net::steady_timer Timer(co_await Net::this_coro::executor);
        Timer.expires_after(Timeout);
        boost::system::error_code WaitError;
        co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, WaitError));
        if (WaitError)
        {
            co_return;
        }
        for (const auto &Value : State->Attempts)
        {
            Value->Signal.emit(Net::cancellation_type::all);
        }
        boost::system::error_code SendError;
        co_await State->Events->async_send(boost::system::error_code{},
            RaceEvent{State->Attempts.size(), {}, true},
            Net::redirect_error(Net::use_awaitable, SendError));
    }

    inline auto Dialer::CloseAttempts(const Race &State, const std::optional<std::size_t> Keep) -> void
    {
        for (std::size_t Index = 0; Index < State.Attempts.size(); ++Index)
        {
            if (Keep && Index == *Keep)
            {
                continue;
            }
            boost::system::error_code CloseError;
            State.Attempts[Index]->Socket.close(CloseError);
        }
    }

    inline auto Dialer::Connect(Preview::Network::Target Target)
        -> Net::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
    {
        if (Target.Host.Empty() || Target.Port == 0)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument, {}});
        }

        auto Candidates = co_await ResolveCandidates(Options_, Target);
        if (!Candidates)
        {
            co_return std::unexpected(Candidates.error());
        }

        auto State = std::make_shared<Race>(Executor_);
        State->Observation = Options_.Observation;
        State->Candidates = std::move(*Candidates);
        State->Events = std::make_shared<EventChannel>(Executor_, State->Candidates.size() + 1U);
        State->Watch = std::make_shared<Net::cancellation_signal>();
        for (std::size_t Index = 0; Index < State->Candidates.size(); ++Index)
        {
            State->Attempts.push_back(std::make_shared<Attempt>(Executor_));
            Net::co_spawn(Executor_, RunAttempt(State, Index), Net::detached);
        }
        Net::co_spawn(Executor_, WatchDeadline(State, Options_.Timeout),
            Net::bind_cancellation_slot(State->Watch->slot(), Net::detached));

        std::size_t Reported = 0;
        std::optional<std::size_t> Winner;
        boost::system::error_code LastError;
        bool Expired = false;
        bool Aborted = false;
        while (Reported < State->Attempts.size())
        {
            boost::system::error_code ReceiveError;
            const auto Event = co_await State->Events->async_receive(
                Net::redirect_error(Net::use_awaitable, ReceiveError));
            if (ReceiveError)
            {
                Aborted = true;
                break;
            }
            if (Event.Expired)
            {
                Expired = true;
                continue;
            }
            ++Reported;
            if (Event.Error)
            {
                LastError = Event.Error;
                continue;
            }
            if (Winner)
            {
                continue;
            }
            Winner = Event.Index;
            const auto Keep = Event.Index;
            for (std::size_t Index = 0; Index < State->Attempts.size(); ++Index)
            {
                if (Index != Keep)
                {
                    State->Attempts[Index]->Signal.emit(Net::cancellation_type::all);
                }
            }
        }

        State->Watch->emit(Net::cancellation_type::all);
        if (Aborted)
        {
            CloseAttempts(*State, std::nullopt);
            co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Canceled, {}});
        }
        if (!Winner)
        {
            CloseAttempts(*State, std::nullopt);
            if (Expired)
            {
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Timeout, {}});
            }
            co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::ToCode(LastError), LastError});
        }
        CloseAttempts(*State, Winner);
        auto Socket = std::move(State->Attempts[*Winner]->Socket);
        co_return std::make_shared<Preview::Transport::Reliable>(std::move(Socket));
    }

} // namespace Preview::Network::Dialer
