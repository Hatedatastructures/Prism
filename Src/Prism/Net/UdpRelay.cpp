/** @file UdpRelay.cpp @brief UDP 双向中继与关联回收实现。 */
#include <Prism/Net/UdpRelay.hpp>
#include <Prism/Net/Udp/Detail/EndpointRetirement.hpp>
#include <Prism/Transport/Unreliable.hpp>

#include <boost/asio/error.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <map>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>
#include <variant>

namespace Prism::Network::Udp::Detail
{
    EndpointRetirement::EndpointRetirement(
        std::shared_ptr<Prism::Transport::Unreliable> First,
        std::shared_ptr<Prism::Transport::Unreliable> Second)
        : Endpoints_{std::move(First), std::move(Second)}
    {
    }

    auto EndpointRetirement::Finish(
        Prism::Fault::Failure Primary,
        std::exception_ptr FatalException) -> Net::awaitable<RelayResult>
    {
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        Record(std::move(Primary));
        RecordException(std::move(FatalException));
        SubmitRetirement();
        co_await DrainRetired();
        if (FatalException_)
        {
            std::rethrow_exception(FatalException_);
        }
        if (Failure_.Failed())
        {
            co_return std::unexpected(Failure_);
        }
        co_return RelayResult{};
    }

    auto EndpointRetirement::Record(Prism::Fault::Failure Value) noexcept -> void
    {
        if (Failure_.Succeeded() && Value.Failed())
        {
            Failure_ = std::move(Value);
        }
    }

    auto EndpointRetirement::RecordException(std::exception_ptr Error) noexcept -> void
    {
        if (!Error)
        {
            return;
        }
        try
        {
            std::rethrow_exception(Error);
        }
        catch (const boost::system::system_error &NativeError)
        {
            Record(Prism::Fault::FromNative(
                static_cast<std::error_code>(NativeError.code())));
        }
        catch (const std::system_error &NativeError)
        {
            Record(Prism::Fault::FromNative(NativeError.code()));
        }
        catch (...)
        {
            if (!FatalException_)
            {
                FatalException_ = std::move(Error);
            }
        }
    }

    auto EndpointRetirement::SubmitRetirement() -> void
    {
        for (const auto &Endpoint : Endpoints_)
        {
            if (!Endpoint)
            {
                continue;
            }
            try
            {
                const auto CancelResult = Endpoint->Cancel();
                if (!CancelResult)
                {
                    Record(CancelResult.error());
                }
            }
            catch (...)
            {
                RecordException(std::current_exception());
            }
            try
            {
                const auto CloseResult = Endpoint->Close();
                if (!CloseResult)
                {
                    Record(CloseResult.error());
                }
            }
            catch (...)
            {
                RecordException(std::current_exception());
            }
        }
    }

    auto EndpointRetirement::DrainRetired() -> Net::awaitable<void>
    {
        for (const auto &Endpoint : Endpoints_)
        {
            if (!Endpoint)
            {
                continue;
            }
            try
            {
                const auto Activity = Endpoint->Activity();
                if (!Activity)
                {
                    Record({Prism::Fault::Code::Blocked});
                    continue;
                }
                const auto DrainResult = co_await Activity->Drain();
                if (!DrainResult)
                {
                    Record(DrainResult.error());
                }
            }
            catch (...)
            {
                RecordException(std::current_exception());
            }
        }
        co_return;
    }
}

namespace Prism::Network::Udp
{
    struct UdpRelay::AssocTable final
    {
        explicit AssocTable(const std::chrono::milliseconds IdleTimeout,
            const std::size_t MaxAssociations)
            : Timeout_(IdleTimeout), MaxAssociations_(MaxAssociations)
        {
        }

        struct Entry final
        {
            Net::ip::udp::endpoint Peer{};
            std::uint64_t LastSeen{0};
        };

        [[nodiscard]] auto PeerOf(const Net::ip::udp::endpoint &SourceEndpoint,
            const bool FromA) const -> std::optional<Net::ip::udp::endpoint>
        {
            const auto &Table = FromA ? AToB_ : BToA_;
            const auto It = Table.find(SourceEndpoint);
            if (It == Table.end() || It->second.Peer == Net::ip::udp::endpoint{})
            {
                return std::nullopt;
            }
            return It->second.Peer;
        }

        auto Touch(const Net::ip::udp::endpoint &SourceEndpoint, const bool FromA) -> void
        {
            auto &Self = FromA ? AToB_ : BToA_;
            auto &Other = FromA ? BToA_ : AToB_;
            const auto Now = NowMs();
            auto It = Self.find(SourceEndpoint);
            if (It == Self.end())
            {
                for (auto EntryIt = Self.begin(); EntryIt != Self.end();)
                {
                    if (EntryIt->second.Peer == Net::ip::udp::endpoint{})
                    {
                        EntryIt = Self.erase(EntryIt);
                    }
                    else
                    {
                        ++EntryIt;
                    }
                }
                It = Self.emplace(SourceEndpoint, Entry{{}, Now}).first;
            }
            else
            {
                It->second.LastSeen = Now;
            }
            if (It->second.Peer != Net::ip::udp::endpoint{})
            {
                return;
            }

            std::optional<Net::ip::udp::endpoint> Best;
            std::uint64_t BestSeen = 0;
            for (auto EntryIt = Other.begin(); EntryIt != Other.end();)
            {
                if (EntryIt->second.Peer != Net::ip::udp::endpoint{})
                {
                    ++EntryIt;
                    continue;
                }
                if (Timeout_.count() > 0 &&
                    Now - EntryIt->second.LastSeen > static_cast<std::uint64_t>(Timeout_.count()))
                {
                    EntryIt = Other.erase(EntryIt);
                    continue;
                }
                if (!Best || EntryIt->second.LastSeen > BestSeen)
                {
                    Best = EntryIt->first;
                    BestSeen = EntryIt->second.LastSeen;
                }
                ++EntryIt;
            }
            if (!Best)
            {
                return;
            }
            if (MaxAssociations_ != 0 && PairedCount_ >= MaxAssociations_)
            {
                Other.erase(*Best);
                Self.erase(It);
                return;
            }
            It->second.Peer = *Best;
            Other[*Best].Peer = SourceEndpoint;
            ++PairedCount_;
        }

        auto Reap() -> std::size_t
        {
            if (Timeout_.count() <= 0)
            {
                return 0;
            }
            const auto Now = NowMs();
            const auto Limit = static_cast<std::uint64_t>(Timeout_.count());
            const auto Idle = [Now, Limit](const std::uint64_t Last)
            {
                return Now - Last > Limit;
            };
            std::size_t Removed = 0;
            for (auto It = AToB_.begin(); It != AToB_.end();)
            {
                auto &Slot = It->second;
                if (Slot.Peer == Net::ip::udp::endpoint{})
                {
                    if (Idle(Slot.LastSeen))
                    {
                        It = AToB_.erase(It);
                        ++Removed;
                    }
                    else
                    {
                        ++It;
                    }
                    continue;
                }
                const auto PeerIt = BToA_.find(Slot.Peer);
                if (PeerIt == BToA_.end() || Idle(std::max(Slot.LastSeen, PeerIt->second.LastSeen)))
                {
                    if (PeerIt != BToA_.end())
                    {
                        BToA_.erase(PeerIt);
                    }
                    It = AToB_.erase(It);
                    if (PairedCount_ > 0)
                    {
                        --PairedCount_;
                    }
                    ++Removed;
                    continue;
                }
                ++It;
            }
            for (auto It = BToA_.begin(); It != BToA_.end();)
            {
                auto &Slot = It->second;
                if (Slot.Peer == Net::ip::udp::endpoint{})
                {
                    if (Idle(Slot.LastSeen))
                    {
                        It = BToA_.erase(It);
                        ++Removed;
                    }
                    else
                    {
                        ++It;
                    }
                    continue;
                }
                const auto PeerIt = AToB_.find(Slot.Peer);
                if (PeerIt == AToB_.end() || Idle(std::max(Slot.LastSeen, PeerIt->second.LastSeen)))
                {
                    if (PeerIt != AToB_.end())
                    {
                        AToB_.erase(PeerIt);
                    }
                    It = BToA_.erase(It);
                    if (PairedCount_ > 0)
                    {
                        --PairedCount_;
                    }
                    ++Removed;
                    continue;
                }
                ++It;
            }
            return Removed;
        }

        [[nodiscard]] static auto NowMs() -> std::uint64_t
        {
            return static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch())
                    .count());
        }

        std::chrono::milliseconds Timeout_{std::chrono::seconds(60)};
        std::size_t MaxAssociations_{256};
        std::size_t PairedCount_{0};
        std::map<Net::ip::udp::endpoint, Entry> AToB_;
        std::map<Net::ip::udp::endpoint, Entry> BToA_;
    };

    struct UdpRelay::RelayDirection final
    {
        std::shared_ptr<Prism::Transport::Unreliable> Source;
        std::shared_ptr<Prism::Transport::Unreliable> Destination;
        std::shared_ptr<AssocTable> Table;
        bool FromIsA{false};
    };

    UdpRelay::UdpRelay(std::shared_ptr<Prism::Transport::Unreliable> EndpointA,
        std::shared_ptr<Prism::Transport::Unreliable> EndpointB, const RelayOptions Options)
        : A_(std::move(EndpointA)), B_(std::move(EndpointB)), Opts_(Options)
    {
    }

    auto UdpRelay::Run() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        return RunOwned(A_, B_, Opts_);
    }

    auto UdpRelay::RunDirections(
        std::shared_ptr<Prism::Transport::Unreliable> EndpointA,
        std::shared_ptr<Prism::Transport::Unreliable> EndpointB,
        std::shared_ptr<AssocTable> Assoc) -> Net::awaitable<RelayResult>
    {
        using Net::experimental::awaitable_operators::operator||;
        auto Outcome = co_await (
            RelayOne(RelayDirection{EndpointA, EndpointB, Assoc, true}) ||
            RelayOne(RelayDirection{EndpointB, EndpointA, std::move(Assoc), false}));
        if (Outcome.index() == 0U)
        {
            co_return std::move(std::get<0>(Outcome));
        }
        co_return std::move(std::get<1>(Outcome));
    }

    auto UdpRelay::RunOwned(
        std::shared_ptr<Prism::Transport::Unreliable> EndpointA,
        std::shared_ptr<Prism::Transport::Unreliable> EndpointB,
        RelayOptions Options) -> Net::awaitable<RelayResult>
    {
        using Net::experimental::awaitable_operators::operator||;
        Detail::EndpointRetirement Retirement(EndpointA, EndpointB);
        Prism::Fault::Failure Primary;
        std::exception_ptr FatalException;
        if (!EndpointA || !EndpointB)
        {
            Primary = {Prism::Fault::Code::InvalidArgument};
        }
        else
        {
            try
            {
                auto Assoc = std::make_shared<AssocTable>(
                    Options.IdleTimeout, Options.MaxAssociations);
                RelayResult RunResult;
                if (Options.IdleTimeout.count() <= 0)
                {
                    RunResult = co_await RunDirections(EndpointA, EndpointB, Assoc);
                }
                else
                {
                    auto Outcome = co_await (
                        RunDirections(EndpointA, EndpointB, Assoc) ||
                        RecycleLoop(Assoc, Options.IdleTimeout));
                    if (Outcome.index() == 0U)
                    {
                        RunResult = std::move(std::get<0>(Outcome));
                    }
                    else
                    {
                        RunResult = std::move(std::get<1>(Outcome));
                    }
                }
                if (!RunResult)
                {
                    Primary = RunResult.error();
                }
            }
            catch (const boost::system::system_error &NativeError)
            {
                Primary = Prism::Fault::FromNative(
                    static_cast<std::error_code>(NativeError.code()));
            }
            catch (const std::system_error &NativeError)
            {
                Primary = Prism::Fault::FromNative(NativeError.code());
            }
            catch (...)
            {
                FatalException = std::current_exception();
            }
        }
        co_return co_await Retirement.Finish(
            std::move(Primary), std::move(FatalException));
    }

    auto UdpRelay::RelayOne(RelayDirection Direction) -> Net::awaitable<RelayResult>
    {
        auto &Source = *Direction.Source;
        auto &Destination = *Direction.Destination;
        auto Table = std::move(Direction.Table);
        const auto FromIsA = Direction.FromIsA;
        auto Buffer = std::make_shared<std::array<std::byte, 65535>>();
        while (true)
        {
            Net::ip::udp::endpoint SourceEndpoint;
            boost::system::error_code ReceiveError;
            const auto Size = co_await Source.NativeSocket().async_receive_from(
                Net::buffer(Buffer->data(), Buffer->size()), SourceEndpoint,
                Net::redirect_error(Net::use_awaitable, ReceiveError));
            if (ReceiveError)
            {
                co_return std::unexpected(Prism::Fault::FromNative(
                    static_cast<std::error_code>(ReceiveError)));
            }
            Table->Touch(SourceEndpoint, FromIsA);
            const auto Peer = Table->PeerOf(SourceEndpoint, FromIsA);
            if (!Peer)
            {
                continue;
            }
            boost::system::error_code WriteError;
            (void)co_await Destination.NativeSocket().async_send_to(
                Net::buffer(Buffer->data(), Size), *Peer,
                Net::redirect_error(Net::use_awaitable, WriteError));
            if (WriteError)
            {
                co_return std::unexpected(Prism::Fault::FromNative(
                    static_cast<std::error_code>(WriteError)));
            }
            Table->Touch(SourceEndpoint, FromIsA);
        }
        co_return RelayResult{};
    }

    auto UdpRelay::RecycleLoop(std::shared_ptr<AssocTable> Table,
        const std::chrono::milliseconds IdleTimeout) -> Net::awaitable<RelayResult>
    {
        while (true)
        {
            Net::steady_timer Timer(co_await Net::this_coro::executor);
            Timer.expires_after(IdleTimeout);
            boost::system::error_code ErrorCode;
            co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode)
            {
                co_return std::unexpected(Prism::Fault::FromNative(
                    static_cast<std::error_code>(ErrorCode)));
            }
            Table->Reap();
        }
        co_return RelayResult{};
    }
} // namespace Prism::Network::Udp
