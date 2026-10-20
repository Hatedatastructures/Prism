/**
 * @file Ws.cpp
 * @brief WebSocket 工厂实现。
 */
#include <Prism/Protocols/Ws/Ws.hpp>
#include <Prism/Protocols/Ws/Detail/FrameWriteGate.hpp>
#include <Prism/Protocols/Ws/Detail/StreamOwner.hpp>
#include <Prism/Transport/ActivityGroupFactory.hpp>

#include <Prism/Contract/Ingress/InboundAdmission.hpp>

#include <boost/asio/async_result.hpp>
#include <boost/asio/co_composed.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>

#include <atomic>
#include <memory>
#include <span>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace Prism::Ws
{
    namespace
    {
        [[nodiscard]] auto SelectExecutor(const SharedTransmission &Upstream)
            -> Net::any_io_executor
        {
            if (!Upstream)
            {
                return {};
            }
            return Upstream->Executor();
        }
    }

    struct StreamTransport::Impl final
    {
        using Memory = Detail::StreamOwner<>::MemoryType;
        using Session = Detail::ConnSession<Memory>;
        using Transport = Detail::ConnTransport<Memory>;
        using CloseOwner = Detail::ConnClose<Memory>;
        using Frame = Detail::ConnFrame<Memory>;
        using Stream = Detail::ConnStream<Memory>;
        using Handshake = Detail::ConnHandshake<Memory>;

        struct SessionSetup final
        {
            SharedTransmission Upstream;
            std::shared_ptr<Prism::Memory::BytePool> Bytes;
            bool Client{false};
        };

        struct ReadInput final
        {
            std::shared_ptr<StreamTransport> Owner;
            Impl *State;
            std::span<std::byte> Buffer;
        };

        struct WriteInput final
        {
            std::shared_ptr<StreamTransport> Owner;
            Impl *State;
            std::span<const std::byte> Buffer;
        };

        struct ReadWork final
        {
            template <class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner)
                {
                    co_return std::tuple{Prism::IoResult{
                        0, {Prism::Fault::Code::InvalidArgument}}};
                }
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(),
                    Input.State->Stream_.ReadPartial(Input.Buffer),
                    Net::deferred);
                co_return std::tuple{Result};
            }
        };

        struct WriteWork final
        {
            template <class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner)
                {
                    co_return std::tuple{Prism::IoResult{
                        0, {Prism::Fault::Code::InvalidArgument}}};
                }
                std::error_code Error;
                const auto Count = co_await Net::co_spawn(
                    Input.Owner->Executor(),
                    Input.State->Stream_.WritePartial(Input.Buffer, Error),
                    Net::deferred);
                co_return std::tuple{Prism::IoResult{
                    Count, Prism::Fault::FromNative(Error)}};
            }
        };

        Impl(SessionSetup Setup, Prism::Transmission &Owner)
            : Session_(std::move(Setup.Upstream), std::move(Setup.Bytes), Setup.Client),
              Transport_(Session_),
              Close_(Session_, Owner),
              Frame_(Session_, Transport_, Close_),
              Stream_(Session_, Frame_, Close_),
              Handshake_(Session_, Transport_)
        {
        }

        auto AttachActivity(std::shared_ptr<Prism::Contract::CarrierActivity> Parent) -> void
        {
            Activity_ = CreateActivity(std::move(Parent), Session_);
        }

        template <class Work, class Input>
        auto Initiate(Input Value, Prism::Transmission::Completion Handler) -> void
        {
            Net::async_initiate<Prism::Transmission::Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Session_.Executor()),
                Handler,
                std::move(Value));
        }

        [[nodiscard]] static auto CreateActivity(
            std::shared_ptr<Prism::Contract::CarrierActivity> Parent,
            const Session &SessionValue)
            -> std::shared_ptr<Prism::Contract::CarrierActivity>
        {
            std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>> Children;
            if (auto Upstream = SessionValue.Underlying())
            {
                Children.push_back(Upstream->Activity());
            }
            return Prism::Transport::MakeActivityGroup(
                std::move(Parent), std::move(Children));
        }

        auto PrepareHandshake() -> void
        {
            Close_.Reset();
            Frame_.Reset();
            Stream_.Reset();
        }

        Session Session_;
        std::shared_ptr<Prism::Contract::CarrierActivity> Activity_;
        Transport Transport_;
        CloseOwner Close_;
        Frame Frame_;
        Stream Stream_;
        Handshake Handshake_;
    };

    StreamTransport::StreamTransport(
        SharedTransmission Transport,
        std::shared_ptr<Prism::Memory::BytePool> Bytes,
        bool Client)
        : Prism::Transmission(SelectExecutor(Transport))
    {
        Impl_ = std::make_unique<Impl>(
            Impl::SessionSetup{std::move(Transport), std::move(Bytes), Client}, *this);
        Impl_->AttachActivity(Prism::Transmission::Activity());
    }

    StreamTransport::~StreamTransport() = default;

    auto StreamTransport::Executor() const -> Net::any_io_executor
    {
        return Impl_->Session_.Executor();
    }

    auto StreamTransport::Activity() const noexcept
        -> std::shared_ptr<Prism::Contract::CarrierActivity>
    {
        return Impl_->Activity_;
    }

    auto StreamTransport::NextLayer() noexcept -> Prism::Transmission *
    {
        return Impl_->Close_.NextLayer();
    }

    auto StreamTransport::NextLayer() const noexcept -> const Prism::Transmission *
    {
        return Impl_->Close_.NextLayer();
    }

    auto StreamTransport::Release() -> SharedTransmission
    {
        if (!Impl_->Activity_->IsRetired())
        {
            return {};
        }
        return Impl_->Close_.Release();
    }

    auto StreamTransport::WriteHandshake(std::string_view Key, std::string_view Host)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        Impl_->PrepareHandshake();
        return Impl_->Handshake_.WriteHandshake(Key, Host);
    }

    auto StreamTransport::ReadHandshake(
        std::string &Key,
        std::string_view ExpectedPath,
        std::string_view ExpectedHost)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        Impl_->PrepareHandshake();
        return Impl_->Handshake_.ReadHandshake(Key, ExpectedPath, ExpectedHost);
    }

    auto StreamTransport::Accept() const noexcept -> const std::string &
    {
        return Impl_->Handshake_.Accept();
    }

    auto StreamTransport::StartRead(
        std::span<std::byte> Buffer,
        Completion Handler) -> void
    {
        auto Owner = std::static_pointer_cast<StreamTransport>(
            Prism::Transmission::shared_from_this());
        Impl_->Initiate<Impl::ReadWork>(
            Impl::ReadInput{std::move(Owner), Impl_.get(), Buffer}, std::move(Handler));
    }

    auto StreamTransport::StartWrite(
        std::span<const std::byte> Buffer,
        Completion Handler) -> void
    {
        auto Owner = std::static_pointer_cast<StreamTransport>(
            Prism::Transmission::shared_from_this());
        Impl_->Initiate<Impl::WriteWork>(
            Impl::WriteInput{std::move(Owner), Impl_.get(), Buffer}, std::move(Handler));
    }

    auto StreamTransport::StartWriteShutdown(Completion Handler) -> void
    {
        Impl_->Close_.WriteShutdown(std::move(Handler));
    }

    auto StreamTransport::OnClose() -> ControlResult
    {
        return Impl_->Close_.Close();
    }

    auto StreamTransport::OnCancel() -> ControlResult
    {
        return Impl_->Close_.Cancel();
    }
}

namespace Prism::Ws::Detail
{
    FrameWritePermit::State::State(Net::any_io_executor Executor)
        : Available(std::make_shared<Signal>(std::move(Executor), 1))
    {
    }

    FrameWritePermit::FrameWritePermit(std::shared_ptr<State> Owner) noexcept
        : Owner_(std::move(Owner))
    {
    }

    FrameWritePermit::FrameWritePermit(FrameWritePermit &&Other) noexcept
        : Owner_(std::move(Other.Owner_))
    {
    }

    auto FrameWritePermit::operator=(FrameWritePermit &&Other) noexcept -> FrameWritePermit &
    {
        if (this != &Other)
        {
            Release();
            Owner_ = std::move(Other.Owner_);
        }
        return *this;
    }

    FrameWritePermit::~FrameWritePermit() noexcept
    {
        Release();
    }

    auto FrameWritePermit::Release() noexcept -> void
    {
        if (Owner_ && !Owner_->Closed.load(std::memory_order_acquire))
        {
            const auto Released = Owner_->Available->try_send(
                boost::system::error_code{});
            if (!Released)
            {
                Owner_->Closed.store(true, std::memory_order_release);
                Owner_->Available->close();
            }
        }
        Owner_.reset();
    }

    FrameWriteGate::FrameWriteGate(Net::any_io_executor Executor)
        : State_(std::make_shared<State>(std::move(Executor)))
    {
        const auto Ready = State_->Available->try_send(boost::system::error_code{});
        if (!Ready)
        {
            State_->Closed.store(true, std::memory_order_release);
            State_->Available->close();
        }
    }

    auto FrameWriteGate::Acquire()
        -> Net::awaitable<std::expected<FrameWritePermit, Prism::Fault::Failure>>
    {
        const auto Owner = State_;
        if (!Owner || Owner->Closed.load(std::memory_order_acquire))
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }

        boost::system::error_code Error;
        co_await Owner->Available->async_receive(
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            co_return std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(Error)));
        }
        if (Owner->Closed.load(std::memory_order_acquire))
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }
        co_return FrameWritePermit{Owner};
    }

    auto FrameWriteGate::Close() noexcept -> void
    {
        const auto Owner = State_;
        if (Owner && !Owner->Closed.exchange(true, std::memory_order_acq_rel))
        {
            Owner->Available->close();
        }
    }

}

namespace Prism::Ws
{
    auto Connect(ConnectOptions Options)
        -> Net::awaitable<std::expected<ConnectResult, Prism::Fault::Failure>>
    {
        if (!Options.Transport)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::IoError});
        }
        auto TicketResult = co_await Prism::Contract::InboundAdmission::Prepare(Options.Transport);
        if (!TicketResult)
        {
            co_return std::unexpected(TicketResult.error());
        }
        auto Ticket = std::move(*TicketResult);
        if (!Options.Bytes)
        {
            const auto Failure = co_await Ticket.Retire(
                Prism::Fault::Failure{Prism::Fault::Code::IoError});
            co_return std::unexpected(Failure);
        }

        auto Connection = std::shared_ptr<StreamTransport>(new StreamTransport(
            Options.Transport, std::move(Options.Bytes), true));
        const auto Tracked = Ticket.Track(Connection);
        if (!Tracked)
        {
            const auto Failure = co_await Ticket.Retire(Tracked.error());
            co_return std::unexpected(Failure);
        }
        const auto Handshake = co_await Connection->WriteHandshake(
            Options.Client.Key, Options.Client.Host);
        if (!Handshake)
        {
            const auto Failure = co_await Ticket.Retire(Handshake.error());
            co_return std::unexpected(Failure);
        }

        ConnectResult Result;
        Result.Accept = Connection->Accept();
        Result.Connection = std::move(Connection);
        Ticket.Release();
        co_return Result;
    }

    auto Accept(AcceptOptions Options)
        -> Net::awaitable<std::expected<AcceptResult, Prism::Fault::Failure>>
    {
        if (!Options.Transport)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::IoError});
        }
        auto TicketResult = co_await Prism::Contract::InboundAdmission::Prepare(Options.Transport);
        if (!TicketResult)
        {
            co_return std::unexpected(TicketResult.error());
        }
        auto Ticket = std::move(*TicketResult);
        if (!Options.Bytes)
        {
            const auto Failure = co_await Ticket.Retire(
                Prism::Fault::Failure{Prism::Fault::Code::IoError});
            co_return std::unexpected(Failure);
        }

        auto Connection = std::shared_ptr<StreamTransport>(new StreamTransport(
            Options.Transport, std::move(Options.Bytes), false));
        const auto Tracked = Ticket.Track(Connection);
        if (!Tracked)
        {
            const auto Failure = co_await Ticket.Retire(Tracked.error());
            co_return std::unexpected(Failure);
        }
        AcceptResult Result;
        const auto Handshake = co_await Connection->ReadHandshake(
            Result.Key, Options.Server.Path, Options.Server.Host);
        if (!Handshake)
        {
            const auto Failure = co_await Ticket.Retire(Handshake.error());
            co_return std::unexpected(Failure);
        }
        Result.Connection = std::move(Connection);
        Ticket.Release();
        co_return Result;
    }
}
