/** @file Session.hpp @brief AnyTLS 正式根：认证 lease 一次 Run 移交和全部真实 task drain。 */
#pragma once
#include <Preview/Protocols/Anytls/Detail/Session/Relay.hpp>
#include <Preview/Lifecycle/DrainReservation.hpp>
#include <charconv>
#include <system_error>
#include <boost/system/system_error.hpp>

namespace Preview::Anytls::Detail
{
    inline auto PeerVersion(const Frame& Value) noexcept -> std::uint32_t
    {
        const auto Text = std::string_view(reinterpret_cast<const char*>(Value.Payload.data()), Value.Payload.size());
        std::size_t Offset = 0;
        while (Offset < Text.size())
        {
            const auto End = Text.find('\n', Offset);
            auto LineLength = Text.size() - Offset;
            if (End != std::string_view::npos) LineLength = End - Offset;
            const auto Line = Text.substr(Offset, LineLength);
            if (Line.starts_with("v="))
            {
                std::uint32_t Version = 0;
                const auto [Last, ErrorCode] = std::from_chars(Line.data() + 2, Line.data() + Line.size(), Version);
                if (ErrorCode == std::errc{} && Last == Line.data() + Line.size() && Version > 0) return Version;
            }
            if (End == std::string_view::npos) break;
            Offset = End + 1;
        }
        return 1;
    }
    inline auto Alert(std::shared_ptr<State> Root, std::string_view Reason) -> Net::awaitable<void>
    {
        Root->RecordTerminalFailure(
            Preview::Fault::Failure{Preview::Fault::Code::ProtocolError});
        const auto Bytes = std::as_bytes(std::span(Reason));
        const auto Sent = co_await Root->Writer->Send(
            {Command::Alert, 0, std::vector<std::byte>(Bytes.begin(), Bytes.end())});
        if (Sent.Failure.Failed()) Root->RecordTerminalFailure(Sent.Failure);
        Root->Stop();
    }
    inline auto Dispatch(std::shared_ptr<State> Root, Frame Value) -> Net::awaitable<void>
    {
        switch (Value.Kind)
        {
        case Command::Settings:
            if (Root->SettingsReceived || Value.StreamId != 0) { co_await Alert(Root, "InvalidSettings"); break; }
            Root->SettingsReceived = true; Root->PeerVersion = PeerVersion(Value);
            if (Root->PeerVersion >= 2)
            {
                constexpr std::string_view Settings{"v=2\nserver=prism\n"};
                const auto Bytes = std::as_bytes(std::span(Settings));
                const auto Sent = co_await Root->Writer->Send({Command::ServerSettings, 0,
                    std::vector<std::byte>(Bytes.begin(), Bytes.end())});
                if (Sent.Failure.Failed())
                {
                    Root->RecordTerminalFailure(Sent.Failure);
                    Root->Stop();
                }
            }
            break;
        case Command::Syn:
            if (!Root->SettingsReceived || Value.StreamId == 0 || Value.StreamId <= Root->LastStreamId || !Value.Payload.empty())
            { co_await Alert(Root, "InvalidStreamIdOrSettings"); break; }
            Root->LastStreamId = Value.StreamId;
            if (!OpenStream(Root, Value.StreamId)) Root->Stop();
            break;
        case Command::Push:
            if (const auto Found = Root->Streams.find(Value.StreamId); Found != Root->Streams.end())
            {
                if (!Value.Payload.empty() && !Found->second->Data->try_send(boost::system::error_code{}, std::move(Value.Payload)))
                { Found->second->PeerFin = true; Found->second->Cancel(); }
            }
            else if (Value.StreamId == 0 || Value.StreamId > Root->LastStreamId)
                co_await Alert(Root, "UnknownStream");
            break;
        case Command::Fin:
            if (const auto Found = Root->Streams.find(Value.StreamId); Found != Root->Streams.end())
            { Found->second->PeerFin = true; Found->second->Cancel(); }
            break;
        case Command::HeartRequest:
        {
            const auto Sent = co_await Root->Writer->Send({Command::HeartResponse, 0});
            if (Sent.Failure.Failed())
            {
                Root->RecordTerminalFailure(Sent.Failure);
                Root->Stop();
            }
            break;
        }
        case Command::Alert: Root->Stop(); break;
        case Command::Waste: case Command::UpdatePadding: case Command::HeartResponse: break;
        case Command::SynAck: case Command::ServerSettings: co_await Alert(Root, "InvalidClientCommand"); break;
        }
    }
    inline auto RunFrames(std::shared_ptr<State> Root) -> Net::awaitable<void>
    {
        try
        {
            while (!Root->Stopping.load())
            {
                auto Value = co_await ReadFrame(Root->Connection);
                if (!Value) break;
                co_await Dispatch(Root, std::move(*Value));
            }
        }
        catch (const boost::system::system_error &Error)
        {
            const auto Native = static_cast<std::error_code>(Error.code());
            Root->RecordTerminalFailure(Preview::Fault::FromNative(Native));
        }
        catch (const std::system_error &Error)
        {
            Root->RecordTerminalFailure(Preview::Fault::FromNative(Error.code()));
        }
        catch (...)
        {
            Root->RecordTerminalFailure(FailureFromException(std::current_exception()));
        }
        Root->Stop();
    }
    inline auto DrainTaskScope(
        const std::shared_ptr<Preview::Lifecycle::TaskRegistry> &Scope,
        const std::shared_ptr<State> &Root) -> Net::awaitable<bool>
    {
        std::expected<void, Preview::Fault::Failure> Result;
        try { Result = co_await Scope->Drain(); }
        catch (...) { Result = std::unexpected(FailureFromException(std::current_exception())); }
        if (!Result) Root->RecordTerminalFailure(Result.error());
        const auto Stats = Scope->Stats();
        co_return Stats.Active == 0U && !Stats.DrainBlocked;
    }
    inline auto DrainRootResources(std::shared_ptr<State> Root)
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        if (Root->ResourcesRetired.load(std::memory_order_acquire))
        {
            const auto Failure = Root->TerminalFailure.Load();
            if (Failure.Failed()) co_return std::unexpected(Failure);
            co_return std::expected<void, Preview::Fault::Failure>{};
        }
        try
        {
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            co_await Net::dispatch(Root->Executor, Net::use_awaitable);
        }
        catch (...)
        {
            const auto Failure = FailureFromException(std::current_exception());
            Root->RecordTerminalFailure(Failure);
            co_return std::unexpected(Failure);
        }
        Root->StopOnExecutor();
        Root->Lifetime.Seal();
        Root->Loops->Seal();
        Root->Children->Seal();
        Root->Writes->Seal();
        const auto Loops = co_await DrainTaskScope(Root->Loops, Root);
        const auto Children = co_await DrainTaskScope(Root->Children, Root);
        const auto Writes = co_await DrainTaskScope(Root->Writes, Root);
        std::expected<void, Preview::Fault::Failure> ChildDrain;
        try { ChildDrain = co_await Root->DrainChildren(); }
        catch (...)
        {
            ChildDrain = std::unexpected(FailureFromException(std::current_exception()));
            Root->ChildRetirementFailed = true;
        }
        if (!ChildDrain) Root->RecordTerminalFailure(ChildDrain.error());
        std::expected<void, Preview::Fault::Failure> Lifetime;
        try { Lifetime = co_await Root->Lifetime.Drain(); }
        catch (...) { Lifetime = std::unexpected(FailureFromException(std::current_exception())); }
        if (!Lifetime) Root->RecordTerminalFailure(Lifetime.error());
        const bool LifetimeRetired = Root->Lifetime.Active() == 0U && !Root->Lifetime.IsBlocked();
        const auto Carrier = Root->Connection->Activity();
        if (!Carrier)
        {
            const Preview::Fault::Failure Failure{Preview::Fault::Code::Blocked};
            Root->RecordTerminalFailure(Failure);
            co_return std::unexpected(Root->TerminalFailure.Load());
        }
        Carrier->Seal();
        std::expected<void, Preview::Fault::Failure> Inbound;
        try { Inbound = co_await Carrier->Drain(); }
        catch (...) { Inbound = std::unexpected(FailureFromException(std::current_exception())); }
        if (!Inbound) Root->RecordTerminalFailure(Inbound.error());
        const auto CarrierRetired = Carrier->IsRetired();
        if (!CarrierRetired && Inbound)
            Root->RecordTerminalFailure(
                Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        const bool Retired = Loops && Children && Writes && LifetimeRetired && !Root->ChildRetirementFailed &&
            Root->Streams.empty() && CarrierRetired;
        if (!Retired)
        {
            auto Failure = Root->TerminalFailure.Load();
            if (!Failure.Failed()) Failure = {Preview::Fault::Code::Blocked};
            co_return std::unexpected(Failure);
        }
        Root->ReleaseRetired();
        const auto Failure = Root->TerminalFailure.Load();
        if (Failure.Failed()) co_return std::unexpected(Failure);
        co_return std::expected<void, Preview::Fault::Failure>{};
    }
    inline auto RunActive(std::shared_ptr<State> Root, Preview::Contract::MuxRootRequest Request)
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        if (!Root->Lifetime.Enter())
        {
            Root->Stop();
            co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Canceled});
        }
        Preview::Lifecycle::DrainReservation Lifetime(Root->Lifetime);
        Root->Lease = std::move(Request.Lease);
        Root->Admission = Root->Lease.Streams();
        Root->Metadata = std::move(Request.Metadata);
        if (!Request.GenerationUseState ||
            Request.GenerationUseState != Root->GenerationUseState || !Root->GenerationLease)
        {
            Root->RecordTerminalFailure(
                Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            Root->Stop();
        }
        Root->Writer->BindIdentity(Root->Metadata.TaskIdentity);
        if (!Root->Stopping.load())
        {
            Preview::Lifecycle::TaskRequest FrameTask{
                .Context = Preview::Lifecycle::FromParent(Root->Metadata.TaskIdentity),
                .StartOnSubmit = true};
            const auto Weak = std::weak_ptr<State>(Root);
            FrameTask.Cancel = [Weak] { if (const auto Owner = Weak.lock()) Owner->Stop(); };
            const auto Frame = Root->Loops->SpawnTracked(std::move(FrameTask), RunFrames(Root));
            if (!Frame)
            {
                Root->RecordTerminalFailure(Frame.error());
                Root->Stop();
            }
        }
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        const auto Loops = co_await DrainTaskScope(Root->Loops, Root);
        Root->Stop();
        if (!Loops)
        {
            auto Failure = Root->TerminalFailure.Load();
            if (!Failure.Failed()) Failure = {Preview::Fault::Code::Blocked};
            co_return std::unexpected(Failure);
        }
        const auto Failure = Root->TerminalFailure.Load();
        if (Failure.Failed()) co_return std::unexpected(Failure);
        co_return std::expected<void, Preview::Fault::Failure>{};
    }
    class Session final : public Preview::Contract::MuxSession
    {
        class SessionActivity final : public Preview::Contract::CarrierActivity
        {
        public:
            explicit SessionActivity(std::shared_ptr<State> Value) : State_(std::move(Value)) {}

            /** @brief 封止 AnyTLS 的 frame、child 与 writer 三个真实 task scope。 */
            auto Seal() noexcept -> void override
            {
                State_->Lifetime.Seal();
                State_->Loops->Seal();
                State_->Children->Seal();
                State_->Writes->Seal();
            }

            [[nodiscard]] auto Executor() const -> Net::any_io_executor override
            { return State_->Executor; }

            [[nodiscard]] auto IsRetired() const noexcept -> bool override
            { return State_->ResourcesRetired.load(std::memory_order_acquire); }

            /** @brief 依次排空现有 task tree，首个失败保留，其余 scope 仍继续排空。 */
            [[nodiscard]] auto Drain()
                -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
            {
                Seal();
                co_return co_await DrainRootResources(State_);
            }

        private:
            std::shared_ptr<State> State_;
        };

    public:
        /** @brief 只消费预预约 mux create request；分配前 ticket 持 carrier 与账户资源。 */
        [[nodiscard]] static auto Create(
            Preview::Contract::MuxRootCreateRequest &Request,
            Preview::Contract::StreamServices Services)
            -> std::expected<std::shared_ptr<Session>, Preview::Fault::Failure>
        {
            if (!Request.BeginSessionCreation())
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            const auto Inbound = Request.Inbound();
            if (!Inbound || !Request.GenerationUseState())
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            auto Connection = std::static_pointer_cast<Conn<>>(Inbound);
            auto State = std::make_shared<Preview::Anytls::Detail::State>(
                std::move(Connection), std::move(Services), Request.GenerationUseState());
            auto Owner = std::shared_ptr<Session>(new Session(std::move(State)));
            Request.AttachSession(Owner);
            Owner->State_->ParentStreamLease = Request.TakeParentStreamLease();
            Owner->State_->GenerationLease = Request.TakeGenerationUseLease();
            return Owner;
        }

        ~Session() override { Close(); }
        auto Run(Preview::Contract::MuxRootRequest Request)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            const auto Root = State_;
            if (Root->Started.exchange(true))
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            std::expected<void, Preview::Fault::Failure> RunResult;
            try { RunResult = co_await RunActive(Root, std::move(Request)); }
            catch (...) { RunResult = std::unexpected(FailureFromException(std::current_exception())); }
            if (!RunResult) Root->RecordTerminalFailure(RunResult.error());
            const auto Drained = co_await DrainRootResources(Root);
            if (!Drained) Root->RecordTerminalFailure(Drained.error());
            const auto Failure = Root->TerminalFailure.Load();
            if (Failure.Failed()) co_return std::unexpected(Failure);
            if (!Drained) co_return std::unexpected(Drained.error());
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        /** @brief 暴露 AnyTLS 已有 task tree 的唯一协议活动 owner。 */
        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        { return Activity_; }
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        { return State_->ResourcesRetired.load(std::memory_order_acquire); }
        auto Cancel() noexcept -> void override { Activity_->Seal(); State_->Stop(); }
        auto Close() noexcept -> void override { Activity_->Seal(); State_->Stop(); }
    private:
        explicit Session(std::shared_ptr<State> Value)
            : State_(std::move(Value)), Activity_(std::make_shared<SessionActivity>(State_)) {}

        std::shared_ptr<State> State_;
        std::shared_ptr<SessionActivity> Activity_;
    };
}
