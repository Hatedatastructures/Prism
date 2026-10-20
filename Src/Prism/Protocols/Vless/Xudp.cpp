/** @file Xudp.cpp @brief VLESS XUDP 生命周期与数据面状态机实现。 */
#include <Prism/Protocols/Vless/Xudp/State.hpp>
#include <Prism/Protocols/Vless/Xudp/Association.hpp>
#include <Prism/Protocols/Vless/Xudp/RootSession.hpp>
#include <Prism/Protocols/Vless/Xudp/VlessXudp.hpp>
#include <Prism/Protocols/Vless/Xudp/Writer.hpp>

#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Vless::Xudp
{

    [[nodiscard]] auto TaskScopePhysicallyRetired(
        const Prism::Lifecycle::TaskStats& Stats) noexcept -> bool
    {
        return Stats.Active == 0U && !Stats.DrainBlocked;
    }

    [[nodiscard]] auto TaskScopePhysicallyRetired(
        const std::shared_ptr<Prism::Lifecycle::TaskRegistry>& Scope) noexcept -> bool
    {
        return Scope && TaskScopePhysicallyRetired(Scope->Stats());
    }

    auto RunFailureState::Record(Prism::Fault::Failure Failure) noexcept -> void
    {
        if (First.Succeeded())
        {
            First = std::move(Failure);
        }
    }

    auto MakeRunFailureHandler(const std::shared_ptr<RunFailureState> &State)
        -> Prism::Lifecycle::TaskRegistry::FailureHandler
    {
        return [State](const Prism::Lifecycle::TaskIdentity &, Prism::Fault::Failure Failure)
        { State->Record(std::move(Failure)); };
    }

    struct Writer::Entry final
    {
        Entry(Net::any_io_executor Executor, WritePacket PacketValue)
            : Value(std::move(PacketValue)), Completion(Executor, 1)
        {
        }

        WritePacket Value;
        Net::experimental::channel<void(boost::system::error_code, WriteResult)> Completion;
        std::size_t WireBytes{0};
        bool Completed{false};
    };

    Writer::Writer(
        Prism::SharedTransmission Inbound,
        std::shared_ptr<Prism::Lifecycle::TaskRegistry> Tasks,
        std::shared_ptr<RunFailureState> Failure)
        : Inbound_(std::move(Inbound)), Tasks_(std::move(Tasks)), Failure_(std::move(Failure))
    {
    }

    auto Writer::BindIdentity(Prism::Lifecycle::TaskIdentity Identity) -> void
    {
        Identity_ = Identity;
    }

    auto Writer::Send(WritePacket Packet) -> Net::awaitable<WriteResult>
    {
        co_await Net::dispatch(Tasks_->Executor(), Net::use_awaitable);
        if (Closed_)
        {
            co_return WriteResult{0, 0, {Prism::Fault::Code::Canceled}};
        }
        if (Packet.Wire.empty() || Packet.PayloadSize > Packet.Wire.size())
        {
            co_return WriteResult{0, 0, {Prism::Fault::Code::InvalidArgument}};
        }
        const auto EntryValue = std::make_shared<Entry>(Tasks_->Executor(), std::move(Packet));
        Queue_.push_back(EntryValue);
        if (!Running_)
        {
            Running_ = true;
            Prism::Lifecycle::TaskRequest Request{
                .Context = Prism::Lifecycle::FromParent(Identity_),
                .StartOnSubmit = true};
            const auto Weak = weak_from_this();
            Request.Cancel = [Weak]
            {
                if (const auto Owner = Weak.lock())
                {
                    Owner->Close();
                }
            };
            if (!Tasks_->SpawnTracked(std::move(Request), Pump(shared_from_this())))
            {
                Close();
            }
        }
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        co_return co_await EntryValue->Completion.async_receive(Net::use_awaitable);
    }

    auto Writer::Close() noexcept -> void
    {
        if (Closed_)
        {
            return;
        }
        Closed_ = true;
        while (!Queue_.empty())
        {
            Complete(Queue_.front(), WriteResult{0, 0, {Prism::Fault::Code::Canceled}});
            Queue_.pop_front();
        }
        try
        {
            const auto Canceled = Inbound_->Cancel();
            if (!Canceled) Failure_->Record(Canceled.error());
            const auto Closed = Inbound_->Close();
            if (!Closed) Failure_->Record(Closed.error());
        }
        catch (const boost::system::system_error &Error)
        {
            Failure_->Record(Prism::Fault::FromNative(
                static_cast<std::error_code>(Error.code())));
        }
        catch (const std::system_error &Error)
        {
            Failure_->Record(Prism::Fault::FromNative(Error.code()));
        }
        catch (...)
        {
            Failure_->Record(Prism::Fault::Failure{Prism::Fault::Code::IoError});
        }
    }

    auto Writer::Complete(const std::shared_ptr<Entry> &Item, WriteResult Result) noexcept -> void
    {
        if (Item->Completed)
        {
            return;
        }
        Item->Completed = true;
        (void)Item->Completion.try_send(boost::system::error_code{}, Result);
    }

    auto Writer::Pump(std::shared_ptr<Writer> Owner) -> Net::awaitable<void>
    {
        try
        {
            while (!Owner->Closed_ && !Owner->Queue_.empty())
            {
                auto Item = Owner->Queue_.front();
                Owner->Queue_.pop_front();
                Owner->Active_ = Item;
                Prism::Fault::Failure Failure;
                while (Item->WireBytes < Item->Value.Wire.size() && !Owner->Closed_)
                {
                    const auto Part = co_await Owner->Inbound_->WriteSome(
                        std::span(Item->Value.Wire).subspan(Item->WireBytes));
                    const auto Count = Part.Bytes;
                    if (Count > Item->Value.Wire.size() - Item->WireBytes)
                    {
                        Failure = {Prism::Fault::Code::InvalidArgument, Part.Failure.Native};
                        break;
                    }
                    Item->WireBytes += Count;
                    if (Part.Failure.Failed())
                    {
                        Failure = Part.Failure;
                        break;
                    }
                    if (Count == 0U)
                    {
                        Failure = {Prism::Fault::Code::WouldBlock};
                        break;
                    }
                }
                if (Owner->Closed_ && !Failure.Failed())
                {
                    Failure = {Prism::Fault::Code::Canceled};
                }
                const bool Success = !Failure.Failed() &&
                    Item->WireBytes == Item->Value.Wire.size();
                if (!Success && !Failure.Failed())
                {
                    Failure = {Prism::Fault::Code::IoError};
                }
                const auto PayloadBytes = Success ? Item->Value.PayloadSize : 0U;
                Complete(Item, {PayloadBytes, Item->WireBytes, Failure});
                Owner->Active_.reset();
                if (!Success)
                {
                    Owner->Failure_->Record(Failure);
                    Owner->Close();
                }
            }
        }
        catch (const boost::system::system_error &Error)
        {
            const auto Failure = Prism::Fault::FromNative(
                static_cast<std::error_code>(Error.code()));
            Owner->Failure_->Record(Failure);
            if (Owner->Active_)
            {
                const auto Item = Owner->Active_;
                Complete(Item, {0, Item->WireBytes, Failure});
            }
            Owner->Active_.reset();
            Owner->Close();
        }
        catch (const std::system_error &Error)
        {
            const auto Failure = Prism::Fault::FromNative(Error.code());
            Owner->Failure_->Record(Failure);
            if (Owner->Active_)
            {
                Complete(Owner->Active_, {0, Owner->Active_->WireBytes, Failure});
            }
            Owner->Active_.reset();
            Owner->Close();
        }
        catch (...)
        {
            const Prism::Fault::Failure Failure{Prism::Fault::Code::IoError};
            Owner->Failure_->Record(Failure);
            if (Owner->Active_)
            {
                Complete(Owner->Active_, {0, Owner->Active_->WireBytes, Failure});
            }
            Owner->Active_.reset();
            Owner->Close();
        }
        Owner->Running_ = false;
    }

    FrameCompletion::FrameCompletion(std::shared_ptr<State> Root)
        : Root_(std::move(Root))
    {
    }

    FrameCompletion::~FrameCompletion()
    {
        (void)Root_->FrameFinished.try_send(boost::system::error_code{});
    }

    Association::Association(Net::any_io_executor Ex, std::shared_ptr<Prism::Lifecycle::TaskRegistry> Scope)
        : Socket(Ex), Incoming(Ex, 32), Ready(Ex, 1), Deadline(Ex), Tasks(std::move(Scope))
    {}

    auto Association::Cancel() noexcept -> void
    {
        const bool First = !Closed.exchange(true);
        if (First)
        {
            Cancellation.emit(Net::cancellation_type::all);
            Incoming.close(); Ready.close(); Deadline.cancel();
        }
        boost::system::error_code Error;
        Socket.cancel(Error); Socket.close(Error);
        (void)Tasks->Cancel();
    }

    State::State(Prism::SharedTransmission Value, Prism::Protocols::DatagramBinding Binding,
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState)
        : Inbound(std::move(Value)), Services(std::move(Binding.Services)), Observation(std::move(Binding.Observation)),
          Executor(Net::make_strand(Inbound->Executor())),
          FrameFinished(Executor, 1),
          DrainChanged(Executor),
          Failure(std::make_shared<RunFailureState>()),
          Loops(std::make_shared<Prism::Lifecycle::TaskRegistry>(
              Executor, MakeRunFailureHandler(Failure))),
          Children(std::make_shared<Prism::Lifecycle::TaskRegistry>(
              Executor, MakeRunFailureHandler(Failure))),
          Writes(std::make_shared<Prism::Lifecycle::TaskRegistry>(
              Executor, MakeRunFailureHandler(Failure))),
          Lifetime(Loops->Reclaimer()),
          RequiredGenerationUseState(std::move(UseState)),
          Output(std::make_shared<Writer>(Inbound, Writes, Failure))
    {}

    auto State::Stop() noexcept -> void
    {
        if (Stopping.exchange(true)) return;
        const auto Self = shared_from_this();
        Net::dispatch(Executor, [Self] { Self->StopOnExecutor(); });
    }

    auto State::Cancel() noexcept -> void
    {
        Cancelled.store(true, std::memory_order_release);
        Stop();
    }

    auto State::RecordFailure(Prism::Fault::Failure Value) noexcept -> void
    {
        Failure->Record(std::move(Value));
    }

    [[nodiscard]] auto State::PhysicalRetirementReady() const noexcept -> bool
    {
        return TaskScopePhysicallyRetired(Children) &&
            TaskScopePhysicallyRetired(Loops) &&
            TaskScopePhysicallyRetired(Writes) &&
            Lifetime.Active() == 0U && !Lifetime.IsBlocked() &&
            Associations.empty() && !RetiringAssociations &&
            CarrierRetired.load(std::memory_order_acquire);
    }

    [[nodiscard]] auto State::ReleaseResources() -> Net::awaitable<bool>
    {
        co_await Net::dispatch(Executor, Net::use_awaitable);
        if (ResourcesReleased.load(std::memory_order_acquire)) co_return true;
        if (!PhysicalRetirementReady()) co_return false;
        Output.reset();
        Inbound.reset();
        Services = {};
        Observation = {};
        Metadata = {};
        Admission = {};
        Lease.Release();
        GenerationLease = {};
        RequiredGenerationUseState.reset();
        ResourcesReleased.store(true, std::memory_order_release);
        co_return true;
    }

    auto State::StopOnExecutor() noexcept -> void
    {
        Stopping.store(true);
        if (Output) Output->Close();
        CancelAssociationsOnExecutor();
        (void)Loops->Cancel(); (void)Children->Cancel(); (void)Writes->Cancel();
    }

    auto State::CancelAssociationsOnExecutor() noexcept -> void
    {
        for (const auto& [Id, Value] : Associations) { (void)Id; Value->Cancel(); }
        for (auto Value = RetiringAssociations; Value; Value = Value->RetiringNext)
            Value->Cancel();
    }

    [[nodiscard]] auto MakeTrafficObservation(
        const std::shared_ptr<State> &Root,
        const std::shared_ptr<Association> &Value) -> Prism::Foundation::TrafficObservation
    {
        return {Root->Services.Traffic,
            Prism::Foundation::TrafficEvent{
                .Generation = Root->Metadata.TaskIdentity.Generation,
                .Worker = Root->Metadata.TaskIdentity.WorkerId,
                .Session = Root->Metadata.TaskIdentity.SessionId,
                .Stream = Value->Identity.StreamId,
                .Task = Value->Identity.TaskId,
                .Account = Root->Observation.AccountId}};
    }

    [[nodiscard]] auto AssociationPhysicallyRetired(
        const std::shared_ptr<Association>& Value) noexcept -> bool
    {
        return Value->Closed.load(std::memory_order_acquire) && !Value->Socket.is_open() &&
            TaskScopePhysicallyRetired(Value->Tasks);
    }

    auto FinishAssociation(
        const std::shared_ptr<State>& Root,
        const std::shared_ptr<Association>& Value) -> void
    {
        if (Value->CompletionReported) return;
        Value->CompletionReported = true;
        auto Observation = Root->Observation;
        Observation.Request.TaskIdentity = Value->Identity;
        Observation.Finish({.Datagrams = Value->Datagrams, .UpBytes = Value->Up, .DownBytes = Value->Down});
        MakeTrafficObservation(Root, Value).Complete();
        Value->Lease.Release();
    }

    auto UnlinkRetiringAssociation(
        const std::shared_ptr<State>& Root,
        const std::shared_ptr<Association>& Value) -> void
    {
        auto* Link = &Root->RetiringAssociations;
        while (*Link)
        {
            if (*Link == Value)
            {
                auto Next = Value->RetiringNext;
                Value->RetiringNext.reset();
                *Link = std::move(Next);
                return;
            }
            Link = &((*Link)->RetiringNext);
        }
    }

    auto DrainAssociation(const std::shared_ptr<State>& Root,
        const std::shared_ptr<Association>& Value) -> Net::awaitable<bool>
    {
        Value->Cancel();
        const auto Drained = co_await Value->Tasks->Drain();
        if (!Drained) Root->RecordFailure(Drained.error());
        if (!AssociationPhysicallyRetired(Value))
        {
            Root->RecordFailure({Prism::Fault::Code::Blocked});
            co_return false;
        }
        co_return true;
    }

    auto RetireAssociationOwners(const std::shared_ptr<State>& Root)
        -> Net::awaitable<bool>
    {
        auto Active = Root->Associations.begin();
        while (Active != Root->Associations.end())
        {
            const auto Value = Active->second;
            if (!(co_await DrainAssociation(Root, Value)))
            {
                ++Active;
                continue;
            }
            FinishAssociation(Root, Value);
            Active = Root->Associations.erase(Active);
        }
        auto* Retiring = &Root->RetiringAssociations;
        while (*Retiring)
        {
            const auto Value = *Retiring;
            if (!(co_await DrainAssociation(Root, Value)))
            {
                Retiring = &Value->RetiringNext;
                continue;
            }
            FinishAssociation(Root, Value);
            auto Next = Value->RetiringNext;
            Value->RetiringNext.reset();
            *Retiring = std::move(Next);
        }
        co_return Root->Associations.empty() && !Root->RetiringAssociations;
    }

    auto Touch(const std::shared_ptr<State>& Root, const std::shared_ptr<Association>& Value) -> void
    {
        Value->Activity=std::chrono::steady_clock::now();
        if(Root->Services.IdleTimeout.count()>0) Value->Deadline.expires_at(Value->Activity+Root->Services.IdleTimeout);
    }

    auto OpenSocket(const std::shared_ptr<State>& Root,
        const std::shared_ptr<Association>& Value, Net::ip::udp::endpoint Target) -> bool
    {
        boost::system::error_code Error;
        if (Value->Socket.is_open())
        {
            const auto Local = Value->Socket.local_endpoint(Error);
            if (Error)
            {
                Root->RecordFailure(Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error)));
                return false;
            }
            if (Local.protocol() != Target.protocol())
            {
                ++Value->SocketEpoch;
                Value->Socket.close(Error);
                if (Error)
                {
                    Root->RecordFailure(Prism::Fault::FromNative(
                        static_cast<std::error_code>(Error)));
                    return false;
                }
            }
        }
        if(Value->Socket.is_open()) return true;
        Value->Socket.open(Target.protocol(),Error);
        if (Error)
        {
            Root->RecordFailure(Prism::Fault::FromNative(
                static_cast<std::error_code>(Error)));
            return false;
        }
        Value->Socket.bind(Net::ip::udp::endpoint(Target.protocol(),0),Error);
        if (Error)
        {
            Root->RecordFailure(Prism::Fault::FromNative(
                static_cast<std::error_code>(Error)));
            Error.clear();
            Value->Socket.close(Error);
            if (Error)
            {
                Root->RecordFailure(Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error)));
            }
            return false;
        }
        ++Value->SocketEpoch;
        (void)Value->Ready.try_send(boost::system::error_code{});
        return true;
    }

    auto Send(std::shared_ptr<State> Root, std::shared_ptr<Association> Value, Frame Packet)
        -> Net::awaitable<Prism::Fault::Code>
    {
        if(Packet.HasTarget){Value->Target=std::move(Packet.Target);Value->HasTarget=true;}
        if (!Value->HasTarget)
        {
            Root->RecordFailure({Prism::Fault::Code::ProtocolError});
            co_return Prism::Fault::Code::ProtocolError;
        }
        const auto Resolved=co_await Prism::Protocols::ResolveDatagram(Root->Services,Value->Target);
        if(!Resolved)
        {
            Root->RecordFailure(Resolved.error());
            co_return Resolved.error().Code;
        }
        const auto Target=*Resolved;
        if (Value->Closed.load()) co_return Prism::Fault::Code::Canceled;
        if (!OpenSocket(Root, Value, Target))
            co_return Prism::Fault::Code::IoError;
        Value->ExpectedSource = Target;
        boost::system::error_code IoError;
        const auto Sent=co_await Value->Socket.async_send_to(Net::buffer(Packet.Payload),Target,
            Net::redirect_error(Net::use_awaitable,IoError));
        Value->Up+=Sent;++Value->Datagrams;
        MakeTrafficObservation(Root, Value).Transfer(
            Sent, Prism::Foundation::TrafficObservation::Direction::Upload);
        if (IoError)
        {
            if (!Value->Closed.load() && !Root->Stopping.load())
            {
                Root->RecordFailure(Prism::Fault::FromNative(
                    static_cast<std::error_code>(IoError)));
            }
            co_return Prism::Fault::ToCode(static_cast<std::error_code>(IoError));
        }
        Touch(Root,Value);co_return Prism::Fault::Code::Success;
    }

    auto Work(std::shared_ptr<State> Root, std::shared_ptr<Association> Value) -> Net::awaitable<void>
    {
        while (!Value->Closed.load() && !Root->Stopping.load())
        {
            boost::system::error_code Error;
            auto Packet = co_await Value->Incoming.async_receive(
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                if (!Value->Closed.load() && !Root->Stopping.load())
                    Root->RecordFailure(Prism::Fault::FromNative(
                        static_cast<std::error_code>(Error)));
                break;
            }
            const Prism::Protocols::DatagramDeadline Deadline{
                Root->Executor, Root->Services.IdleTimeout};
            const auto Status = co_await Prism::Protocols::AwaitDatagramDeadline(
                Send(Root, Value, std::move(Packet)), Deadline);
            if (Status != Prism::Fault::Code::Success)
            {
                if (Status != Prism::Fault::Code::Canceled ||
                    (!Value->Closed.load() && !Root->Stopping.load()))
                {
                    Root->RecordFailure(Prism::Fault::Failure{Status});
                }
                break;
            }
        }
        Value->Cancel();
    }

    auto Receive(std::shared_ptr<State> Root, std::shared_ptr<Association> Value) -> Net::awaitable<void>
    {
        while (!Value->Closed.load() && !Root->Stopping.load())
        {
            if (!Value->Socket.is_open())
            {
                boost::system::error_code ReadyError;
                co_await Value->Ready.async_receive(
                    Net::redirect_error(Net::use_awaitable, ReadyError));
                if (ReadyError || Value->Closed.load())
                {
                    if (ReadyError && !Value->Closed.load() && !Root->Stopping.load())
                        Root->RecordFailure(Prism::Fault::FromNative(
                            static_cast<std::error_code>(ReadyError)));
                    break;
                }
            }
            const auto Epoch = Value->SocketEpoch;
            std::array<std::uint8_t, MaxDatagram> Response{};
            Net::ip::udp::endpoint Source;
            boost::system::error_code Error;
            const auto Count = co_await Value->Socket.async_receive_from(
                Net::buffer(Response), Source,
                Net::redirect_error(Net::use_awaitable, Error));
            if (Epoch != Value->SocketEpoch) continue;
            if (Error)
            {
                if (!Value->Closed.load() && !Root->Stopping.load())
                    Root->RecordFailure(Prism::Fault::FromNative(
                        static_cast<std::error_code>(Error)));
                break;
            }
            if (!Value->ExpectedSource || Source != *Value->ExpectedSource)
            {
                continue;
            }
            Touch(Root, Value);
            std::vector<std::uint8_t> Payload(
                Response.begin(), Response.begin() + static_cast<std::ptrdiff_t>(Count));
            const auto Result = co_await Root->Output->Send(
                {EncodeReply({Value->Id, Source, std::move(Payload)}), Count});
            if (Result.Failure.Failed())
            {
                Root->RecordFailure(Result.Failure);
                break;
            }
            if (Result.PayloadBytes != Count)
            {
                Root->RecordFailure({Prism::Fault::Code::InvalidArgument});
                break;
            }
            Value->Down += Result.PayloadBytes;
            MakeTrafficObservation(Root, Value).Transfer(
                Result.PayloadBytes, Prism::Foundation::TrafficObservation::Direction::Download);
            Touch(Root, Value);
        }
        Value->Cancel();
    }

    auto Idle(std::shared_ptr<State> Root, std::shared_ptr<Association> Value) -> Net::awaitable<void>
    {
        while(!Value->Closed.load())
        {
            if(Root->Services.IdleTimeout.count()>0) Value->Deadline.expires_at(Value->Activity+Root->Services.IdleTimeout);
            else Value->Deadline.expires_after(std::chrono::hours(24));
            boost::system::error_code Error;
            co_await Value->Deadline.async_wait(Net::redirect_error(Net::use_awaitable,Error));
            if(!Error&&Root->Services.IdleTimeout.count()>0){Value->Cancel();break;}
        }
    }

    auto RunWorker(std::shared_ptr<State> Root, std::shared_ptr<Association> Value) -> Net::awaitable<void>
    {
        co_await Net::co_spawn(Root->Executor,Work(Root,Value),
            Net::bind_cancellation_slot(Value->Cancellation.slot(),Net::use_awaitable));
    }

    auto RunAssociation(std::shared_ptr<State> Root, std::shared_ptr<Association> Value) -> Net::awaitable<void>
    {
        Prism::Lifecycle::TaskRequest Request{.Context = Prism::Lifecycle::FromParent(Value->Identity), .StartOnSubmit = true};
        const auto Weak = std::weak_ptr<Association>(Value);
        Request.Cancel = [Weak] { if (const auto Owner = Weak.lock()) Owner->Cancel(); };
        if (!Value->Tasks->SpawnTracked(Request, RunWorker(Root, Value)) ||
            !Value->Tasks->SpawnTracked(Request, Receive(Root, Value)) ||
            !Value->Tasks->SpawnTracked(std::move(Request), Idle(Root, Value))) Value->Cancel();
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        const auto Drained = co_await Value->Tasks->Drain();
        if (!Drained) Root->RecordFailure(Drained.error());
        Value->Cancel();
        if (!AssociationPhysicallyRetired(Value))
        {
            Root->RecordFailure({Prism::Fault::Code::Blocked});
            co_return;
        }
        FinishAssociation(Root, Value);
        const auto Found = Root->Associations.find(Value->Id);
        if (Found != Root->Associations.end() && Found->second == Value) Root->Associations.erase(Found);
        UnlinkRetiringAssociation(Root, Value);
    }

    auto RejectAssociation(std::shared_ptr<State> Root, std::uint16_t Id) -> Net::awaitable<void>
    {
        const auto Result = co_await Root->Output->Send({EncodeEnd(Id)});
        if (Result.Failure.Failed()) Root->RecordFailure(Result.Failure);
    }

    auto StartAssociation(std::shared_ptr<State> Root, Frame Packet) -> bool
    {
        auto Identity = Root->Metadata.TaskIdentity;
        Identity.StreamId = Prism::StreamId{Packet.SessionId};
        Prism::Account::StreamLease Lease;
        Prism::Lifecycle::TaskRequest Request{.Context = Prism::Lifecycle::FromParent(Identity), .StartOnSubmit = true};
        if (Root->Admission)
        {
            auto Acquired = Root->Admission.Acquire();
            if (!Acquired)
                return bool(Root->Children->SpawnTracked(std::move(Request), RejectAssociation(Root, Packet.SessionId)));
            Lease = std::move(*Acquired);
        }
        auto Value = std::make_shared<Association>(
            Root->Executor, Root->Children->CreateChild(MakeRunFailureHandler(Root->Failure)));
        Value->Id = Packet.SessionId; Value->Lease = std::move(Lease);
        const auto Weak = std::weak_ptr<Association>(Value);
        Request.Cancel = [Weak] { if (const auto Owner = Weak.lock()) Owner->Cancel(); };
        const auto Task = Root->Children->SpawnTracked(std::move(Request), RunAssociation(Root, Value));
        if (!Task) { Value->Cancel(); return false; }
        Value->Identity = Task->Identity();
        (void)Value->Incoming.try_send(boost::system::error_code{}, std::move(Packet));
        Root->Associations.emplace(Value->Id, std::move(Value));
        return true;
    }

    auto PreserveRunFailure(State& Root, Prism::Fault::Failure Failure) -> void
    {
        Root.RecordFailure(std::move(Failure));
    }

    [[nodiscard]] auto CurrentRunResult(const State& Root) -> RunResult
    {
        if (Root.Failure->First.Failed())
        {
            return std::unexpected(Root.Failure->First);
        }
        return {};
    }

    auto RunFrames(std::shared_ptr<State> Root) -> Net::awaitable<void>
    {
        FrameCompletion Completion(Root);
        while (!Root->Stopping.load())
        {
            auto Packet = co_await ReadFrame(Root->Inbound);
            if (!Packet)
            {
                const auto Failure = Packet.error();
                if (Failure.Code != Prism::Fault::Code::Eof || Failure.Native)
                    PreserveRunFailure(*Root, Failure);
                break;
            }
            const auto Found = Root->Associations.find(Packet->SessionId);
            if (Packet->StatusValue == Status::End)
            {
                if (Found != Root->Associations.end())
                {
                    const auto Retiring = Found->second;
                    Retiring->Cancel();
                    Retiring->RetiringNext = std::move(Root->RetiringAssociations);
                    Root->RetiringAssociations = Retiring;
                    Root->Associations.erase(Found);
                }
                continue;
            }
            if (Packet->StatusValue == Status::KeepAlive) continue;
            if (Found == Root->Associations.end())
            {
                if (Packet->StatusValue != Status::New || !Packet->HasTarget)
                {
                    Prism::Lifecycle::TaskRequest Request{
                        .Context = Prism::Lifecycle::FromParent(Root->Metadata.TaskIdentity),
                        .StartOnSubmit = true};
                    Request.Context.StreamId = Prism::StreamId{Packet->SessionId};
                    (void)Root->Children->SpawnTracked(
                        std::move(Request), RejectAssociation(Root, Packet->SessionId));
                    continue;
                }
                if (!StartAssociation(Root, std::move(*Packet))) break;
            }
            else if (!Found->second->Incoming.try_send(
                         boost::system::error_code{}, std::move(*Packet)))
            {
                Found->second->Cancel();
            }
        }
        Root->Stop();
    }

    auto DrainOwnedResources(const std::shared_ptr<State>& Root) -> Net::awaitable<void>
    {
        Root->CancelAssociationsOnExecutor();
        const auto Children = co_await Root->Children->Drain();
        if (!Children) PreserveRunFailure(*Root, Children.error());
        const auto Loops = co_await Root->Loops->Drain();
        if (!Loops) PreserveRunFailure(*Root, Loops.error());
        const auto Writes = co_await Root->Writes->Drain();
        if (!Writes) PreserveRunFailure(*Root, Writes.error());
        if (TaskScopePhysicallyRetired(Root->Children) &&
            TaskScopePhysicallyRetired(Root->Loops))
        {
            const bool Associations = co_await RetireAssociationOwners(Root);
            if (!Associations) PreserveRunFailure(*Root, {Prism::Fault::Code::Blocked});
        }
        else PreserveRunFailure(*Root, {Prism::Fault::Code::Blocked});

        const auto InboundActivity = Root->Inbound ? Root->Inbound->Activity() : nullptr;
        if (!InboundActivity)
        {
            PreserveRunFailure(*Root, {Prism::Fault::Code::Blocked});
            co_return;
        }
        const auto Carrier = co_await InboundActivity->Drain();
        if (!Carrier) PreserveRunFailure(*Root, Carrier.error());
        const bool CarrierRetired = InboundActivity->IsRetired();
        Root->CarrierRetired.store(CarrierRetired, std::memory_order_release);
        if (!CarrierRetired)
        {
            PreserveRunFailure(*Root, {Prism::Fault::Code::Blocked});
        }
    }

    auto WaitForDrainCompletion(const std::shared_ptr<State>& Root) -> Net::awaitable<void>
    {
        boost::system::error_code Error;
        co_await Root->DrainChanged.async_wait(
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error && Error != Net::error::operation_aborted)
        {
            PreserveRunFailure(*Root,
                Prism::Fault::FromNative(static_cast<std::error_code>(Error)));
        }
    }

    auto SignalDrainCompletion(State& Root) noexcept -> void
    {
        Root.DrainInProgress = false;
        try
        {
            (void)Root.DrainChanged.cancel();
        }
        catch (const boost::system::system_error& Error)
        {
            PreserveRunFailure(Root, Prism::Fault::FromNative(
                static_cast<std::error_code>(Error.code())));
        }
    }

    auto DrainActivityResources(const std::shared_ptr<State>& Root)
        -> Net::awaitable<RunResult>
    {
        const auto Lifetime = co_await Root->Lifetime.Drain();
        if (!Lifetime) PreserveRunFailure(*Root, Lifetime.error());
        if (Root->Lifetime.Active() != 0U)
        {
            PreserveRunFailure(*Root, {Prism::Fault::Code::Blocked});
            co_return CurrentRunResult(*Root);
        }
        if (!Root->ResourcesReleased.load(std::memory_order_acquire))
        {
            if (!Root->PhysicalRetirementReady()) co_await DrainOwnedResources(Root);
            co_return co_await FinishPhysicalRetirement(Root);
        }
        co_return CurrentRunResult(*Root);
    }

    [[nodiscard]] auto FinishPhysicalRetirement(const std::shared_ptr<State>& Root)
        -> Net::awaitable<RunResult>
    {
        if (Root->Cancelled.load(std::memory_order_acquire) && Root->Failure->First.Succeeded())
        {
            PreserveRunFailure(*Root, {Prism::Fault::Code::Canceled});
        }
        if (!Root->PhysicalRetirementReady())
        {
            PreserveRunFailure(*Root, {Prism::Fault::Code::Blocked});
        }
        else
        {
            const bool Released = co_await Root->ReleaseResources();
            if (!Released) PreserveRunFailure(*Root, {Prism::Fault::Code::Blocked});
        }
        co_return CurrentRunResult(*Root);
    }

    auto DrainRunResources(
        const std::shared_ptr<State>& Root,
        Prism::Lifecycle::DrainReservation Reservation) -> Net::awaitable<RunResult>
    {
        co_await DrainOwnedResources(Root);
        if (Root->DrainInProgress)
        {
            Reservation.Transfer();
            Root->Lifetime.Leave();
            const auto Lifetime = co_await Root->Lifetime.Drain();
            if (!Lifetime) PreserveRunFailure(*Root, Lifetime.error());
            co_await WaitForDrainCompletion(Root);
            co_return CurrentRunResult(*Root);
        }
        Root->DrainInProgress = true;
        Root->DrainChanged.expires_at(std::chrono::steady_clock::time_point::max());
        Reservation.Transfer();
        Root->Lifetime.Leave();
        const auto Lifetime = co_await Root->Lifetime.Drain();
        if (!Lifetime) PreserveRunFailure(*Root, Lifetime.error());
        const auto Result = co_await FinishPhysicalRetirement(Root);
        SignalDrainCompletion(*Root);
        co_return Result;
    }

    RootSession::SessionActivity::SessionActivity(std::shared_ptr<State> Value) : State_(std::move(Value))
    {}

    auto RootSession::SessionActivity::Seal() noexcept -> void
    {
        State_->Lifetime.Seal();
        State_->Loops->Seal();
        State_->Children->Seal();
        State_->Writes->Seal();
    }

    [[nodiscard]] auto RootSession::SessionActivity::Executor() const -> Net::any_io_executor
    {
        return State_->Executor;
    }

    [[nodiscard]] auto RootSession::SessionActivity::IsRetired() const noexcept -> bool
    {
        return State_->ResourcesReleased.load(std::memory_order_acquire) &&
            State_->CarrierRetired.load(std::memory_order_acquire) &&
            State_->Lifetime.Active() == 0U && !State_->Lifetime.IsBlocked() &&
            TaskScopePhysicallyRetired(State_->Children) &&
            TaskScopePhysicallyRetired(State_->Loops) &&
            TaskScopePhysicallyRetired(State_->Writes);
    }

    [[nodiscard]] auto RootSession::SessionActivity::Drain() -> Net::awaitable<RunResult>
    {
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        Seal();
        State_->Stop();
        co_await Net::dispatch(State_->Executor, Net::use_awaitable);
        if (State_->DrainInProgress)
        {
            co_await WaitForDrainCompletion(State_);
            co_return CurrentRunResult(*State_);
        }
        State_->DrainInProgress = true;
        State_->DrainChanged.expires_at(std::chrono::steady_clock::time_point::max());
        const auto Result = co_await DrainActivityResources(State_);
        SignalDrainCompletion(*State_);
        co_return Result;
    }

    RootSession::RootSession(Prism::SharedTransmission Inbound,
                Prism::Protocols::DatagramBinding Binding,
                std::shared_ptr<Prism::Foundation::GenerationUseState> UseState)
        : State_(std::make_shared<State>(std::move(Inbound), std::move(Binding),
              std::move(UseState))),
          Activity_(std::make_shared<SessionActivity>(State_))
    {
    }

    [[nodiscard]] auto RootSession::Run(Prism::Contract::MuxRootRequest Request)
        -> Net::awaitable<RunResult>
    {
        const auto Root = State_;
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        co_await Net::dispatch(Root->Executor, Net::use_awaitable);
        if (Root->Started.exchange(true))
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (Root->ResourcesReleased.load(std::memory_order_acquire))
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }
        if (!Request.GenerationUseState ||
            Request.GenerationUseState != Root->RequiredGenerationUseState)
        {
            co_return co_await FailAndDrain(
                {Prism::Fault::Code::InvalidArgument});
        }
        auto Generation = Root->RequiredGenerationUseState->Acquire();
        if (!Generation) co_return co_await FailAndDrain(Generation.error());
        Root->GenerationLease = std::move(*Generation);
        if (!Root->Lifetime.Enter())
        {
            co_return co_await FailAndDrain({Prism::Fault::Code::Canceled});
        }
        Prism::Lifecycle::DrainReservation Lifetime(Root->Lifetime);
        Root->Lease = std::move(Request.Lease);
        Root->Admission = Root->Lease.Streams();
        Root->Metadata = std::move(Request.Metadata);
        Root->Output->BindIdentity(Root->Metadata.TaskIdentity);

        Prism::Lifecycle::TaskRequest Loop{
            .Context = Prism::Lifecycle::FromParent(Root->Metadata.TaskIdentity),
            .StartOnSubmit = true};
        const auto Weak = std::weak_ptr<State>(Root);
        Loop.Cancel = [Weak]
        {
            if (const auto Owner = Weak.lock()) Owner->Stop();
        };
        bool FrameStarted = false;
        if (!Root->Stopping.load())
        {
            const auto Frame = Root->Loops->SpawnTracked(
                std::move(Loop), RunFrames(Root));
            if (!Frame)
            {
                PreserveRunFailure(*Root, Frame.error());
                Root->Stop();
            }
            else
            {
                FrameStarted = true;
            }
        }

        if (FrameStarted)
        {
            boost::system::error_code CompletionError;
            co_await Root->FrameFinished.async_receive(
                Net::redirect_error(Net::use_awaitable, CompletionError));
            if (CompletionError)
            {
                PreserveRunFailure(*Root, Prism::Fault::FromNative(
                    static_cast<std::error_code>(CompletionError)));
            }
        }
        Root->Stop();
        co_return co_await DrainRunResources(Root, std::move(Lifetime));
    }

    [[nodiscard]] auto RootSession::Activity() const
        -> std::shared_ptr<Prism::Contract::CarrierActivity>
    {
        return Activity_;
    }

    [[nodiscard]] auto RootSession::IsRetired() const noexcept -> bool
    {
        return Activity_->IsRetired();
    }

    auto RootSession::Cancel() noexcept -> void
    {
        Activity_->Seal();
        State_->Cancel();
    }

    auto RootSession::Close() noexcept -> void
    {
        Activity_->Seal();
        State_->Stop();
    }

    [[nodiscard]] auto RootSession::FailAndDrain(Prism::Fault::Failure Failure)
        -> Net::awaitable<RunResult>
    {
        PreserveRunFailure(*State_, std::move(Failure));
        State_->Stop();
        const auto Drain = co_await Activity_->Drain();
        if (!Drain) PreserveRunFailure(*State_, Drain.error());
        co_return CurrentRunResult(*State_);
    }

    RootSession::~RootSession()
    { Close(); }


    [[nodiscard]] auto ReadAddress(std::span<const std::uint8_t> Data) -> std::optional<Address>
    {
        Address Result;
        Result.Target.Route = Prism::Network::RouteKind::Forward;
        std::size_t Offset=0;
        auto& Host=Result.Target.Host;
        auto& Port=Result.Target.Port;
        if (Data.size() - Offset < 2U)
        {
            return std::nullopt;
        }
        Port = static_cast<std::uint16_t>(Data[Offset] << 8U | Data[Offset + 1U]);
        Offset += 2U;
        if (Offset >= Data.size())
        {
            return std::nullopt;
        }
        const auto Family = Data[Offset++];
        if (Family == FamilyIpv4)
        {
            if (Data.size() - Offset < 4U)
            {
                return std::nullopt;
            }
            Prism::Network::Ipv4Bytes Bytes;
            std::copy_n(Data.begin() + static_cast<std::ptrdiff_t>(Offset), 4U, Bytes.Bytes.begin());
            Host = Prism::Network::Host(Bytes);
            Offset += 4U;
            Result.Consumed = Offset; return Result;
        }
        if (Family == FamilyFqdn)
        {
            if (Offset >= Data.size())
            {
                return std::nullopt;
            }
            const auto Length = static_cast<std::size_t>(Data[Offset++]);
            if (Data.size() - Offset < Length)
            {
                return std::nullopt;
            }
            auto Domain = Prism::Network::DecodeHost(Prism::Network::HostEncoding::Domain,
                {reinterpret_cast<const char *>(Data.data() + Offset), Length});
            if (!Domain) return std::nullopt;
            Host = std::move(*Domain);
            Offset += Length;
            Result.Consumed = Offset; return Result;
        }
        if (Family == FamilyIpv6)
        {
            if (Data.size() - Offset < 16U)
            {
                return std::nullopt;
            }
            Net::ip::address_v6::bytes_type Bytes{};
            std::copy_n(Data.begin() + static_cast<std::ptrdiff_t>(Offset), 16U, Bytes.begin());
            Host = Prism::Network::Host(Prism::Network::Ipv6Bytes{Bytes});
            Offset += 16U;
            Result.Consumed = Offset; return Result;
        }
        return std::nullopt;

    }

    [[nodiscard]] auto ReadFrame(Prism::SharedTransmission Inbound)
        -> Net::awaitable<std::expected<Frame, Prism::Fault::Failure>>
    {
        if (!Inbound)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        std::array<std::uint8_t, 6> Prefix{};
        const auto PrefixRead = co_await Inbound->ReadExact(
            std::as_writable_bytes(std::span<std::uint8_t>(Prefix)));
        if (PrefixRead.Failure.Failed())
        {
            auto Failure = PrefixRead.Failure;
            if (Failure.Code == Prism::Fault::Code::Eof && PrefixRead.Bytes > 0U)
                Failure.Code = Prism::Fault::Code::BadMessage;
            co_return std::unexpected(std::move(Failure));
        }
        if (PrefixRead.Bytes != Prefix.size())
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }
        const auto Length = static_cast<std::size_t>(Prefix[0] << 8U | Prefix[1]);
        Frame Result;
        Result.SessionId = static_cast<std::uint16_t>(Prefix[2] << 8U | Prefix[3]);
        Result.StatusValue = static_cast<Status>(Prefix[4]);
        const auto Option = Prefix[5];
        if (Result.StatusValue == Status::End)
        {
            co_return Result;
        }
        if (Result.StatusValue != Status::New && Result.StatusValue != Status::Keep &&
            Result.StatusValue != Status::KeepAlive)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }
        if (Length < 4U)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }
        if (Length > 4U)
        {
            std::vector<std::uint8_t> Body(Length - 4U);
            const auto BodyRead = co_await Inbound->ReadExact(
                std::as_writable_bytes(std::span<std::uint8_t>(Body)));
            if (BodyRead.Failure.Failed())
            {
                auto Failure = BodyRead.Failure;
                if (Failure.Code == Prism::Fault::Code::Eof && BodyRead.Bytes > 0U)
                    Failure.Code = Prism::Fault::Code::BadMessage;
                co_return std::unexpected(std::move(Failure));
            }
            if (BodyRead.Bytes != Body.size() || Body.empty())
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            }
            if (Body[0] != NetworkUdp)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            }
            auto Target = ReadAddress(std::span<const std::uint8_t>(Body).subspan(1));
            if (!Target)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            }
            Result.Target = std::move(Target->Target);
            Result.HasTarget = true;
        }
        if ((Option & OptionError) != 0U)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ProtocolError});
        }
        if ((Option & OptionData) == 0U)
        {
            co_return Result;
        }
        std::array<std::uint8_t, 2> PayloadLengthWire{};
        const auto LengthRead = co_await Inbound->ReadExact(
            std::as_writable_bytes(std::span<std::uint8_t>(PayloadLengthWire)));
        if (LengthRead.Failure.Failed())
        {
            auto Failure = LengthRead.Failure;
            if (Failure.Code == Prism::Fault::Code::Eof && LengthRead.Bytes > 0U)
                Failure.Code = Prism::Fault::Code::BadMessage;
            co_return std::unexpected(std::move(Failure));
        }
        if (LengthRead.Bytes != PayloadLengthWire.size())
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }
        const auto PayloadLength = static_cast<std::size_t>(
            PayloadLengthWire[0] << 8U | PayloadLengthWire[1]);
        Result.Payload.resize(PayloadLength);
        const auto PayloadRead = co_await Inbound->ReadExact(
            std::as_writable_bytes(std::span<std::uint8_t>(Result.Payload)));
        if (PayloadRead.Failure.Failed())
        {
            auto Failure = PayloadRead.Failure;
            if (Failure.Code == Prism::Fault::Code::Eof && PayloadRead.Bytes > 0U)
                Failure.Code = Prism::Fault::Code::BadMessage;
            co_return std::unexpected(std::move(Failure));
        }
        if (PayloadRead.Bytes != Result.Payload.size())
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }
        co_return Result;
    }

    [[nodiscard]] auto EncodeReply(Reply Value) -> std::vector<std::byte>
    {
        if (Value.Payload.size() > MaxDatagram) return {};
        const auto V4 = Value.Source.address().is_v4();
        const auto Length = static_cast<std::uint16_t>(V4 ? 12 : 24);
        std::vector<std::byte> Wire{std::byte{static_cast<std::uint8_t>(Length >> 8)},
            std::byte{static_cast<std::uint8_t>(Length)},
            std::byte{static_cast<std::uint8_t>(Value.SessionId >> 8)},
            std::byte{static_cast<std::uint8_t>(Value.SessionId)},std::byte{2},std::byte{1},std::byte{2},
            std::byte{static_cast<std::uint8_t>(Value.Source.port() >> 8)},
            std::byte{static_cast<std::uint8_t>(Value.Source.port())},std::byte{static_cast<std::uint8_t>(V4 ? 1 : 3)}};
        const auto Add = [&Wire](auto Address)
        { for (const auto Byte : Address.to_bytes()) Wire.push_back(std::byte{Byte}); };
        if (V4) Add(Value.Source.address().to_v4()); else Add(Value.Source.address().to_v6());
        Wire.push_back(std::byte{static_cast<std::uint8_t>(Value.Payload.size() >> 8)});
        Wire.push_back(std::byte{static_cast<std::uint8_t>(Value.Payload.size())});
        for (const auto Byte : Value.Payload) Wire.push_back(std::byte{Byte});
        return Wire;
    }

    [[nodiscard]] auto EncodeEnd(std::uint16_t Id) -> std::vector<std::byte>
    {
        return {std::byte{0},std::byte{4},std::byte{static_cast<std::uint8_t>(Id >> 8)},
            std::byte{static_cast<std::uint8_t>(Id)},std::byte{3},std::byte{OptionError}};
    }

} // namespace Prism::Vless::Xudp
