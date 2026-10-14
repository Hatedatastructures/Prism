/** @file Association.hpp @brief 每 id 独立的 DNS/send/receive 全阶段期限和真实 drain。 */
#pragma once
#include <Preview/Protocols/Vless/Xudp/State.hpp>
#include <Preview/Protocols/Common/DatagramDeadline.hpp>
#include <Preview/Foundation/Utility/TrafficSink.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/co_spawn.hpp>

namespace Preview::Vless::Xudp
{
    [[nodiscard]] inline auto MakeTrafficObservation(
        const std::shared_ptr<State> &Root,
        const std::shared_ptr<Association> &Value) -> Preview::Foundation::TrafficObservation
    {
        return {Root->Services.Traffic,
            Preview::Foundation::TrafficEvent{
                .Generation = Root->Metadata.TaskIdentity.Generation,
                .Worker = Root->Metadata.TaskIdentity.WorkerId,
                .Session = Root->Metadata.TaskIdentity.SessionId,
                .Stream = Value->Identity.StreamId,
                .Task = Value->Identity.TaskId,
                .Account = Root->Observation.AccountId}};
    }

    [[nodiscard]] inline auto AssociationPhysicallyRetired(
        const std::shared_ptr<Association>& Value) noexcept -> bool
    {
        return Value->Closed.load(std::memory_order_acquire) && !Value->Socket.is_open() &&
            TaskScopePhysicallyRetired(Value->Tasks);
    }

    inline auto FinishAssociation(
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

    inline auto UnlinkRetiringAssociation(
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

    inline auto DrainAssociation(const std::shared_ptr<State>& Root,
        const std::shared_ptr<Association>& Value) -> Net::awaitable<bool>
    {
        Value->Cancel();
        const auto Drained = co_await Value->Tasks->Drain();
        if (!Drained) Root->RecordFailure(Drained.error());
        if (!AssociationPhysicallyRetired(Value))
        {
            Root->RecordFailure({Preview::Fault::Code::Blocked});
            co_return false;
        }
        co_return true;
    }

    /** @brief 重试 active 与 End 后关联；只在 socket/子任务真实退休后释放 lease。 */
    inline auto RetireAssociationOwners(const std::shared_ptr<State>& Root)
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

    /** @brief 当前 association executor 更新真实活动期限；计时 owner 只关闭本 id。 */
    inline auto Touch(const std::shared_ptr<State>& Root, const std::shared_ptr<Association>& Value) -> void
    {
        Value->Activity=std::chrono::steady_clock::now();
        if(Root->Services.IdleTimeout.count()>0) Value->Deadline.expires_at(Value->Activity+Root->Services.IdleTimeout);
    }
    inline auto OpenSocket(const std::shared_ptr<State>& Root,
        const std::shared_ptr<Association>& Value, Net::ip::udp::endpoint Target) -> bool
    {
        boost::system::error_code Error;
        if (Value->Socket.is_open())
        {
            const auto Local = Value->Socket.local_endpoint(Error);
            if (Error)
            {
                Root->RecordFailure(Preview::Fault::FromNative(
                    static_cast<std::error_code>(Error)));
                return false;
            }
            if (Local.protocol() != Target.protocol())
            {
                ++Value->SocketEpoch;
                Value->Socket.close(Error);
                if (Error)
                {
                    Root->RecordFailure(Preview::Fault::FromNative(
                        static_cast<std::error_code>(Error)));
                    return false;
                }
            }
        }
        if(Value->Socket.is_open()) return true;
        Value->Socket.open(Target.protocol(),Error);
        if (Error)
        {
            Root->RecordFailure(Preview::Fault::FromNative(
                static_cast<std::error_code>(Error)));
            return false;
        }
        Value->Socket.bind(Net::ip::udp::endpoint(Target.protocol(),0),Error);
        if (Error)
        {
            Root->RecordFailure(Preview::Fault::FromNative(
                static_cast<std::error_code>(Error)));
            Error.clear();
            Value->Socket.close(Error);
            if (Error)
            {
                Root->RecordFailure(Preview::Fault::FromNative(
                    static_cast<std::error_code>(Error)));
            }
            return false;
        }
        ++Value->SocketEpoch;
        (void)Value->Ready.try_send(boost::system::error_code{});
        return true;
    }
    /** @brief 一次发送拥有 Packet，DNS/send 全阶段期限由 sender await；回包由独立 receiver。 */
    inline auto Send(std::shared_ptr<State> Root, std::shared_ptr<Association> Value, Frame Packet)
        -> Net::awaitable<Preview::Fault::Code>
    {
        if(Packet.HasTarget){Value->Target=std::move(Packet.Target);Value->HasTarget=true;}
        if (!Value->HasTarget)
        {
            Root->RecordFailure({Preview::Fault::Code::ProtocolError});
            co_return Preview::Fault::Code::ProtocolError;
        }
        const auto Resolved=co_await Preview::Protocols::ResolveDatagram(Root->Services,Value->Target);
        if(!Resolved)
        {
            Root->RecordFailure(Resolved.error());
            co_return Resolved.error().Code;
        }
        const auto Target=*Resolved;
        if (Value->Closed.load()) co_return Preview::Fault::Code::Canceled;
        if (!OpenSocket(Root, Value, Target))
            co_return Preview::Fault::Code::IoError;
        Value->ExpectedSource = Target;
        boost::system::error_code IoError;
        const auto Sent=co_await Value->Socket.async_send_to(Net::buffer(Packet.Payload),Target,
            Net::redirect_error(Net::use_awaitable,IoError));
        Value->Up+=Sent;++Value->Datagrams;
        MakeTrafficObservation(Root, Value).Transfer(
            Sent, Preview::Foundation::TrafficObservation::Direction::Upload);
        if (IoError)
        {
            if (!Value->Closed.load() && !Root->Stopping.load())
            {
                Root->RecordFailure(Preview::Fault::FromNative(
                    static_cast<std::error_code>(IoError)));
            }
            co_return Preview::Fault::ToCode(static_cast<std::error_code>(IoError));
        }
        Touch(Root,Value);co_return Preview::Fault::Code::Success;
    }
    inline auto Work(std::shared_ptr<State> Root, std::shared_ptr<Association> Value) -> Net::awaitable<void>
    {
        while (!Value->Closed.load() && !Root->Stopping.load())
        {
            boost::system::error_code Error;
            auto Packet = co_await Value->Incoming.async_receive(
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                if (!Value->Closed.load() && !Root->Stopping.load())
                    Root->RecordFailure(Preview::Fault::FromNative(
                        static_cast<std::error_code>(Error)));
                break;
            }
            const Preview::Protocols::DatagramDeadline Deadline{
                Root->Executor, Root->Services.IdleTimeout};
            const auto Status = co_await Preview::Protocols::AwaitDatagramDeadline(
                Send(Root, Value, std::move(Packet)), Deadline);
            if (Status != Preview::Fault::Code::Success)
            {
                if (Status != Preview::Fault::Code::Canceled ||
                    (!Value->Closed.load() && !Root->Stopping.load()))
                {
                    Root->RecordFailure({Status});
                }
                break;
            }
        }
        Value->Cancel();
    }
    /** @brief 持私有 socket 连续接收全部回包；地址族切换的旧 receive 先退栈再进入新 epoch。 */
    inline auto Receive(std::shared_ptr<State> Root, std::shared_ptr<Association> Value) -> Net::awaitable<void>
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
                        Root->RecordFailure(Preview::Fault::FromNative(
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
                    Root->RecordFailure(Preview::Fault::FromNative(
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
                Root->RecordFailure({Preview::Fault::Code::InvalidArgument});
                break;
            }
            Value->Down += Result.PayloadBytes;
            MakeTrafficObservation(Root, Value).Transfer(
                Result.PayloadBytes, Preview::Foundation::TrafficObservation::Direction::Download);
            Touch(Root, Value);
        }
        Value->Cancel();
    }
    /** @brief 独立 idle owner；真实 DNS、发送、收包或 writer 挂起都会被本 id 的 deadline 取消并 join。 */
    inline auto Idle(std::shared_ptr<State> Root, std::shared_ptr<Association> Value) -> Net::awaitable<void>
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
    inline auto RunWorker(std::shared_ptr<State> Root, std::shared_ptr<Association> Value) -> Net::awaitable<void>
    {
        co_await Net::co_spawn(Root->Executor,Work(Root,Value),
            Net::bind_cancellation_slot(Value->Cancellation.slot(),Net::use_awaitable));
    }
    /** @brief 外部 owning task 等 association 自己的 scope，scope 内没有等待自身的 runner。 */
    inline auto RunAssociation(std::shared_ptr<State> Root, std::shared_ptr<Association> Value) -> Net::awaitable<void>
    {
        Preview::Lifecycle::TaskRequest Request{.Context = Preview::Lifecycle::FromParent(Value->Identity), .StartOnSubmit = true};
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
            Root->RecordFailure({Preview::Fault::Code::Blocked});
            co_return;
        }
        FinishAssociation(Root, Value);
        const auto Found = Root->Associations.find(Value->Id);
        if (Found != Root->Associations.end() && Found->second == Value) Root->Associations.erase(Found);
        UnlinkRetiringAssociation(Root, Value);
    }
    inline auto RejectAssociation(std::shared_ptr<State> Root, std::uint16_t Id) -> Net::awaitable<void>
    {
        const auto Result = co_await Root->Output->Send({EncodeEnd(Id)});
        if (Result.Failure.Failed()) Root->RecordFailure(Result.Failure);
    }
    inline auto StartAssociation(std::shared_ptr<State> Root, Frame Packet) -> bool
    {
        auto Identity = Root->Metadata.TaskIdentity; 
        Identity.StreamId = Preview::StreamId{Packet.SessionId};
        Preview::Account::StreamLease Lease;
        Preview::Lifecycle::TaskRequest Request{.Context = Preview::Lifecycle::FromParent(Identity), .StartOnSubmit = true};
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
}
