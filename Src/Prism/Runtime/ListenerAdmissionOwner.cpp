/** @file ListenerAdmissionOwner.cpp @brief 已接受套接字的监听准入事务实现。 */
#include <Prism/Runtime/ListenerAdmissionOwner.hpp>

#include <boost/system/error_code.hpp>

#include <memory>
#include <optional>
#include <utility>

namespace Prism::Runtime::Detail
{
    auto ListenerAdmissionOwner::Prepare(
        Net::ip::tcp::socket Socket,
        const Dependencies& Input) noexcept -> std::optional<PreparedListenerAdmission>
    {
        std::shared_ptr<Prism::Executor::ClosingStorage> AdmissionStorage;
        try
        {
            AdmissionStorage = Prism::Executor::ClosingStorage::ProcessStorage();
        }
        catch (...)
        {
            CloseSocket(Socket);
            NotifyFailure(Input.OnFailure, Prism::Fault::Code::ResourceUnavailable);
            return {};
        }

        std::optional<WorkerSelection> Selection;
        try
        {
            Selection = SelectWorker(Socket, Input);
        }
        catch (...)
        {
            CloseSocket(Socket);
            NotifyFailure(Input.OnFailure, Prism::Fault::Code::ResourceUnavailable);
            return {};
        }
        if (!Selection)
        {
            CloseSocket(Socket);
            return {};
        }

        if (!ListenerConnectionGate::TryAcquire(Input.ConnectionQuota))
        {
            CloseSocket(Socket);
            return {};
        }

        ListenerConnectionGate::Reservation AcquiredSlot(
            Input.ConnectionQuota, std::move(AdmissionStorage),
            std::move(Selection->Receipt));
        std::shared_ptr<ListenerConnectionGate::Reservation> ConnectionSlot;
        try
        {
            ConnectionSlot = std::make_shared<ListenerConnectionGate::Reservation>(
                std::move(AcquiredSlot));
        }
        catch (...)
        {
            CloseSocket(Socket);
            NotifyFailure(Input.OnFailure, Prism::Fault::Code::ResourceUnavailable);
            return {};
        }

        std::shared_ptr<ListenerConnectionDrain> RejectionDrain;
        Prism::SharedTransmission Transport;
        try
        {
            auto Transferred = Prism::Network::Tcp::MoveAcceptedSocket(
                std::move(Socket), std::move(Selection->Executor));
            if (!Transferred)
            {
                NotifyFailure(Input.OnFailure, Transferred.error().Code);
                return {};
            }

            Transport = Prism::Transport::MakeReliable(std::move(*Transferred));
            if (!Transport)
            {
                NotifyFailure(Input.OnFailure, Prism::Fault::Code::ResourceUnavailable);
                return {};
            }

            ConnectionSlot->AdoptTransport(Transport);
            ConnectionSlot->RetainOnDrop();
            RejectionDrain = ListenerConnectionDrain::Make(
                {Transport, ConnectionSlot, {}, {}});

            return PreparedListenerAdmission{
                std::move(Transport), std::move(ConnectionSlot),
                std::move(RejectionDrain), std::move(Selection->Peer),
                Selection->Worker, std::move(Selection->GenerationPin)};
        }
        catch (...)
        {
            if (RejectionDrain)
            {
                ConnectionSlot->ReleaseTransport();
                RejectionDrain->Start();
            }
            else if (Transport)
            {
                ConnectionSlot->AdoptTransport(Transport);
                ConnectionSlot->RetainOnDrop();
                ConnectionSlot->RequestRetirement();
            }
            else
            {
                CloseSocket(Socket);
                ConnectionSlot->Release();
            }
            NotifyFailure(Input.OnFailure, Prism::Fault::Code::ResourceUnavailable);
            return {};
        }
    }

    auto ListenerAdmissionOwner::SelectWorker(
        const Net::ip::tcp::socket& Socket,
        const Dependencies& Input) -> std::optional<WorkerSelection>
    {
        WorkerSelection Selection;
        Selection.Peer = "unknown";
        boost::system::error_code EndpointError;
        const auto Remote = Socket.remote_endpoint(EndpointError);
        if (!EndpointError)
        {
            Selection.Peer = Remote.address().to_string();
        }
        const auto Index = Input.Balancer.Select(Selection.Peer);
        Selection.Worker = Prism::WorkerId{static_cast<std::uint64_t>(Index + 1U)};
        Selection.Executor = Input.ListenerExecutor;
        if (!Input.Publication)
        {
            return {};
        }
        Selection.GenerationPin = Input.Publication->Current();
        if (!Selection.GenerationPin || !Selection.GenerationPin->Id())
        {
            return {};
        }
        if (!Input.Workers)
        {
            return Selection;
        }
        auto* WorkerValue = Input.Workers->Find(Selection.Worker);
        if (!WorkerValue)
        {
            return {};
        }
        Selection.Receipt = WorkerValue->TryReserveAdmission(Selection.GenerationPin->Id());
        if (!Selection.Receipt || Selection.Receipt->Id() != Selection.Worker ||
            Selection.Receipt->Generation() != Selection.GenerationPin->Id())
        {
            return {};
        }
        Selection.Executor = WorkerValue->Executor();
        return Selection;
    }

    auto ListenerAdmissionOwner::CloseSocket(Net::ip::tcp::socket& Socket) noexcept -> void
    {
        boost::system::error_code Error;
        Socket.close(Error);
    }

    auto ListenerAdmissionOwner::NotifyFailure(
        const std::function<void(Prism::Fault::Code)>& Handler,
        const Prism::Fault::Code Code) noexcept -> void
    {
        if (!Handler)
        {
            return;
        }
        try
        {
            Handler(Code);
        }
        catch (...)
        {
        }
    }
}
