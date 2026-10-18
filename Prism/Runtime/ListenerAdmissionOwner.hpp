/**
 * @file ListenerAdmissionOwner.hpp
 * @brief 接管 listener accepted socket、连接配额和 worker executor 的准入事务。
 * @details 事务成功返回 transport、quota 与拒绝 drain 的共同 owner；失败时
 *          accepted socket 由当前或目标 socket owner 关闭，未移交的 quota 立即归还。
 */
#pragma once

#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Net/Tcp/SocketExecutorTransfer.hpp>
#include <Prism/Runtime/AffinityBalancer.hpp>
#include <Prism/Runtime/GenerationPublication.hpp>
#include <Prism/Runtime/ListenerConnectionDrain.hpp>
#include <Prism/Runtime/ListenerConnectionGate.hpp>
#include <Prism/Runtime/WorkerGroup.hpp>
#include <Prism/Transport/Reliable.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace Prism::Runtime::Detail
{
    namespace Net = boost::asio;

    /** @brief 一个被选中 worker 的 owning listener admission 结果。 */
    struct PreparedListenerAdmission final
    {
        Prism::SharedTransmission Transport;
        std::shared_ptr<ListenerConnectionGate::Reservation> ConnectionSlot;
        std::shared_ptr<ListenerConnectionDrain> RejectionDrain;
        std::string Peer;
        Prism::WorkerId Worker{};
        Prism::Foundation::GenerationPin GenerationPin;
    };

    /** @brief 真实 listener 准入事务，拥有 quota 到 transport/drain 的全部冷路径交接。 */
    class ListenerAdmissionOwner final
    {
    public:
        struct Dependencies final
        {
            Net::any_io_executor ListenerExecutor;
            std::shared_ptr<ListenerConnectionGate::Quota> ConnectionQuota;
            AffinityBalancer &Balancer;
            WorkerGroup *Workers{nullptr};
            std::shared_ptr<GenerationPublication> Publication;
            const std::function<void(Prism::Fault::Code)> &OnFailure;
        };

        struct WorkerSelection final
        {
            Net::any_io_executor Executor;
            std::shared_ptr<Prism::Runtime::Worker::AdmissionReceipt> Receipt;
            std::string Peer;
            Prism::WorkerId Worker{};
            Prism::Foundation::GenerationPin GenerationPin;
        };

        [[nodiscard]] static auto Prepare(Net::ip::tcp::socket Socket,
                                          const Dependencies &Input) noexcept
            -> std::optional<PreparedListenerAdmission>
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
                ConnectionSlot =
                    std::make_shared<ListenerConnectionGate::Reservation>(
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

    private:
        [[nodiscard]] static auto SelectWorker(
            const Net::ip::tcp::socket &Socket,
            const Dependencies &Input) -> std::optional<WorkerSelection>
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
            Selection.Worker = Prism::WorkerId{
                static_cast<std::uint64_t>(Index + 1U)};
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
            auto *WorkerValue = Input.Workers->Find(Selection.Worker);
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

        static auto CloseSocket(Net::ip::tcp::socket &Socket) noexcept -> void
        {
            boost::system::error_code Error;
            Socket.close(Error);
        }

        static auto NotifyFailure(
            const std::function<void(Prism::Fault::Code)> &Handler,
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

    };
} // 运行时准入 owner
