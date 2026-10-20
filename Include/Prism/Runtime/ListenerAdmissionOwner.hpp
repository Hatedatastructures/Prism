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
#include <Prism/Runtime/GenerationPublication.hpp>
#include <Prism/Runtime/ListenerConnectionDrain.hpp>
#include <Prism/Runtime/ListenerConnectionGate.hpp>
#include <Prism/Runtime/WorkerGroup.hpp>
#include <Prism/Transport/Reliable.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace Prism::Runtime
{
    /**
     * @class AffinityBalancer
     * @brief 亲和性分发器。
     * @details FNV-1a 哈希远端标识，同一标识稳定映射到同一 worker。
     */
    class AffinityBalancer
    {
    public:
        explicit AffinityBalancer(std::size_t WorkerCount);
        [[nodiscard]] auto Select(std::string_view Key) const noexcept -> std::size_t;
        [[nodiscard]] auto WorkerCount() const noexcept -> std::size_t;

    private:
        std::size_t WorkerCount_{1};
    };
}

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
            -> std::optional<PreparedListenerAdmission>;

    private:
        [[nodiscard]] static auto SelectWorker(
            const Net::ip::tcp::socket &Socket,
            const Dependencies &Input) -> std::optional<WorkerSelection>;

        static auto CloseSocket(Net::ip::tcp::socket &Socket) noexcept -> void;

        static auto NotifyFailure(
            const std::function<void(Prism::Fault::Code)> &Handler,
            const Prism::Fault::Code Code) noexcept -> void;

    };
} // 运行时准入 owner
