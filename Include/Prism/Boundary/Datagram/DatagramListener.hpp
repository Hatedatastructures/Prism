/**
 * @file DatagramListener.hpp
 * @brief Prism 唯一 UDP socket 的接收、停止和排空生命周期。
 * @details 该 listener 只拥有 socket 和 packet pump，不知道协议 handler、
 *          Worker session map 或 DNS。所有数据以 owner-held BoundaryPacket 交给
 *          BoundaryDispatcher，QUIC 与普通 UDP 不创建第二个 socket。
 */
#pragma once

#include <Prism/Boundary/Datagram/DatagramClassifier.hpp>
#include <Prism/Contract/Services/DatagramEgress.hpp>
#include <Prism/Contract/Services/Quic.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/system/error_code.hpp>

#include <cstdint>
#include <functional>
#include <memory>

namespace Prism::Boundary
{

    namespace Net = boost::asio;

    /** @brief 借用 Boundary UDP socket 的回包端口，不拥有 socket 关闭权。 */
    class DatagramSender final : public Prism::Contract::DatagramSender
    {
    public:
        explicit DatagramSender(std::shared_ptr<Net::ip::udp::socket> Socket);

        /** @brief 接管数据报到发送完成；底层 socket 由弱引用临时 pin，取消向发送操作传递。 */
        [[nodiscard]] auto Send(Prism::Contract::DatagramPacket Packet)
            -> Net::awaitable<boost::system::error_code> override;

    private:
        [[nodiscard]] static auto SendOnExecutor(
            std::shared_ptr<Net::ip::udp::socket> Socket,
            Prism::Contract::DatagramPacket Packet)
            -> Net::awaitable<boost::system::error_code>;

        std::weak_ptr<Net::ip::udp::socket> Socket_;
    };

    /** @brief 只用于 UDP 入口：对端 ICMP 拒绝/重置不停止共享 packet pump；取消与坏 socket 仍终止。 */
    [[nodiscard]] auto IsRecoverableReceiveError(
        const boost::system::error_code Error) noexcept -> bool;

    enum class DatagramStartCode : std::uint8_t
    {
        Success,
        Invalid,
        AlreadyStarted,
        BindFailed,
        Closed,
    };

    struct DatagramStartResult final
    {
        DatagramStartCode Code{DatagramStartCode::Invalid};
        boost::system::error_code Error;

        [[nodiscard]] auto Succeeded() const noexcept -> bool
        {
            return Code == DatagramStartCode::Success;
        }
    };

    struct DatagramDrainResult final
    {
        bool Completed{false};
        std::uint64_t PacketsReceived{0};
    };

    struct DatagramListenerHealth final
    {
        bool Bound{false};
        bool Ready{false};
        bool Draining{false};
        std::uint64_t PacketsReceived{0};
        std::uint64_t PacketsRejected{0};
        boost::system::error_code LastError;

        [[nodiscard]] auto Healthy() const noexcept -> bool
        {
            return Bound && Ready && !Draining && !LastError;
        }
    };

    class DatagramListener final
    {
    public:
        using PacketHandler = std::function<void(BoundaryPacket)>;
        using ErrorHandler = std::function<void(boost::system::error_code)>;

        struct StartRequest final
        {
            boost::asio::ip::udp::endpoint Endpoint;
            std::shared_ptr<DatagramClassifier> Demux;
            PacketHandler Handler;
            ErrorHandler OnError;
        };

        struct StopRequest final
        {
            bool CloseSocket{true};
        };

        explicit DatagramListener(Net::any_io_executor Executor);

        ~DatagramListener() noexcept;

        DatagramListener(const DatagramListener &) = delete;
        auto operator=(const DatagramListener &) -> DatagramListener & = delete;

        [[nodiscard]] auto Start(StartRequest Request) -> Net::awaitable<DatagramStartResult>;

        auto Stop(StopRequest Request) noexcept -> void;

        [[nodiscard]] auto Drain() -> Net::awaitable<DatagramDrainResult>;

        [[nodiscard]] auto LocalEndpoint() const -> boost::asio::ip::udp::endpoint;

        [[nodiscard]] auto SharedSocket() const -> std::shared_ptr<Net::ip::udp::socket>;

        /** @brief 返回拥有 Boundary socket state 的服务端 UDP sender 句柄。 */
        [[nodiscard]] auto SharedSender() const
            -> std::shared_ptr<Prism::Contract::QuicDatagramSender>;
        [[nodiscard]] auto Health() const noexcept -> DatagramListenerHealth;

        /** @brief 仅借用原子就绪事实，允许管理 executor 查询，不触碰 socket 或错误对象。 */
        [[nodiscard]] auto IsReady() const noexcept -> bool;

        /** @brief 绑定与就绪分别表达；socket 关闭后就绪为 false。 */
        [[nodiscard]] auto IsBound() const noexcept -> bool;

    private:
        struct State;

        static auto ReportPacketError(
            const std::shared_ptr<State>& StateValue,
            const boost::system::error_code Error) noexcept -> void;

        [[nodiscard]] static auto ReceiveLoop(std::shared_ptr<State> StateValue)
            -> Net::awaitable<void>;

        std::shared_ptr<State> State_;
    };

} // namespace Prism::Boundary
