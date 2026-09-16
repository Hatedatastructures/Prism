/**
 * @file ProductionWorkerServices.hpp
 * @brief PrismPreview 对 production worker public API 的最小适配
 */

#pragma once

#include <prism/preview/WorkerBridge.hpp>
#include <prism/runtime/worker/worker.hpp>

#include <Preview/Composition/Adapters/ProtocolAdapter.hpp>
#include <Preview/Composition/Recognition/CandidateFactory.hpp>
#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Transport/Reliable.hpp>

#include <charconv>
#include <memory>
#include <string_view>
#include <system_error>
#include <utility>

namespace psm::preview
{

    /**
     * @class ProductionWorkerServices
     * @brief 将 production worker/launcher 暴露为 Preview 启动所需的服务
     */
    class ProductionWorkerServices final
    {
    public:
        using Worker = psm::runtime::worker::worker;
        using Launcher = psm::runtime::worker::ConnectionLauncher;

        /**
         * @brief 构造使用 production 默认 session launcher 的 worker pool 回调
         * @return verified ConnectionLauncher；空回调由 production launch::start 处理
         */
        [[nodiscard]] static auto DefaultConnectionLauncher() -> Launcher
        {
            return [](psm::runtime::worker::launch_params Parameters)
            {
                psm::runtime::worker::launch::start(std::move(Parameters));
            };
        }

        /**
         * @brief 构造 production worker 上的 Preview SOCKS5 数据面 launcher
         * @details 该 launcher 只负责 SOCKS5；其他协议仍由调用方选择 PSM fallback。
         */
        [[nodiscard]] static auto Socks5PreviewConnectionLauncher() -> Launcher
        {
            return [](psm::runtime::worker::launch_params Parameters)
            {
                const auto Worker = Parameters.worker;
                (void)Worker->tasks.spawn_tracked(
                    "preview.socks5.session",
                    RunSocks5Session(std::move(Parameters)));
            };
        }

        [[nodiscard]] static constexpr auto Socks5ModeDescription() noexcept -> std::string_view
        {
            return "socks5=preview;other_protocols=production_fallback";
        }

        [[nodiscard]] static auto HttpPreviewConnectionLauncher() -> Launcher
        {
            return [](psm::runtime::worker::launch_params Parameters)
            {
                const auto Worker = Parameters.worker;
                (void)Worker->tasks.spawn_tracked(
                    "preview.http.session",
                    RunHttpSession(std::move(Parameters)));
            };
        }

        [[nodiscard]] static constexpr auto HttpModeDescription() noexcept -> std::string_view
        {
            return "http=preview;other_protocols=production_fallback";
        }

        /**
         * @brief 将真实 launcher 公开 API 绑定到 bridge
         * @param WorkerObject 已拥有的 production worker
         * @return typed production access
         */
        [[nodiscard]] static auto MakeAccess(const std::shared_ptr<Worker> &WorkerObject)
            -> WorkerBridge::ProductionAccess
        {
            WorkerBridge::ProductionAccess Access;
            if (!WorkerObject)
            {
                return Access;
            }
            Access.Launcher = WorkerObject;
            Access.ResourceWorker = WorkerObject->resources();
            Access.Alive = [WorkerObject] { return WorkerObject->alive(); };
            Access.Stop = [WorkerObject] { WorkerObject->stop(); };
            Access.Metrics = [WorkerObject]
            {
                const auto Snapshot = WorkerObject->load_snapshot();
                return WorkerMetricsSnapshot{
                    .ActiveSessions = Snapshot.active_sessions,
                    .PendingHandoffs = Snapshot.pending_handoffs,
                    .LagUs = Snapshot.lag_us,
                    .ActiveTasks = Snapshot.active_tasks,
                    .SpawnedTotal = Snapshot.spawned_total,
                    .CancelledTotal = Snapshot.cancelled_total,
                    .Alive = Snapshot.alive};
            };
            return Access;
        }

    private:
        [[nodiscard]] static auto RunSocks5Session(
            psm::runtime::worker::launch_params Parameters) -> boost::asio::awaitable<void>
        {
            namespace Net = boost::asio;

            auto Inbound = std::make_shared<Preview::Transport::Reliable>(
                std::move(Parameters.socket));
            auto Dialer = std::make_shared<Preview::Network::Dialer::Dialer>(
                Parameters.worker->ioc.get_executor());
            auto Services = std::make_shared<Preview::Runtime::SessionServices>();

            Preview::Socks5::ServerConfig SocksConfig;
            SocksConfig.EnableTcp = true;
            SocksConfig.EnableUdp = false;
            SocksConfig.EnableAuth = true;
            SocksConfig.username = "prism";
            SocksConfig.password = "prism";
            SocksConfig.DeferConnectReply = true;
            Services->AcceptProtocol = Preview::Runtime::MakeAcceptSocks5(
                std::move(SocksConfig));
            Services->Dial = [Dialer](const Preview::Network::Target &Target)
                -> Net::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
            {
                std::uint16_t Port = 0;
                const auto PortView = std::string_view(Target.Port.data(), Target.Port.size());
                const auto ParseResult = std::from_chars(
                    PortView.data(), PortView.data() + PortView.size(), Port);
                if (ParseResult.ec != std::errc{} ||
                    ParseResult.ptr != PortView.data() + PortView.size())
                {
                    co_return std::pair{Preview::Fault::Code::InvalidArgument,
                                        Preview::SharedTransmission{}};
                }

                std::error_code ErrorCode;
                auto Outbound = co_await Dialer->Connect(
                    std::string_view(Target.Host.data(), Target.Host.size()), Port, ErrorCode);
                if (ErrorCode || !Outbound)
                {
                    co_return std::pair{Preview::Fault::Code::Unreachable,
                                        Preview::SharedTransmission{}};
                }
                co_return std::pair{Preview::Fault::Code::Success, std::move(Outbound)};
            };

            Preview::Runtime::SessionOptions Options;
            Options.Services = std::move(Services);
            auto Session = std::make_shared<Preview::Runtime::Session>(std::move(Options));
            try
            {
                (void)co_await Session->Run(Inbound);
            }
            catch (...)
            {
            }
            Session->Close();
            Inbound->Cancel();
            Inbound->Close();
        }

        [[nodiscard]] static auto RunHttpSession(
            psm::runtime::worker::launch_params Parameters) -> boost::asio::awaitable<void>
        {
            namespace Net = boost::asio;

            auto Inbound = std::make_shared<Preview::Transport::Reliable>(
                std::move(Parameters.socket));
            auto Dialer = std::make_shared<Preview::Network::Dialer::Dialer>(
                Parameters.worker->ioc.get_executor());
            auto Services = std::make_shared<Preview::Runtime::SessionServices>();

            Preview::Composition::Recognition::HttpConfig HttpConfig;
            Services->AcceptProtocol =
                Preview::Composition::Recognition::CandidateFactory::MakeHttp(
                    {}, std::move(HttpConfig)).Accept;
            Services->Dial = [Dialer](const Preview::Network::Target &Target)
                -> Net::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
            {
                std::uint16_t Port = 0;
                const auto PortView = std::string_view(Target.Port.data(), Target.Port.size());
                const auto ParseResult = std::from_chars(
                    PortView.data(), PortView.data() + PortView.size(), Port);
                if (ParseResult.ec != std::errc{} ||
                    ParseResult.ptr != PortView.data() + PortView.size())
                {
                    co_return std::pair{Preview::Fault::Code::InvalidArgument,
                                        Preview::SharedTransmission{}};
                }

                std::error_code ErrorCode;
                auto Outbound = co_await Dialer->Connect(
                    std::string_view(Target.Host.data(), Target.Host.size()), Port, ErrorCode);
                if (ErrorCode || !Outbound)
                {
                    co_return std::pair{Preview::Fault::Code::Unreachable,
                                        Preview::SharedTransmission{}};
                }
                co_return std::pair{Preview::Fault::Code::Success, std::move(Outbound)};
            };

            Preview::Runtime::SessionOptions Options;
            Options.Services = std::move(Services);
            auto Session = std::make_shared<Preview::Runtime::Session>(std::move(Options));
            try
            {
                (void)co_await Session->Run(Inbound);
            }
            catch (...)
            {
            }
            Session->Close();
            Inbound->Cancel();
            Inbound->Close();
        }
    };

} // namespace psm::preview
