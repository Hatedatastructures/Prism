/**
 * @file Admission.hpp
 * @brief Hysteria2 admission 契约与连接 owner 声明。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <atomic>
#include <expected>
#include <exception>
#include <cassert>
#include <utility>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <Preview/Account/Lease.hpp>
#include <Preview/Lifecycle/DrainBarrier.hpp>
#include <Preview/Foundation/Executor/FatalState.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <Preview/Foundation/Utility/TrafficSink.hpp>
#include <Preview/Protocols/Hysteria2/Types.hpp>
#include <Preview/Protocols/Hysteria2/Http3Auth.hpp>
#include <Preview/Protocols/Http3/Auth.hpp>
#include <Preview/Protocols/Quic/DatagramAdapter.hpp>
#include <Preview/Protocols/Quic/StreamAdapter.hpp>
#include <Preview/Net/Target.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Contract/Ingress/RequestMetadata.hpp>

namespace Preview::Hysteria2
{

    namespace Net = boost::asio;

    class StreamSession;
    class DatagramSession;

    enum class AdmissionError : std::uint8_t
    {
        Closed,
        AuthenticationRequired,
        InvalidRequest,
        StreamQuota,
        DatagramQuota,
        Canceled,
        ServiceFailure,
    };

    struct DialRequest final
    {
        Preview::Network::Target Target;
    };

    struct ResolveRequest final
    {
        Address Target;
    };

    struct ResolveResult final
    {
        Preview::Fault::Code Status{Preview::Fault::Code::Success};
        std::vector<Address> Endpoints;
    };

    struct StreamRelayRequest final
    {
        Preview::Quic::SharedStreamProvider Inbound;
        Preview::SharedTransmission Outbound;
        Preview::Network::Target Target;
        std::vector<std::byte> InitialPayload;
        bool InitialFin{false};
        Preview::AccountId AccountId{};
        std::string Identity;
        Preview::Account::StreamLease Lease;
        Preview::Contract::RequestMetadata Metadata{};
    };

    struct DatagramRequest final
    {
        Address Target;
        std::vector<std::uint8_t> Payload;
        Preview::AccountId AccountId{};
    };

    struct DatagramResult final
    {
        Preview::Fault::Code Status{Preview::Fault::Code::Success};
        Address Source;
        std::vector<std::uint8_t> Payload;
        std::uint64_t UploadedBytes{0};
        std::uint64_t DownloadedBytes{0};
    };

    struct StreamReport final
    {
        Preview::AccountId AccountId{};
        Preview::Fault::Code Status{Preview::Fault::Code::Success};
        Preview::Contract::RequestMetadata Metadata{};
    };

    struct DatagramSessionReport final
    {
        Preview::AccountId AccountId{};
        std::uint64_t ValidDatagrams{0};
        std::uint64_t MalformedDatagrams{0};
        std::uint64_t DroppedDatagrams{0};
        std::uint64_t UploadedBytes{0};
        std::uint64_t DownloadedBytes{0};
        Preview::Contract::RequestMetadata Metadata{};
        Preview::Foundation::TrafficEventKind Kind{
            Preview::Foundation::TrafficEventKind::Completed};
    };

    struct AdmissionServices final
    {
        std::function<Net::awaitable<std::expected<Preview::SharedTransmission,
            Preview::Fault::Failure>>(DialRequest)> Dial;
        std::function<Net::awaitable<std::expected<void, Preview::Fault::Failure>>(StreamRelayRequest)> RelayStream;
        std::function<Net::awaitable<ResolveResult>(ResolveRequest)> Resolve;
        std::function<Net::awaitable<DatagramResult>(DatagramRequest)> ExchangeDatagram;
        std::function<void(StreamReport)> ReportStream;
        std::function<void(DatagramSessionReport)> ReportDatagram;
    };

    struct AdmissionOptions final
    {
        Net::any_io_executor Executor{};
        std::shared_ptr<Http3AuthSession> AuthSession{};
        std::size_t MaxPendingBidiStreams{64};
        std::size_t MaxPendingDatagrams{1};
        /** @brief 在 admission strand 上请求唯一 QUIC owner 关闭并返回 typed 回执。 */
        std::function<std::expected<void, Preview::Fault::Failure>()> CloseOwner;
        Preview::Contract::RequestMetadata Metadata{};
    };

    class ConnectionAdmission final : public std::enable_shared_from_this<ConnectionAdmission>
    {
    public:
        [[nodiscard]] static auto Create(AdmissionOptions Options, AdmissionServices Services)
            -> std::expected<std::shared_ptr<ConnectionAdmission>, Preview::Fault::Failure>;

        ~ConnectionAdmission() noexcept;

        ConnectionAdmission(const ConnectionAdmission &) = delete;
        auto operator=(const ConnectionAdmission &) -> ConnectionAdmission & = delete;

        [[nodiscard]] auto HandleEvent(Preview::Http3::ServerEvent Event)
            -> Net::awaitable<Preview::Http3::SessionAction>;

        [[nodiscard]] auto OnDatagram(Preview::Quic::SharedDatagramProvider Provider)
            -> std::expected<void, Preview::Fault::Failure>;
        /** @brief 请求在原 executor 上关闭；不返回虚构的异步交付结果。 */
        auto Close() -> void;
        auto OnClosed() -> void;
        /** @brief 原 executor 关闭并等待所有实际 stream/datagram completion。
         * @return 子任务真实退栈才成功；失败保留 admission 与账户租约 owner。
         */
        [[nodiscard]] auto Drain()
            ->Net::awaitable<std::expected<void,Preview::Fault::Failure>>;

        [[nodiscard]] auto Authenticated() const noexcept -> bool;
        [[nodiscard]] auto Closed() const noexcept -> bool;
        [[nodiscard]] auto LastError() const noexcept -> std::optional<AdmissionError>;

    private:
        ConnectionAdmission(AdmissionOptions Options, AdmissionServices Services);

        auto StartPendingChildren() -> void;
        auto RemovePendingStream(std::int64_t StreamId) -> void;
        auto StartStream(Preview::Quic::SharedStreamProvider Provider) -> void;
        auto StartDatagram(Preview::Quic::SharedDatagramProvider Provider) -> void;
        auto AdmitDatagram(Preview::Quic::SharedDatagramProvider Provider)->void;
        auto AdmitPendingDatagram() -> void;
        auto FinishStream(std::uint64_t Id, Preview::Fault::Code Status) noexcept -> void;
        auto FinishDatagram(std::exception_ptr Error) noexcept -> void;
        auto MaybeFinishClose() noexcept -> void;
        auto CloseOnExecutor() noexcept -> void;
        auto RecordFailure(Preview::Fault::Failure Failure) noexcept -> void;
        auto RecordFatal(std::exception_ptr Error) noexcept -> void;
        [[nodiscard]] auto RequestOwnerClose() noexcept
            -> std::expected<void, Preview::Fault::Failure>;


        [[nodiscard]] static auto MapAuthError(AuthError Error) noexcept -> AdmissionError;

        Net::strand<Net::any_io_executor> Executor_;
        AdmissionOptions Options_;
        AdmissionServices Services_;
        std::shared_ptr<Preview::Executor::FatalState> Fatal_;
        std::shared_ptr<Http3AuthSession> AuthSession_;
        std::vector<Preview::Quic::SharedStreamProvider> PendingStreams_;
        Preview::Quic::SharedDatagramProvider PendingDatagram_;
        std::atomic<std::shared_ptr<Preview::Quic::DatagramProvider>> DatagramIdentity_{};
        std::atomic<std::shared_ptr<Preview::Quic::DatagramProvider>> DatagramIngress_{};
        std::unordered_map<std::uint64_t, std::shared_ptr<StreamSession>> ActiveStreams_;
        std::shared_ptr<DatagramSession> ActiveDatagram_;
        Preview::Quic::SharedStreamProvider FailedStreamProvider_{};
        std::shared_ptr<StreamSession> FailedStreamOwner_{};
        Preview::Quic::SharedDatagramProvider FailedDatagramProvider_{};
        std::shared_ptr<DatagramSession> FailedDatagramOwner_{};
        std::size_t PendingDatagrams_{0};
        std::uint64_t NextChildId_{1};
        std::optional<AdmissionError> LastError_;
        Preview::Fault::FailureState Failure_;
        std::atomic<bool> CloseQueued_{false};
        bool Authenticated_{false};
        bool Closed_{false};
        bool CloseOwnerAccepted_{false};
        bool RetryOwnerClose_{false};
        std::optional<Preview::Fault::Failure> OwnerCloseFailure_{};
        Preview::Lifecycle::DrainBarrier Children_;
    };


} // namespace Preview::Hysteria2

#include <Preview/Protocols/Hysteria2/AdmissionLifecycle.hpp>
