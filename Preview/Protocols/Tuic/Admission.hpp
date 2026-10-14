/**
 * @file Admission.hpp
 * @brief TUIC 单连接认证与流/数据报 admission 状态机
 * @details ConnectionAdmission 是一个 QUIC 连接的唯一账户租约 owner。所有事件
 *          在其 executor 上串行处理；它不依赖 Ingress、Composition、Runtime 或 Application。
 */
#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <exception>
#include <cassert>
#include <system_error>
#include <utility>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <Preview/Account/Credential.hpp>
#include <Preview/Account/Lease.hpp>
#include <Preview/Lifecycle/DrainBarrier.hpp>
#include <Preview/Lifecycle/DrainReservation.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <Preview/Foundation/Executor/FatalState.hpp>
#include <Preview/Foundation/Executor/ClosingStorage.hpp>
#include <Preview/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Preview/Foundation/Utility/TrafficSink.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Quic/DatagramAdapter.hpp>
#include <Preview/Protocols/Quic/StreamAdapter.hpp>
#include <Preview/Protocols/Tuic/Conn.hpp>
#include <Preview/Protocols/Tuic/Dgram.hpp>
#include <Preview/Protocols/Tuic/Types.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Contract/Ingress/RequestMetadata.hpp>

namespace Preview::Tuic
{

    namespace Net = boost::asio;

    /** @brief 连接 admission 的静态 TUIC 认证材料与生命周期 owner。 */
    struct AdmissionOptions final
    {
        Net::any_io_executor Executor{};
        std::array<std::uint8_t, UuidLen> Uuid{};
        std::string ExporterContext{};
        std::shared_ptr<const Preview::Account::Credential> Credential{};
        Preview::SharedAuthenticator AuthenticatorOwner{};
        std::size_t MaxPendingBidiStreams{0};
        /** @brief 在 admission strand 上请求唯一 QUIC owner 关闭并返回 typed 回执。 */
        std::function<std::expected<void, Preview::Fault::Failure>()> CloseOwner{};
        /** @brief 原 executor 上对象与服务最终销毁后通知；回调只 weak 联系退休屏障，不保留 context。 */
        std::function<void()> OnFinalized{};
        Preview::Contract::RequestMetadata Metadata{};
    };

    struct DialRequest final
    {
        Address Target;
    };

    struct ResolveRequest final
    {
        Address Target;
    };

    struct ResolveResult final
    {
        Error Status{Error::None};
        std::vector<Address> Endpoints{};
    };

    /**
     * @brief TCP 转发请求；Lease 由 admission 在 bidi 接入时获取并贯穿握手、拨号与 relay。
     * @details Composition adapter 应转交该租约，不要再次获取 stream quota。
     */
    struct StreamRelayRequest final
    {
        Message Request{};
        SharedConn Inbound{};
        Preview::SharedTransmission Outbound{};
        Preview::AccountId AccountId{};
        std::string Identity{};
        Preview::Account::StreamLease Lease{};
        Preview::Contract::RequestMetadata Metadata{};
    };

/** @brief 已完成 stream 业务操作的 typed 失败观察，不表示连接清理失败。 */
struct StreamFailureReport final
{
    std::uint64_t ConnectionStreamId{0};
    Preview::Lifecycle::TaskIdentity TaskIdentity{};
    Preview::Fault::Failure Failure{};
};

    /** @brief 单个已解析 UDP 目标、请求负载与已认证账户。 */
    struct DatagramRequest final
    {
        Address Target;
        std::vector<std::uint8_t> Payload{};
        /** @brief 从 connection admission 认证结果传递，不需要出站服务回查目录。 */
        Preview::AccountId AccountId{};
    };

    /** @brief 一次 UDP egress 结果；字节数只在对应网络阶段成功后报告。 */
    struct DatagramResult final
    {
        Error Status{Error::None};
        Address Source{};
        std::vector<std::uint8_t> Payload{};
        /** @brief 已成功发送到目标 UDP socket 的请求字节数，即使后续收包失败也保留。 */
        std::uint64_t UploadedBytes{0};
        /** @brief 目标返回的响应字节数；仅在 Admission 成功回送 TUIC provider 后计入会话。 */
        std::uint64_t DownloadedBytes{0};
    };

    /** @brief 一个 TUIC datagram association 结束时的账户级汇总。 */
    struct DatagramSessionReport final
    {
        Preview::AccountId AccountId{};
        std::uint64_t DatagramCount{0};
        std::uint64_t UploadedBytes{0};
        std::uint64_t DownloadedBytes{0};
        Preview::Contract::RequestMetadata Metadata{};
        Preview::Foundation::TrafficEventKind Kind{
            Preview::Foundation::TrafficEventKind::Completed};
    };

    /**
     * @brief TUIC 的协议到外部网络能力端口；每个操作仅接收一个 typed request。
     * @details Admission 直接 await 每个返回值；child coroutine 的 cancellation state 会
     *          传播到这些 awaitable。若适配器再用 co_spawn，必须显式转发当前 cancellation
     *          slot；不得把请求分离到未追踪的 detached 工作。session report 在 datagram child
     *          正常结束、I/O 错误或取消退栈时同步调用一次。
     */
    struct AdmissionServices final
    {
        std::function<Net::awaitable<std::expected<Preview::SharedTransmission,
            Preview::Fault::Failure>>(DialRequest)> Dial{};
        std::function<Net::awaitable<ResolveResult>(ResolveRequest)> Resolve{};
        std::function<Net::awaitable<std::expected<void, Preview::Fault::Failure>>(StreamRelayRequest)> RelayStream{};
        /** @brief 观察已完成的拨号/relay 失败；观察异常进入 FatalState，不改变原失败值。 */
        std::function<void(StreamFailureReport)> ReportStreamFailure{};
        std::function<Net::awaitable<DatagramResult>(DatagramRequest)> ExchangeDatagram{};
        std::function<void(DatagramSessionReport)> ReportDatagramSession{};
    };

    /**
     * @class ConnectionAdmission
     * @brief 持有一个 TUIC QUIC 连接的认证、stream lease 和 child 生命周期。
     * @details 调用方在连接 executor 上投递事件。认证 uni stream 与 exporter 都就绪后只
     *          认证一次；连接租约留在本对象，bidi handler 各自持有一个 StreamLease。
     *          最后一个 shared owner 可从任意线程释放；创建时安装的 deleter 会将析构投递到
     *          connection strand，因此 executor 必须运行到该析构回调完成。
     */
    class ConnectionAdmission final : public std::enable_shared_from_this<ConnectionAdmission>
    {
    public:
        /** @brief 冷构造 admission 与有界失败 owner。
         * @param Options 拥有型认证、executor 与会话配置。
         * @param Services 拥有型网络操作；协程由 admission 原 executor 等待退栈。
         * @return 成功 owner；非法配置返回 InvalidArgument，预留溢出或分配不足保留 ResourceUnavailable 原因。
         * @details 构造完成后 On* 输入先占预约，再排入 admission strand；最终关闭由其 QuicConnectionLifecycle 负责。
         */
        [[nodiscard]] static auto Create(AdmissionOptions Options, AdmissionServices Services)
            -> std::expected<std::shared_ptr<ConnectionAdmission>, Preview::Fault::Failure>;

        ~ConnectionAdmission() noexcept;

        ConnectionAdmission(const ConnectionAdmission &) = delete;
        auto operator=(const ConnectionAdmission &) -> ConnectionAdmission & = delete;

        /** @brief 接收原生单向认证流；成功只确认有界预约，失败时 provider 仍由 Native stream registry 保有。
         * @param AuthStream 原生共享 provider，适配器只在预约交付到 admission executor 后创建。
         * @return 成功表示 admission 已接管预约；失败保留原生 Failure，不声称事件已处理。
         */
        [[nodiscard]] auto OnUnidirectional(Preview::Quic::SharedStreamProvider AuthStream)
            -> std::expected<void, Preview::Fault::Failure>;
        /** @brief 接收 exporter；同一连接的重复通知合并为同一拥有事件。 */
        [[nodiscard]] auto OnExporter(KeyingMaterialExporter Exporter)
            -> std::expected<void, Preview::Fault::Failure>;
        /** @brief 接收原生双向流；成功只确认有界预约，拒绝时仍由 Native stream registry 保有。 */
        [[nodiscard]] auto OnBidirectional(Preview::Quic::SharedStreamProvider Stream)
            -> std::expected<void, Preview::Fault::Failure>;
        /** @brief 接收唯一 datagram provider；重复同一 provider 合并，冲突 provider 返回 ResourceUnavailable。 */
        [[nodiscard]] auto OnDatagram(Preview::Quic::SharedDatagramProvider Provider)
            -> std::expected<void, Preview::Fault::Failure>;
        /** @brief 请求一次原 executor 关闭交付；最终 I/O 退栈由 Drain 等待。 */
        void Close();
        /** @brief 记录 Native close cause 并保留关闭事件；停域期间仍可由同一 owner 重试。 */
        void OnClosed();
        /** @brief 原 executor 等待 auth/relay/datagram completion；最后才释放账户租约与服务材料。 */
        [[nodiscard]] auto Drain()
            ->Net::awaitable<std::expected<void,Preview::Fault::Failure>>;

    private:
        /** @brief 未完成输入交付或拒绝排空的预约上限；独立于 QUIC stream 总量与重用代次。 */
        static constexpr std::size_t MaxPendingInputs = 64U;
        /** @brief 复投索引沿用现有输入预算，并为去重关闭事件各留一槽。 */
        static constexpr std::size_t MaxRetryableInputDeliveries = MaxPendingInputs + 2U;
        enum class InputKind : std::uint8_t { Authentication, Exporter, Stream, Datagram, Close, NativeClosed };
        struct InputReservation final
        {
            InputReservation(Preview::Lifecycle::DrainBarrier &Barrier,
                std::atomic<std::size_t> *Count);
            InputReservation(InputReservation &&Other) noexcept;
            auto operator=(InputReservation &&Other) noexcept -> InputReservation &;
            InputReservation(const InputReservation &) = delete;
            ~InputReservation() noexcept;
            auto Reset() noexcept -> void;

            std::optional<Preview::Lifecycle::DrainReservation> Barrier_{};
            std::atomic<std::size_t> *Count_{};
        };
        struct InputEvent final
        {
            InputKind Kind{InputKind::Authentication};
            Preview::SharedTransmission Carrier{};
            Preview::Quic::SharedStreamProvider StreamProvider{};
            Preview::Quic::SharedDatagramProvider Provider{};
            KeyingMaterialExporter Exporter{};
            std::optional<InputReservation> Reservation{};
        };
        struct RejectedDrainCompletion final
        {
            Preview::SharedTransmission Carrier;
            InputReservation Reservation;
            std::exception_ptr Error;
            std::expected<void, Preview::Fault::Failure> Result;
        };
        class InputDelivery;
        /** @brief 首次真实 Post 拒收时懒分配；弱槽只索引 Storage 已拥有的输入实物。 */
        struct RetryableInputIndex final
        {
            std::array<std::atomic<std::weak_ptr<InputDelivery>>,
                MaxRetryableInputDeliveries> Slots{};
        };
        struct ActiveStream final
        {
            SharedConn Inbound{};
            Preview::SharedTransmission Outbound{};
            std::shared_ptr<Net::cancellation_signal> Cancellation{};
            std::optional<Preview::Account::StreamLease> RetainedLease{};
        };
        struct StreamTaskResult final
        {
            std::optional<Preview::Fault::Failure> OperationFailure{};
            std::optional<Preview::Fault::Failure> CleanupFailure{};
            std::optional<Preview::Account::StreamLease> RetainedLease{};
        };

        ConnectionAdmission(AdmissionOptions Options, AdmissionServices Services);

        void StartAuthentication();
        /** @brief 记录认证子协程终结并按原 executor 关闭其 connection owner。 */
        void FinishAuthentication(std::exception_ptr Error) noexcept;
        /** @brief 关闭并排空认证 Conn 与其底层 stream，保留首个 typed Failure。 */
        [[nodiscard]] auto CloseAndDrainAuthenticationConnection(
            std::shared_ptr<Conn<>> Connection)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>;
        void AdmitAuthentication(Preview::SharedTransmission AuthStream,
            InputReservation Input);
        void AdmitStream(Preview::SharedTransmission Stream,
            InputReservation Input);
        void AdmitDatagram(Preview::Quic::SharedDatagramProvider Provider,
            Preview::SharedTransmission Transport,
            InputReservation Input);
        [[nodiscard]] auto ReserveInput() noexcept -> std::optional<InputReservation>;
        [[nodiscard]] auto DispatchInput(InputEvent Event)
            -> std::expected<void, Preview::Fault::Failure>;
        /** @brief 只登记已被原 executor 明确拒收的交付；索引不拥有事件或预约。 */
        [[nodiscard]] auto TrackRetryableInputDelivery(
            const std::shared_ptr<InputDelivery> &Delivery) noexcept -> bool;
        /** @brief 输入真实完成后清除索引；失败或未知交付继续占有 reservation 与槽。 */
        auto RemoveRetryableInputDelivery(InputDelivery &Delivery) noexcept -> void;
        /** @brief 在原 admission strand 重投真实拒收事件，保留首个 typed 失败。 */
        [[nodiscard]] auto RetryRejectedInputDeliveries() noexcept
            -> std::expected<void, Preview::Fault::Failure>;
        void StartStream(Preview::SharedTransmission Stream,
            std::optional<InputReservation> Input);
        void StartDatagram(Preview::Quic::SharedDatagramProvider Provider,
            Preview::SharedTransmission Transport);
        void FinishStream(std::uint64_t Id, std::exception_ptr Exception,
            StreamTaskResult Result) noexcept;
        void FinishDatagram(
            const Preview::Quic::SharedDatagramProvider &Provider,
            std::exception_ptr Exception,
            std::expected<void,Preview::Fault::Failure> Result) noexcept;
        /** @brief 数据报协程完成边界；持有 provider 并将异常与正式结果交还协议 owner。 */
        auto CompleteDatagram(Preview::Quic::SharedDatagramProvider Provider,
            std::exception_ptr Error,
            std::expected<void, Preview::Fault::Failure> Result) noexcept -> void;
        /** @brief 将 stream 业务失败交给既有观察端；观察抛错发布到 FatalState。 */
        void ObserveStreamFailure(StreamFailureReport Report) noexcept;
        void CloseOnExecutor() noexcept;
        void MaybeFinishClose() noexcept;
        void RecordFailure(Preview::Fault::Failure Failure) noexcept;
        void RecordFatal(std::exception_ptr Error) noexcept;
        void StoreFailedInput(InputEvent Event) noexcept;
        void RetainFailedInput(InputEvent Event) noexcept;
        void RetainFailedCarrier(Preview::SharedTransmission Carrier) noexcept;
        [[nodiscard]] auto RequestOwnerClose() noexcept
            -> std::expected<void, Preview::Fault::Failure>;
        void QueueRejectedTransmission(Preview::SharedTransmission Carrier,
            InputReservation Input);
        void QueueRejectedTransmission(Preview::SharedTransmission Carrier);
        void FinishRejectedTransmission(RejectedDrainCompletion Completion) noexcept;
        [[nodiscard]] auto CloseTransmission(const Preview::SharedTransmission &Carrier) noexcept
            ->std::expected<void,Preview::Fault::Failure>;
        [[nodiscard]] auto DrainTransmission(Preview::SharedTransmission Carrier)
            ->Net::awaitable<std::expected<void,Preview::Fault::Failure>>;
        [[nodiscard]] auto DrainStream(std::uint64_t Id)
            ->Net::awaitable<std::expected<void,Preview::Fault::Failure>>;
        [[nodiscard]] auto DrainPendingCarriers()
            ->Net::awaitable<std::expected<void,Preview::Fault::Failure>>;

        [[nodiscard]] auto Authenticate() -> Net::awaitable<void>;
        [[nodiscard]] auto ServeStream(
            std::uint64_t Id,
            SharedConn Connection,
            Preview::Account::StreamLease StreamLease)
            -> Net::awaitable<StreamTaskResult>;
        /** @brief 借用父协程租约执行握手、拨号与 relay；relay 移交后由真实 relay owner 释放。 */
        [[nodiscard]] auto RunStream(std::uint64_t Id,SharedConn Connection,
            Preview::Account::StreamLease &StreamLease)
            -> Net::awaitable<std::expected<void,Preview::Fault::Failure>>;
        [[nodiscard]] auto ServeDatagrams(Preview::Quic::SharedDatagramProvider Provider,
            Preview::SharedTransmission Transport,
            std::shared_ptr<Net::cancellation_signal> Cancellation)
            -> Net::awaitable<std::expected<void,Preview::Fault::Failure>>;
        [[nodiscard]] auto RunDatagrams(Preview::SharedTransmission Transport)
            ->Net::awaitable<void>;

        Net::strand<Net::any_io_executor> Executor_;
        AdmissionOptions Options_;
        AdmissionServices Services_;
        Preview::SharedTransmission AuthStream_{};
        KeyingMaterialExporter Exporter_{};
        std::vector<Preview::SharedTransmission> PendingStreams_{};
        Preview::Quic::SharedDatagramProvider PendingDatagram_{};
        Preview::SharedTransmission PendingDatagramTransport_{};
        Preview::Quic::SharedDatagramProvider ActiveDatagram_{};
        Preview::SharedTransmission ActiveDatagramTransport_{};
        std::unordered_map<std::uint64_t, ActiveStream> ActiveStreams_{};
        std::shared_ptr<Net::cancellation_signal> DatagramCancellation_{};
        Preview::Account::AccountLease AccountLease_{};
        Preview::AccountId AccountId_{};
        std::string Identity_{};
        std::unique_ptr<InputEvent[]> FailedInputs_{};
        std::atomic<std::size_t> FailedInputCount_{0};
        std::size_t FailedInputCapacity_{0};
        std::atomic<std::size_t> PendingInputCount_{0};
        /** @brief 拒收发生前为空，不给正常输入增加 per-event 分配或全表扫描。 */
        std::atomic<std::shared_ptr<RetryableInputIndex>> RetryableInputIndex_{};
        /** @brief 弱索引分配失败时保留可重试项数，使 Drain typed fail 而不悬挂。 */
        std::atomic<std::size_t> UnindexedRetryCount_{0};
        std::atomic<bool> CloseQueued_{false};
        /** @brief 每个底层连接关闭回执最多登记一次有界输入。 */
        std::atomic<bool> NativeClosedQueued_{false};
        std::atomic<bool> ExporterQueued_{false};
        std::atomic<std::shared_ptr<Preview::Quic::DatagramProvider>> DatagramInput_{};
        std::shared_ptr<Preview::Executor::FatalState> Fatal_;
        std::shared_ptr<Preview::Executor::ClosingStorage> Storage_;
        std::shared_ptr<Preview::Executor::ExecutorReclaimer> Reclaimer_;
        std::uint64_t NextStreamId_{1};
        bool ExporterReady_{false};
        bool AuthenticationStarted_{false};
        bool Authenticated_{false};
        bool Closed_{false};
        /** @brief 收到 Native close 回执；租约释放仍只在 admission executor 上执行。 */
        std::atomic<bool> NativeClosed_{false};
        bool CloseOwnerAccepted_{false};
        bool RetryOwnerClose_{false};
        std::optional<Preview::Fault::Failure> OwnerCloseFailure_{};
        Preview::Fault::FailureState Failure_;
        Preview::Lifecycle::DrainBarrier Inputs_;
        Preview::Lifecycle::DrainBarrier Children_;
    };
} // namespace Preview::Tuic

#include <Preview/Protocols/Tuic/AdmissionRuntime.hpp>
