/**
 * @file NativeConnection.hpp
 * @brief Prism 原生 ngtcp2 QUIC 连接状态、提供者和传输契约。
 * @details 该头文件只包含单连接 owner 的状态和 callback-facing 声明；
 *          行为实现位于同一 owner 的 inline implementation headers。
 */

#pragma once

#include <Prism/Protocols/Quic/Native.hpp>
#include <Prism/Protocols/Quic/Detail/NativeConnectionOperationReservation.hpp>
#include <Prism/Protocols/Quic/Detail/NativeConnectionState.hpp>
#include <Prism/Protocols/Quic/Detail/NativeStreamActivity.hpp>
#include <Prism/Protocols/Quic/Detail/NativeConnectionSocketRegistry.hpp>
#include <Prism/Protocols/Quic/Detail/DatagramInbox.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Foundation/Executor/FatalState.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <openssl/rand.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <limits>
#include <span>
#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>
#include <type_traits>

namespace Prism::Quic::Detail
{

    namespace Net = boost::asio;
    using Udp = Net::ip::udp;

    class NativeConnection;
    struct StreamProviderCloseActionOwner;

    [[nodiscard]] inline auto ToStdError(const Prism::Error ErrorCode) -> std::error_code
    {
        return {static_cast<int>(ErrorCode), std::generic_category()};
    }

    [[nodiscard]] inline auto ToStdError(const boost::system::error_code &ErrorCode) -> std::error_code
    {
        if (!ErrorCode)
        {
            return {};
        }
        return {ErrorCode.value(), std::generic_category()};
    }

    [[nodiscard]] inline auto Now() -> ngtcp2_tstamp
    {
        return static_cast<ngtcp2_tstamp>(std::chrono::duration_cast<std::chrono::microseconds>(
                                               std::chrono::steady_clock::now().time_since_epoch())
                                               .count());
    }

    template <typename EndpointOptions>
    [[nodiscard]] inline auto MakeDatagramLimits(const EndpointOptions &Options)
        -> DatagramInbox::Limits
    {
        if constexpr (std::is_same_v<EndpointOptions, Prism::Quic::ServerOptions>)
        {
            return DatagramInbox::Limits{Options.MaxDatagrams, 64U * 1024U};
        }
        return DatagramInbox::Limits{};
    }

    class NativeStream final : public StreamProvider, public std::enable_shared_from_this<NativeStream>
    {
    public:
        NativeStream(std::weak_ptr<NativeConnection> OwnerValue, std::shared_ptr<StreamState> StateValue)
            : Context_(StateValue ? Prism::Executor::ContextOwner::Find(StateValue->Executor) : nullptr),
              Owner_(std::move(OwnerValue)), State_(std::move(StateValue)),
              Activity_(State_ ? std::make_shared<NativeStreamActivity>(State_) : nullptr)
        {
            if (State_)
            {
                State_->Activity = Activity_;
            }
        }

        [[nodiscard]] auto Read(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override;

        [[nodiscard]] auto Write(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override;

        [[nodiscard]] auto Close() -> ControlResult override;
        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return Activity_;
        }
        [[nodiscard]] auto ShutdownWrite() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override;
        [[nodiscard]] auto WaitForWriteAcknowledgement()
            -> Net::awaitable<ShutdownResult> override;

        [[nodiscard]] auto StreamId() const noexcept -> std::int64_t override
        {
            if (State_)
            {
                return State_->Id;
            }
            return -1;
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (State_)
            {
                return State_->Executor;
            }
            return Net::any_io_executor{};
        }

        [[nodiscard]] auto IsClosed() const noexcept -> bool override
        {
            return !State_ || State_->Closed;
        }

    private:
        [[nodiscard]] static auto ReadOwned(
            NativeStreamActivity::Operation Reservation,
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t>;
        [[nodiscard]] static auto WriteOwned(
            NativeStreamActivity::Operation Reservation,
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t>;
        [[nodiscard]] static auto ShutdownOwned(
            std::shared_ptr<NativeStream> Owner,
            NativeStreamActivity::Operation Reservation)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        [[nodiscard]] static auto AcknowledgementOwned(
            std::shared_ptr<NativeStream> Owner,
            NativeStreamActivity::Operation Reservation)
            -> Net::awaitable<ShutdownResult>;
        /** @brief provider、状态、关闭回执与独立 executor/PMR 的析构顺序固定。 */
        std::shared_ptr<Prism::Executor::ContextOwner> Context_;
        std::weak_ptr<NativeConnection> Owner_;
        std::shared_ptr<StreamState> State_;
        std::shared_ptr<NativeStreamActivity> Activity_;
    };

    class NativeDatagram final : public DatagramProvider,
                                public std::enable_shared_from_this<NativeDatagram>
    {
    public:
        NativeDatagram(std::weak_ptr<NativeConnection> OwnerValue, std::shared_ptr<DatagramState> StateValue)
            : Context_(StateValue?Prism::Executor::ContextOwner::Find(StateValue->Executor):nullptr),
              Owner_(std::move(OwnerValue)), State_(std::move(StateValue))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (State_)
            {
                return State_->Executor;
            }
            return Net::any_io_executor{};
        }

        [[nodiscard]] auto Receive(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override;

        [[nodiscard]] auto Send(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override;

        auto Close() -> void override;
        auto Cancel() -> void override;

        [[nodiscard]] auto IsClosed() const noexcept -> bool override
        {
            return !State_ || State_->Closed;
        }

    private:
        /** @brief 外部数据报句柄先销毁 State/channel，再释放原独立 executor owner。 */
        std::shared_ptr<Prism::Executor::ContextOwner> Context_;
        std::weak_ptr<NativeConnection> Owner_;
        std::shared_ptr<DatagramState> State_;
    };

    class NativeConnection final : public std::enable_shared_from_this<NativeConnection>
    {
        friend class NativeStream;
        friend class NativeDatagram;
        friend struct StreamProviderCloseActionOwner;
        template <class Owner>
        friend class NativeConnectionOperationReservation;

        using OperationReservation = NativeConnectionOperationReservation<NativeConnection>;

    public:
        enum class Role : std::uint8_t
        {
            Client,
            Server,
        };

        /** @brief 同步借用唯一 typed endpoint 配置并复制拥有值；服务端门面保活 TLS 原 owning 值。
         * @details Client/Server 的角色由配置类型在编译期决定，无位置参数包、协议查找或旧 overload。
         *          全部 I/O 在 Executor 串行执行；Close 取消，Drain 等实际循环完成，stream 支持半关闭。
         */
        template<typename EndpointOptions>
            requires(std::is_same_v<EndpointOptions,Prism::Quic::ClientOptions> ||
                std::is_same_v<EndpointOptions,Prism::Quic::ServerOptions>)
        explicit NativeConnection(const EndpointOptions& Options)
            :Role_(std::is_same_v<EndpointOptions,Prism::Quic::ServerOptions>?Role::Server:Role::Client),
             Executor_(Options.Executor),Fatal_(Prism::Executor::FatalState::For(Executor_)),
             Socket_(Options.Socket),Random_(Options.Random),
             HandshakeNotify_(Executor_,16),IncomingNotify_(Executor_,1),IncomingUnidirectionalNotify_(Executor_,1),
             WritePermit_(Executor_,1),SendNotify_(Executor_,16),FlowNotify_(Executor_,16),PumpTimer_(Executor_),
             Datagram_(std::make_shared<DatagramState>(Executor_, MakeDatagramLimits(Options))),
             Loops_(std::make_shared<Prism::Executor::ExecutorReclaimer>(Executor_))
        {
            if constexpr(std::is_same_v<EndpointOptions,Prism::Quic::ClientOptions>)
            {Peer_=Options.Peer;ServerName_=Options.ServerName;TlsContextOwner_=Options.TlsContext;TlsContext_=TlsContextOwner_?TlsContextOwner_->native_handle():nullptr;}
            else
            {
                Sender_=Options.Sender;
                TlsContextOwner_=Options.TlsContext;TlsContext_=TlsContextOwner_?TlsContextOwner_->native_handle():nullptr;
                ExternalReceive_=Options.ExternalReceive;ExpectedAlpn_=Options.ExpectedAlpn;
                ExpectedServerName_=Options.ExpectedServerName;MaxActiveBidirectionalStreams_=Options.MaxStreams;
                OnEstablished_=Options.OnEstablished;OnStream_=Options.OnStream;OnUnidirectional_=Options.OnUnidirectional;
                OnDatagram_=Options.OnDatagram;OnClosed_=Options.OnClosed;OnExporter_=Options.OnExporter;OnLifecycle_=Options.OnLifecycle;
            }
            (void)WritePermit_.try_send(boost::system::error_code{});
        }

        ~NativeConnection() noexcept = default;

        NativeConnection(const NativeConnection &) = delete;
        auto operator=(const NativeConnection &) -> NativeConnection & = delete;

        auto Start() -> void;
        auto Close() -> void;
        /** @brief 原 executor 等待 pump/receive 实际完成；ExternalReceive 不关闭共享 socket。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        [[nodiscard]] auto IsRetired() const noexcept -> bool;

        [[nodiscard]] auto ReceivePacket(
            const Udp::endpoint &From,
            std::span<const std::byte> Data) -> bool;

        [[nodiscard]] auto WaitHandshake() -> Net::awaitable<bool>;
        [[nodiscard]] auto MarkProtocolReady() -> Net::awaitable<bool>;
        [[nodiscard]] auto OpenBidirectionalStream()
            -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>;
        [[nodiscard]] auto OpenUnidirectionalStream()
            -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>;
        [[nodiscard]] auto AcceptBidirectionalStream()
            -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>;
        [[nodiscard]] auto AcceptUnidirectionalStream()
            -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>;
        [[nodiscard]] auto ExportKeyingMaterial(
            std::span<std::uint8_t> Output,
            std::span<const std::uint8_t> Label,
            std::string_view Context) const -> bool;
        [[nodiscard]] auto DatagramProvider() -> SharedDatagramProvider;
        [[nodiscard]] auto Health() const noexcept -> Prism::Quic::NativeConnectionHealth;

        [[nodiscard]] auto WriteStream(
            std::int64_t StreamId,
            std::vector<std::byte> Data,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t>;
        [[nodiscard]] auto WriteDatagram(
            std::vector<std::byte> Data,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t>;

        auto CloseStream(const std::shared_ptr<StreamState> &State) -> void;
        [[nodiscard]] auto ShutdownStreamWrite(std::shared_ptr<StreamState> State) -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        auto CloseDatagram(const std::shared_ptr<DatagramState> &State) -> void;
        auto OnStreamReadConsumed(std::int64_t StreamId, std::size_t Bytes) -> void;
        auto OnStreamDataAcknowledged(
            std::int64_t StreamId,
            std::uint64_t Offset,
            std::uint64_t DataLength) -> void;
        auto OnStreamReset(
            std::int64_t StreamId,
            std::uint64_t FinalSize,
            std::uint64_t ApplicationErrorCode) -> void;
        auto OnPeerStopSending(std::int64_t StreamId, std::uint64_t ApplicationErrorCode) -> void;

    private:
        /** @brief stream 已终止后仅归还仍存活连接的 MAX_DATA 信用。 */
        auto OnTerminalStreamReadConsumed(std::size_t Bytes) -> void;

        enum class DecodeResult : std::uint8_t
        {
            Accepted,
            Ignored,
            Fatal,
        };

        enum class FinPacketAttempt : std::uint8_t
        {
            Submitted,
            FlowBlocked,
            Retry,
        };

        enum class LoopKind : std::uint8_t
        {
            Receive,
            Pump,
            Send,
        };

        struct OutboundPacket
        {
            std::vector<std::byte> Data;
            Udp::endpoint Peer;
        };

        using NotifyChannel = Net::experimental::channel<void(boost::system::error_code)>;
        using HandshakeChannel = Net::experimental::channel<void(boost::system::error_code, bool)>;

        class WritePermitRelease final
        {
        public:
            explicit WritePermitRelease(NotifyChannel &Permit) noexcept : Permit_(Permit) {}
            ~WritePermitRelease() noexcept
            {
                (void)Permit_.try_send(boost::system::error_code{});
            }

            WritePermitRelease(const WritePermitRelease &) = delete;
            auto operator=(const WritePermitRelease &) -> WritePermitRelease & = delete;

        private:
            NotifyChannel &Permit_;
        };

        [[nodiscard]] auto InitializeClient() -> bool;
        [[nodiscard]] auto InitializeServer(const ngtcp2_version_cid &VersionCid) -> bool;
        [[nodiscard]] auto InitializeTls(bool Server) -> bool;
        [[nodiscard]] auto FillRandom(std::uint8_t *Destination, std::size_t Length) const -> bool;
        [[nodiscard]] auto DecodeAndRead(
            const Udp::endpoint &From,
            std::span<const std::byte> Data) -> DecodeResult;

        [[nodiscard]] auto RunTrackedLoop(LoopKind Kind) -> Net::awaitable<void>;
        [[nodiscard]] auto RunReceiveLoop() -> Net::awaitable<void>;
        [[nodiscard]] auto RunSendLoop() -> Net::awaitable<void>;
        [[nodiscard]] auto RunPumpLoop() -> Net::awaitable<void>;
        [[nodiscard]] auto WaitForSendDrain() -> Net::awaitable<bool>;
        [[nodiscard]] auto TryQueueFinPacket(const std::shared_ptr<StreamState> &State)
            -> std::expected<FinPacketAttempt, Prism::Fault::Failure>;
        [[nodiscard]] auto WriteStreamPackets(
            std::shared_ptr<StreamState> State,
            std::vector<std::byte> Data) -> Net::awaitable<StreamWriteResult>;
        [[nodiscard]] auto QueueStreamFin(std::shared_ptr<StreamState> State) -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        [[nodiscard]] auto QueueFinUntilAccepted(std::shared_ptr<StreamState> State) -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        [[nodiscard]] static auto DrainOwned(std::shared_ptr<NativeConnection> Owner)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        [[nodiscard]] auto DrainOnExecutor()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        auto QueueFlush() -> void;
        auto QueuePacket(
            const std::byte *Data,
            std::size_t Length,
            const Udp::endpoint &Peer) -> void;
        [[nodiscard]] auto StartTrackedLoop(LoopKind Kind) -> bool;
        auto CompleteTrackedLoop(LoopKind Kind, std::exception_ptr Error) noexcept -> void;
        auto StartSendLoop() -> void;
        auto StartOnExecutor() -> void;
        auto CloseOnExecutor() -> void;
        auto RetireCallbackOwnersOnExecutor() noexcept -> void;
        auto SignalHandshake(bool Success) -> void;
        [[nodiscard]] auto AcceptsPacket(std::span<const std::byte> Data) const -> bool;

        [[nodiscard]] auto OpenStream(bool Unidirectional)
            -> Net::awaitable<std::expected<SharedStreamProvider, Prism::Fault::Failure>>;
        [[nodiscard]] auto AbandonOpenedStream(std::int64_t StreamId)
            -> std::optional<Prism::Fault::Failure>;
        [[nodiscard]] auto MakeStream(std::int64_t StreamId, bool Incoming, bool Unidirectional)
            -> std::expected<SharedStreamProvider, Prism::Fault::Failure>;
        auto OnStreamOpen(std::int64_t StreamId) -> int;
        auto OnStreamData(
            std::int64_t StreamId,
            std::uint32_t Flags,
            std::span<const std::byte> Data) -> int;
        auto OnStreamClose(std::int64_t StreamId, std::uint32_t Flags,
                           std::uint64_t ApplicationErrorCode) -> void;
        auto OnDatagram(std::span<const std::byte> Data) -> void;
        auto OnHandshakeComplete() -> int;
        auto EmitLifecycle(Prism::Quic::ServerLifecycleStage Stage,
                           std::int64_t Code = 0) noexcept -> void
        {
            if (!OnLifecycle_)
            {
                return;
            }
            try
            {
                OnLifecycle_(Prism::Quic::ServerLifecycleEvent{Stage, Code});
            }
            catch (...)
            {
            }
        }

    public:
        [[nodiscard]] static auto MakeCallbacks(bool Server) -> ngtcp2_callbacks;
        static int SetReadSecret(
            SSL *Ssl,
            ssl_encryption_level_t Level,
            const SSL_CIPHER *Cipher,
            const std::uint8_t *Secret,
            std::size_t SecretLength);
        static int SetWriteSecret(
            SSL *Ssl,
            ssl_encryption_level_t Level,
            const SSL_CIPHER *Cipher,
            const std::uint8_t *Secret,
            std::size_t SecretLength);
        static int AddHandshakeData(
            SSL *Ssl,
            ssl_encryption_level_t Level,
            const std::uint8_t *Data,
            std::size_t Length);
        static int FlushFlight(SSL *Ssl);
        static int SendAlert(SSL *Ssl, ssl_encryption_level_t Level, std::uint8_t Alert);
        static int HandshakeCompleted(ngtcp2_conn *Conn, void *UserData);
        static int RecvCryptoData(
            ngtcp2_conn *Conn,
            ngtcp2_encryption_level Level,
            std::uint64_t Offset,
            const std::uint8_t *Data,
            std::size_t Length,
            void *UserData);
        static int RecvStreamData(
            ngtcp2_conn *Conn,
            std::uint32_t Flags,
            std::int64_t StreamId,
            std::uint64_t Offset,
            const std::uint8_t *Data,
            std::size_t Length,
            void *UserData,
            void *StreamUserData);
        static int StreamOpen(ngtcp2_conn *Conn, std::int64_t StreamId, void *UserData);
        static int StreamClose(
            ngtcp2_conn *Conn,
            std::uint32_t Flags,
            std::int64_t StreamId,
            std::uint64_t AppErrorCode,
            void *UserData,
            void *StreamUserData);
        static int RecvDatagram(
            ngtcp2_conn *Conn,
            std::uint32_t Flags,
            const std::uint8_t *Data,
            std::size_t Length,
            void *UserData);
        static int AckDatagram(ngtcp2_conn *Conn, std::uint64_t DatagramId, void *UserData);
        static int RecvRetry(ngtcp2_conn *Conn, const ngtcp2_pkt_hd *Header, void *UserData);
        static int VersionNegotiation(
            ngtcp2_conn *Conn,
            std::uint32_t Version,
            const ngtcp2_cid *ClientDcid,
            void *UserData);
        static auto Random(
            std::uint8_t *Destination,
            std::size_t Length,
            const ngtcp2_rand_ctx *Context) -> void;
        static int NewConnectionId(
            ngtcp2_conn *Conn,
            ngtcp2_cid *Cid,
            std::uint8_t *Token,
            std::size_t CidLength,
            void *UserData);
        static int PathChallenge(ngtcp2_conn *Conn, std::uint8_t *Data, void *UserData);

        [[nodiscard]] static auto MakePath(
            ngtcp2_path_storage &Storage,
            const Udp::endpoint &Local,
            const Udp::endpoint &Remote) -> ngtcp2_path *;

    private:
        Role Role_;
        Net::any_io_executor Executor_;
        std::shared_ptr<Prism::Executor::FatalState> Fatal_;
        std::shared_ptr<Udp::socket> Socket_;
        std::shared_ptr<Prism::Contract::QuicDatagramSender> Sender_;
        Udp::endpoint Peer_;
        std::shared_ptr<Net::ssl::context> TlsContextOwner_;
        SSL_CTX *TlsContext_{nullptr};
        std::string ServerName_;
        ngtcp2_conn *Conn_{nullptr};
        SSL *Ssl_{nullptr};
        Prism::Quic::RandomSource Random_{};
        bool RandomFailed_{false};
        bool ExternalReceive_{false};
        std::string ExpectedAlpn_;
        std::string ExpectedServerName_;
        std::size_t MaxActiveBidirectionalStreams_{64};
        Prism::Quic::ServerOptions::EstablishedHandler OnEstablished_;
        Prism::Quic::ServerOptions::StreamHandler OnStream_;
        Prism::Quic::ServerOptions::UnidirectionalHandler OnUnidirectional_;
        Prism::Quic::ServerOptions::DatagramHandler OnDatagram_;
        Prism::Quic::ServerOptions::ClosedHandler OnClosed_;
        Prism::Quic::ServerOptions::ExporterHandler OnExporter_;
        Prism::Quic::ServerLifecycleHandler OnLifecycle_;
        bool CloseNotified_{false};
        ngtcp2_cid LocalCid_{};
        ngtcp2_cid RemoteCid_{};
        bool Started_{false};
        bool Closed_{false};
        bool HandshakeSignaled_{false};
        bool HandshakeResult_{false};
        bool Sending_{false};
        Prism::Fault::Failure SendFailure_{};
        bool ServerReady_{false};
        std::shared_ptr<SocketToken> SocketToken_;
        std::atomic<bool> SocketReadyAtomic_{false};
        std::atomic<bool> ReceiveLoopReadyAtomic_{false};
        std::atomic<bool> HandshakeReadyAtomic_{false};
        std::atomic<bool> ProtocolReadyAtomic_{false};
        std::atomic<bool> ClosedAtomic_{false};
        std::atomic<bool> NativeHandlesRetiredAtomic_{false};
        std::atomic<bool> CallbackOwnersRetiredAtomic_{false};
        std::atomic<bool> BoundedFailureAtomic_{false};
        std::atomic<std::uint64_t> DroppedDatagramsAtomic_{0};
        HandshakeChannel HandshakeNotify_;
        NotifyChannel IncomingNotify_;
        NotifyChannel IncomingUnidirectionalNotify_;
        NotifyChannel WritePermit_;
        NotifyChannel SendNotify_;
        NotifyChannel FlowNotify_;
        Net::steady_timer PumpTimer_;
        std::shared_ptr<DatagramState> Datagram_;
        std::deque<std::shared_ptr<StreamState>> IncomingStreams_;
        std::deque<std::shared_ptr<StreamState>> IncomingUnidirectionalStreams_;
        std::deque<OutboundPacket> Outbound_;
        std::unordered_map<std::int64_t, std::shared_ptr<StreamState>> Streams_;
        Prism::Lifecycle::DrainBarrier Loops_;
    };

    inline const SSL_QUIC_METHOD QuicMethod = {
        &NativeConnection::SetReadSecret,
        &NativeConnection::SetWriteSecret,
        &NativeConnection::AddHandshakeData,
        &NativeConnection::FlushFlight,
        &NativeConnection::SendAlert,
    };

} // namespace Prism::Quic::Detail
