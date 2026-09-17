/**
 * @file Native.cpp
 * @brief Preview 原生 ngtcp2 QUIC 连接实现
 */

#include <Preview/Protocols/Quic/Native.hpp>

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

namespace Preview::Quic::Detail
{

    namespace Net = boost::asio;
    using Udp = Net::ip::udp;

    class NativeConnection;

    [[nodiscard]] auto ToStdError(const Preview::Error ErrorCode) -> std::error_code
    {
        return {static_cast<int>(ErrorCode), std::generic_category()};
    }

    [[nodiscard]] auto ToStdError(const boost::system::error_code &ErrorCode) -> std::error_code
    {
        if (!ErrorCode)
        {
            return {};
        }
        return {ErrorCode.value(), std::generic_category()};
    }

    [[nodiscard]] auto Now() -> ngtcp2_tstamp
    {
        return static_cast<ngtcp2_tstamp>(std::chrono::duration_cast<std::chrono::microseconds>(
                                               std::chrono::steady_clock::now().time_since_epoch())
                                               .count());
    }

    struct SocketToken final
    {
    };

    struct SocketEntry final
    {
        std::weak_ptr<Udp::socket> Socket;
        std::shared_ptr<SocketToken> Token;
    };

    using SocketEntries = std::vector<SocketEntry>;

    std::atomic<std::shared_ptr<const SocketEntries>> ActiveSockets{
        std::make_shared<const SocketEntries>()};

    [[nodiscard]] auto AcquireSocketToken(const std::shared_ptr<Udp::socket> &Socket)
        -> std::shared_ptr<SocketToken>
    {
        if (!Socket)
        {
            return nullptr;
        }
        while (true)
        {
            auto Current = ActiveSockets.load(std::memory_order_acquire);
            auto Next = std::make_shared<SocketEntries>();
            for (const auto &Entry : *Current)
            {
                const auto ExistingSocket = Entry.Socket.lock();
                if (!ExistingSocket)
                {
                    continue;
                }
                if (ExistingSocket.get() == Socket.get())
                {
                    return nullptr;
                }
                Next->push_back(Entry);
            }
            auto Token = std::make_shared<SocketToken>();
            Next->push_back(SocketEntry{Socket, Token});
            std::shared_ptr<const SocketEntries> Desired = Next;
            if (ActiveSockets.compare_exchange_weak(
                    Current,
                    std::move(Desired),
                    std::memory_order_acq_rel,
                    std::memory_order_acquire))
            {
                return Token;
            }
        }
    }

    auto ReleaseSocketToken(
        const std::shared_ptr<Udp::socket> &Socket,
        const std::shared_ptr<SocketToken> &Token) -> void
    {
        if (!Socket || !Token)
        {
            return;
        }
        while (true)
        {
            auto Current = ActiveSockets.load(std::memory_order_acquire);
            auto Next = std::make_shared<SocketEntries>();
            for (const auto &Entry : *Current)
            {
                const auto ExistingSocket = Entry.Socket.lock();
                if (ExistingSocket && ExistingSocket.get() == Socket.get() && Entry.Token == Token)
                {
                    continue;
                }
                if (ExistingSocket)
                {
                    Next->push_back(Entry);
                }
            }
            std::shared_ptr<const SocketEntries> Desired = Next;
            if (ActiveSockets.compare_exchange_weak(
                    Current,
                    std::move(Desired),
                    std::memory_order_acq_rel,
                    std::memory_order_acquire))
            {
                return;
            }
        }
    }

    struct StreamState
    {
        StreamState(Net::any_io_executor ExecutorValue, const std::int64_t StreamIdValue)
            : Executor(std::move(ExecutorValue)), Id(StreamIdValue), Notify(Executor, 1)
        {
        }

        Net::any_io_executor Executor;
        std::int64_t Id;
        Net::experimental::channel<void(boost::system::error_code)> Notify;
        std::deque<std::vector<std::byte>> Received;
        std::weak_ptr<NativeConnection> Owner;
        bool PeerFin{false};
        bool Closed{false};
        bool LocalWriteClosed{false};
        bool Canceled{false};
    };

    struct DatagramState
    {
        explicit DatagramState(Net::any_io_executor ExecutorValue)
            : Executor(std::move(ExecutorValue)), Notify(Executor, 1)
        {
        }

        Net::any_io_executor Executor;
        Net::experimental::channel<void(boost::system::error_code)> Notify;
        std::deque<std::vector<std::byte>> Received;
        bool Closed{false};
        bool Canceled{false};
    };

    class NativeStream final : public StreamProvider
    {
    public:
        NativeStream(std::weak_ptr<NativeConnection> OwnerValue, std::shared_ptr<StreamState> StateValue)
            : Owner_(std::move(OwnerValue)), State_(std::move(StateValue))
        {
        }

        [[nodiscard]] auto Read(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override;

        [[nodiscard]] auto Write(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override;

        auto Close() -> void override;
        auto ShutdownWrite() -> void override;

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
        std::weak_ptr<NativeConnection> Owner_;
        std::shared_ptr<StreamState> State_;
    };

    class NativeDatagram final : public DatagramProvider
    {
    public:
        NativeDatagram(std::weak_ptr<NativeConnection> OwnerValue, std::shared_ptr<DatagramState> StateValue)
            : Owner_(std::move(OwnerValue)), State_(std::move(StateValue))
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
        std::weak_ptr<NativeConnection> Owner_;
        std::shared_ptr<DatagramState> State_;
    };

    class NativeConnection final : public std::enable_shared_from_this<NativeConnection>
    {
    public:
        enum class Role : std::uint8_t
        {
            Client,
            Server,
        };

        NativeConnection(Role ConnectionRole, Net::any_io_executor ExecutorValue,
                         std::shared_ptr<Udp::socket> SocketValue, Udp::endpoint PeerValue,
                         SSL_CTX *TlsContextValue, std::string ServerNameValue,
                         Preview::Quic::RandomSource RandomValue,
                         const bool ExternalReceiveValue = false,
                         std::string ExpectedAlpnValue = {},
                         std::string ExpectedServerNameValue = {},
                         const std::size_t MaxStreamsValue = 64,
                         const std::size_t MaxDatagramsValue = 64,
                         Preview::Quic::ServerOptions::EstablishedHandler Established = {},
                         Preview::Quic::ServerOptions::StreamHandler Stream = {},
                         Preview::Quic::ServerOptions::UnidirectionalHandler Unidirectional = {},
                         Preview::Quic::ServerOptions::DatagramHandler Datagram = {},
                         Preview::Quic::ServerOptions::ClosedHandler Closed = {},
                         Preview::Quic::ServerOptions::ExporterHandler Exporter = {})
            : Role_(ConnectionRole),
              Executor_(std::move(ExecutorValue)),
              Socket_(std::move(SocketValue)),
              Peer_(std::move(PeerValue)),
              TlsContext_(TlsContextValue),
              ServerName_(std::move(ServerNameValue)),
              Random_(std::move(RandomValue)),
              ExternalReceive_(ExternalReceiveValue),
              ExpectedAlpn_(std::move(ExpectedAlpnValue)),
              ExpectedServerName_(std::move(ExpectedServerNameValue)),
              MaxStreams_(MaxStreamsValue),
              MaxDatagrams_(MaxDatagramsValue),
              OnEstablished_(std::move(Established)),
              OnStream_(std::move(Stream)),
              OnUnidirectional_(std::move(Unidirectional)),
              OnDatagram_(std::move(Datagram)),
              OnClosed_(std::move(Closed)),
              OnExporter_(std::move(Exporter)),
              HandshakeNotify_(Executor_, 16),
              IncomingNotify_(Executor_, 1),
              IncomingUnidirectionalNotify_(Executor_, 1),
              WritePermit_(Executor_, 1),
              SendNotify_(Executor_, 16),
              FlowNotify_(Executor_, 16),
              PumpTimer_(Executor_),
              Datagram_(std::make_shared<DatagramState>(Executor_))
        {
            (void)WritePermit_.try_send(boost::system::error_code{});
        }

        ~NativeConnection() noexcept = default;

        NativeConnection(const NativeConnection &) = delete;
        auto operator=(const NativeConnection &) -> NativeConnection & = delete;

        auto Start() -> void;
        auto Close() -> void;

        [[nodiscard]] auto ReceivePacket(
            const Udp::endpoint &From,
            std::span<const std::byte> Data) -> bool;

        [[nodiscard]] auto WaitHandshake() -> Net::awaitable<bool>;
        [[nodiscard]] auto MarkProtocolReady() -> Net::awaitable<bool>;
        [[nodiscard]] auto OpenBidirectionalStream() -> Net::awaitable<SharedStreamProvider>;
        [[nodiscard]] auto OpenUnidirectionalStream() -> Net::awaitable<SharedStreamProvider>;
        [[nodiscard]] auto AcceptBidirectionalStream() -> Net::awaitable<SharedStreamProvider>;
        [[nodiscard]] auto AcceptUnidirectionalStream() -> Net::awaitable<SharedStreamProvider>;
        [[nodiscard]] auto ExportKeyingMaterial(
            std::span<std::uint8_t> Output,
            std::span<const std::uint8_t> Label,
            std::string_view Context) const -> bool;
        [[nodiscard]] auto DatagramProvider() -> SharedDatagramProvider;
        [[nodiscard]] auto Health() const noexcept -> Preview::Quic::NativeConnectionHealth;

        [[nodiscard]] auto WriteStream(
            std::int64_t StreamId,
            std::vector<std::byte> Data,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t>;
        [[nodiscard]] auto WriteDatagram(
            std::vector<std::byte> Data,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t>;

        auto CloseStream(const std::shared_ptr<StreamState> &State) -> void;
        auto ShutdownStreamWrite(const std::shared_ptr<StreamState> &State) -> void;
        auto CloseDatagram(const std::shared_ptr<DatagramState> &State) -> void;
        auto OnStreamReadConsumed(std::int64_t StreamId, std::size_t Bytes) -> void;

    private:
        enum class DecodeResult : std::uint8_t
        {
            Accepted,
            Ignored,
            Fatal,
        };

        struct OutboundPacket
        {
            std::vector<std::byte> Data;
            Udp::endpoint Peer;
        };

        using NotifyChannel = Net::experimental::channel<void(boost::system::error_code)>;
        using HandshakeChannel = Net::experimental::channel<void(boost::system::error_code, bool)>;

        [[nodiscard]] auto InitializeClient() -> bool;
        [[nodiscard]] auto InitializeServer(const ngtcp2_version_cid &VersionCid) -> bool;
        [[nodiscard]] auto InitializeTls(bool Server) -> bool;
        [[nodiscard]] auto FillRandom(std::uint8_t *Destination, std::size_t Length) const -> bool;
        [[nodiscard]] auto DecodeAndRead(
            const Udp::endpoint &From,
            std::span<const std::byte> Data) -> DecodeResult;

        [[nodiscard]] auto RunReceiveLoop() -> Net::awaitable<void>;
        [[nodiscard]] auto RunSendLoop() -> Net::awaitable<void>;
        [[nodiscard]] auto RunPumpLoop() -> Net::awaitable<void>;
        [[nodiscard]] auto WaitForSendDrain() -> Net::awaitable<bool>;
        auto QueueFlush() -> void;
        auto QueuePacket(
            const std::byte *Data,
            std::size_t Length,
            const Udp::endpoint &Peer) -> void;
        auto StartSendLoop() -> void;
        auto StartOnExecutor() -> void;
        auto CloseOnExecutor() -> void;
        auto SignalHandshake(bool Success) -> void;
        [[nodiscard]] auto AcceptsPacket(std::span<const std::byte> Data) const -> bool;

        [[nodiscard]] auto OpenStream(bool Unidirectional) -> Net::awaitable<SharedStreamProvider>;
        [[nodiscard]] auto MakeStream(std::int64_t StreamId, bool Incoming, bool Unidirectional)
            -> SharedStreamProvider;
        auto OnStreamOpen(std::int64_t StreamId) -> void;
        auto OnStreamData(
            std::int64_t StreamId,
            std::uint32_t Flags,
            const std::byte *Data,
            std::size_t Length) -> void;
        auto OnStreamClose(std::int64_t StreamId) -> void;
        auto OnDatagram(std::span<const std::byte> Data) -> void;
        auto OnHandshakeComplete() -> void;

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
        std::shared_ptr<Udp::socket> Socket_;
        Udp::endpoint Peer_;
        SSL_CTX *TlsContext_{nullptr};
        std::string ServerName_;
        ngtcp2_conn *Conn_{nullptr};
        SSL *Ssl_{nullptr};
        Preview::Quic::RandomSource Random_{};
        bool RandomFailed_{false};
        bool ExternalReceive_{false};
        std::string ExpectedAlpn_;
        std::string ExpectedServerName_;
        std::size_t MaxStreams_{64};
        std::size_t MaxDatagrams_{64};
        Preview::Quic::ServerOptions::EstablishedHandler OnEstablished_;
        Preview::Quic::ServerOptions::StreamHandler OnStream_;
        Preview::Quic::ServerOptions::UnidirectionalHandler OnUnidirectional_;
        Preview::Quic::ServerOptions::DatagramHandler OnDatagram_;
        Preview::Quic::ServerOptions::ClosedHandler OnClosed_;
        Preview::Quic::ServerOptions::ExporterHandler OnExporter_;
        bool CloseNotified_{false};
        ngtcp2_cid LocalCid_{};
        ngtcp2_cid RemoteCid_{};
        bool Started_{false};
        bool Closed_{false};
        bool HandshakeSignaled_{false};
        bool HandshakeResult_{false};
        bool Sending_{false};
        bool ServerReady_{false};
        std::shared_ptr<SocketToken> SocketToken_;
        std::atomic<bool> SocketReadyAtomic_{false};
        std::atomic<bool> ReceiveLoopReadyAtomic_{false};
        std::atomic<bool> HandshakeReadyAtomic_{false};
        std::atomic<bool> ProtocolReadyAtomic_{false};
        std::atomic<bool> ClosedAtomic_{false};
        std::atomic<bool> BoundedFailureAtomic_{false};
        HandshakeChannel HandshakeNotify_;
        NotifyChannel IncomingNotify_;
        NotifyChannel IncomingUnidirectionalNotify_;
        NotifyChannel WritePermit_;
        NotifyChannel SendNotify_;
        NotifyChannel FlowNotify_;
        Net::steady_timer PumpTimer_;
        std::shared_ptr<DatagramState> Datagram_;
        std::deque<SharedStreamProvider> IncomingStreams_;
        std::deque<SharedStreamProvider> IncomingUnidirectionalStreams_;
        std::deque<OutboundPacket> Outbound_;
        std::unordered_map<std::int64_t, std::shared_ptr<StreamState>> Streams_;
    };

    const SSL_QUIC_METHOD QuicMethod = {
        &NativeConnection::SetReadSecret,
        &NativeConnection::SetWriteSecret,
        &NativeConnection::AddHandshakeData,
        &NativeConnection::FlushFlight,
        &NativeConnection::SendAlert,
    };

    auto NativeStream::Read(
        const std::span<std::byte> Buffer,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        ErrorCode.clear();
        if (!State_ || Buffer.empty())
        {
            co_return 0;
        }
        co_await Net::dispatch(State_->Executor, Net::use_awaitable);
        while (true)
        {
            if (State_->Canceled)
            {
                State_->Canceled = false;
                ErrorCode = ToStdError(Preview::Error::Canceled);
                co_return 0;
            }
            if (!State_->Received.empty())
            {
                auto &Front = State_->Received.front();
                const auto Length = std::min(Buffer.size(), Front.size());
                std::memcpy(Buffer.data(), Front.data(), Length);
                if (Length == Front.size())
                {
                    State_->Received.pop_front();
                }
                else
                {
                    Front.erase(Front.begin(), Front.begin() + static_cast<std::ptrdiff_t>(Length));
                }
                if (Length != 0)
                {
                    if (const auto Owner = Owner_.lock())
                    {
                        Owner->OnStreamReadConsumed(State_->Id, Length);
                    }
                }
                co_return Length;
            }
            if (State_->Closed || State_->PeerFin)
            {
                co_return 0;
            }

            State_->Notify.reset();
            boost::system::error_code NotifyError;
            co_await State_->Notify.async_receive(Net::redirect_error(Net::use_awaitable, NotifyError));
            if (NotifyError && State_->Closed)
            {
                co_return 0;
            }
        }
    }

    auto NativeStream::Write(
        const std::span<const std::byte> Buffer,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        ErrorCode.clear();
        if (!State_)
        {
            ErrorCode = ToStdError(Preview::Error::BrokenPipe);
            co_return 0;
        }
        if (Buffer.empty())
        {
            co_return 0;
        }
        co_await Net::dispatch(State_->Executor, Net::use_awaitable);
        if (State_->Closed || State_->LocalWriteClosed)
        {
            ErrorCode = ToStdError(Preview::Error::BrokenPipe);
            co_return 0;
        }
        const auto Owner = Owner_.lock();
        if (!Owner)
        {
            ErrorCode = ToStdError(Preview::Error::BrokenPipe);
            co_return 0;
        }
        std::vector<std::byte> Copy(Buffer.begin(), Buffer.end());
        co_return co_await Owner->WriteStream(State_->Id, std::move(Copy), ErrorCode);
    }

    auto NativeStream::Close() -> void
    {
        if (!State_)
        {
            return;
        }
        auto State = State_;
        auto Owner = Owner_.lock();
        auto Close = [Owner = std::move(Owner), State = std::move(State)]() mutable -> void
        {
            if (!State || State->Closed)
            {
                return;
            }
            State->Closed = true;
            State->PeerFin = true;
            (void)State->Notify.try_send(boost::system::error_code{});
            if (Owner)
            {
                Owner->CloseStream(State);
            }
        };
        Net::dispatch(State_->Executor, std::move(Close));
    }

    auto NativeStream::ShutdownWrite() -> void
    {
        if (!State_)
        {
            return;
        }
        auto State = State_;
        auto Owner = Owner_.lock();
        auto Shutdown = [Owner = std::move(Owner), State = std::move(State)]() mutable -> void
        {
            if (!State || State->Closed || State->LocalWriteClosed)
            {
                return;
            }
            State->LocalWriteClosed = true;
            if (Owner)
            {
                Owner->ShutdownStreamWrite(State);
            }
        };
        Net::dispatch(State_->Executor, std::move(Shutdown));
    }

    auto NativeDatagram::Receive(
        const std::span<std::byte> Buffer,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        ErrorCode.clear();
        if (!State_ || Buffer.empty())
        {
            co_return 0;
        }
        co_await Net::dispatch(State_->Executor, Net::use_awaitable);
        while (true)
        {
            if (State_->Canceled)
            {
                State_->Canceled = false;
                ErrorCode = ToStdError(Preview::Error::Canceled);
                co_return 0;
            }
            if (!State_->Received.empty())
            {
                auto &Front = State_->Received.front();
                const auto Length = std::min(Buffer.size(), Front.size());
                std::memcpy(Buffer.data(), Front.data(), Length);
                State_->Received.pop_front();
                co_return Length;
            }
            if (State_->Closed)
            {
                ErrorCode = ToStdError(Preview::Error::BrokenPipe);
                co_return 0;
            }

            State_->Notify.reset();
            boost::system::error_code NotifyError;
            co_await State_->Notify.async_receive(Net::redirect_error(Net::use_awaitable, NotifyError));
            if (NotifyError && State_->Closed)
            {
                ErrorCode = ToStdError(Preview::Error::BrokenPipe);
                co_return 0;
            }
        }
    }

    auto NativeDatagram::Send(
        const std::span<const std::byte> Buffer,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        ErrorCode.clear();
        if (!State_)
        {
            ErrorCode = ToStdError(Preview::Error::BrokenPipe);
            co_return 0;
        }
        co_await Net::dispatch(State_->Executor, Net::use_awaitable);
        if (State_->Closed)
        {
            ErrorCode = ToStdError(Preview::Error::BrokenPipe);
            co_return 0;
        }
        const auto Owner = Owner_.lock();
        if (!Owner)
        {
            ErrorCode = ToStdError(Preview::Error::BrokenPipe);
            co_return 0;
        }
        std::vector<std::byte> Copy(Buffer.begin(), Buffer.end());
        co_return co_await Owner->WriteDatagram(std::move(Copy), ErrorCode);
    }

    auto NativeDatagram::Close() -> void
    {
        if (!State_)
        {
            return;
        }
        auto State = State_;
        auto Owner = Owner_.lock();
        auto Close = [Owner = std::move(Owner), State = std::move(State)]() mutable -> void
        {
            if (!State || State->Closed)
            {
                return;
            }
            State->Closed = true;
            (void)State->Notify.try_send(boost::system::error_code{});
            if (Owner)
            {
                Owner->CloseDatagram(State);
            }
        };
        Net::dispatch(State_->Executor, std::move(Close));
    }

    auto NativeDatagram::Cancel() -> void
    {
        if (!State_)
        {
            return;
        }
        auto State = State_;
        auto Cancel = [State = std::move(State)]() mutable -> void
        {
            if (!State || State->Closed)
            {
                return;
            }
            State->Canceled = true;
            (void)State->Notify.try_send(boost::system::error_code{});
        };
        Net::dispatch(State_->Executor, std::move(Cancel));
    }

    auto NativeConnection::Start() -> void
    {
        auto Self = shared_from_this();
        auto Start = [Self = std::move(Self)]() mutable -> void { Self->StartOnExecutor(); };
        Net::dispatch(Executor_, std::move(Start));
    }

    auto NativeConnection::StartOnExecutor() -> void
    {
        if (Started_ || Closed_)
        {
            return;
        }
        Started_ = true;
        if (!Socket_ || !Socket_->is_open())
        {
            SignalHandshake(false);
            CloseOnExecutor();
            return;
        }

        if (Socket_->get_executor() != Executor_)
        {
            BoundedFailureAtomic_.store(true, std::memory_order_release);
            CloseOnExecutor();
            return;
        }

        if (!ExternalReceive_)
        {
            SocketToken_ = AcquireSocketToken(Socket_);
            if (!SocketToken_)
            {
                BoundedFailureAtomic_.store(true, std::memory_order_release);
                CloseOnExecutor();
                return;
            }
        }
        SocketReadyAtomic_.store(true, std::memory_order_release);

        if (!TlsContext_)
        {
            SignalHandshake(false);
            CloseOnExecutor();
            return;
        }

        if (Role_ == Role::Client && (!InitializeClient() || !InitializeTls(false)))
        {
            SignalHandshake(false);
            CloseOnExecutor();
            return;
        }

        if (Role_ == Role::Client)
        {
            QueueFlush();
        }

        auto Self = shared_from_this();
        if (!ExternalReceive_)
        {
            Net::co_spawn(Executor_, [Self]() -> Net::awaitable<void> { co_await Self->RunReceiveLoop(); },
                          Net::detached);
        }
        Net::co_spawn(Executor_, [Self]() -> Net::awaitable<void> { co_await Self->RunPumpLoop(); },
                      Net::detached);
        ReceiveLoopReadyAtomic_.store(true, std::memory_order_release);
    }

    auto NativeConnection::Close() -> void
    {
        auto Self = shared_from_this();
        auto Close = [Self = std::move(Self)]() mutable -> void { Self->CloseOnExecutor(); };
        Net::dispatch(Executor_, std::move(Close));
    }

    auto NativeConnection::ReceivePacket(
        const Udp::endpoint &From,
        const std::span<const std::byte> Data) -> bool
    {
        // External-receive callers inject the first packet immediately after
        // scheduling Start(); initialize here as well so that a fatal first
        // packet cannot close a socket still owned by the ingress listener.
        if (!Started_)
        {
            StartOnExecutor();
        }
        if (!ExternalReceive_ || Closed_ || Data.empty())
        {
            return false;
        }
        const auto Result = DecodeAndRead(From, Data);
        if (Result == DecodeResult::Fatal)
        {
            SignalHandshake(false);
            CloseOnExecutor();
            return false;
        }
        return Result == DecodeResult::Accepted;
    }

    auto NativeConnection::WaitHandshake() -> Net::awaitable<bool>
    {
        const auto Self = shared_from_this();
        (void)Self;
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        if (HandshakeSignaled_)
        {
            co_return HandshakeResult_;
        }
        boost::system::error_code ReceiveError;
        const auto Result = co_await HandshakeNotify_.async_receive(
            Net::redirect_error(Net::use_awaitable, ReceiveError));
        if (ReceiveError)
        {
            co_return false;
        }
        co_return Result;
    }

    auto NativeConnection::MarkProtocolReady() -> Net::awaitable<bool>
    {
        const auto Self = shared_from_this();
        (void)Self;
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        if (Closed_ || !HandshakeSignaled_ || !HandshakeResult_)
        {
            co_return false;
        }
        ProtocolReadyAtomic_.store(true, std::memory_order_release);
        co_return true;
    }

    auto NativeConnection::OpenStream(const bool Unidirectional) -> Net::awaitable<SharedStreamProvider>
    {
        const auto Self = shared_from_this();
        (void)Self;
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        if ((!Unidirectional && Role_ != Role::Client) || Closed_ || !Conn_ || !HandshakeSignaled_ ||
            !HandshakeResult_)
        {
            co_return nullptr;
        }

        boost::system::error_code PermitError;
        co_await WritePermit_.async_receive(Net::redirect_error(Net::use_awaitable, PermitError));
        if (PermitError || Closed_ || !Conn_)
        {
            co_return nullptr;
        }

        std::int64_t StreamId = -1;
        int Result = 0;
        if (Unidirectional)
        {
            Result = ngtcp2_conn_open_uni_stream(Conn_, &StreamId, nullptr);
        }
        else
        {
            Result = ngtcp2_conn_open_bidi_stream(Conn_, &StreamId, nullptr);
        }
        SharedStreamProvider Provider;
        if (Result == 0)
        {
            Provider = MakeStream(StreamId, false, Unidirectional);
        }
        (void)WritePermit_.try_send(boost::system::error_code{});
        co_return Provider;
    }

    auto NativeConnection::OpenBidirectionalStream() -> Net::awaitable<SharedStreamProvider>
    {
        co_return co_await OpenStream(false);
    }

    auto NativeConnection::OpenUnidirectionalStream() -> Net::awaitable<SharedStreamProvider>
    {
        co_return co_await OpenStream(true);
    }

    auto NativeConnection::AcceptBidirectionalStream() -> Net::awaitable<SharedStreamProvider>
    {
        const auto Self = shared_from_this();
        (void)Self;
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        if (Role_ != Role::Server)
        {
            co_return nullptr;
        }
        while (true)
        {
            if (!IncomingStreams_.empty())
            {
                auto Stream = std::move(IncomingStreams_.front());
                IncomingStreams_.pop_front();
                co_return Stream;
            }
            if (Closed_)
            {
                co_return nullptr;
            }
            IncomingNotify_.reset();
            boost::system::error_code NotifyError;
            co_await IncomingNotify_.async_receive(Net::redirect_error(Net::use_awaitable, NotifyError));
            if (NotifyError && Closed_)
            {
                co_return nullptr;
            }
        }
    }

    auto NativeConnection::AcceptUnidirectionalStream() -> Net::awaitable<SharedStreamProvider>
    {
        const auto Self = shared_from_this();
        (void)Self;
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        while (true)
        {
            if (!IncomingUnidirectionalStreams_.empty())
            {
                auto Stream = std::move(IncomingUnidirectionalStreams_.front());
                IncomingUnidirectionalStreams_.pop_front();
                co_return Stream;
            }
            if (Closed_)
            {
                co_return nullptr;
            }
            IncomingUnidirectionalNotify_.reset();
            boost::system::error_code NotifyError;
            co_await IncomingUnidirectionalNotify_.async_receive(
                Net::redirect_error(Net::use_awaitable, NotifyError));
            if (NotifyError && Closed_)
            {
                co_return nullptr;
            }
        }
    }

    auto NativeConnection::ExportKeyingMaterial(
        std::span<std::uint8_t> Output,
        std::span<const std::uint8_t> Label,
        std::string_view Context) const -> bool
    {
        if (!Ssl_ || !HandshakeResult_ || Output.empty() || Label.empty())
        {
            return false;
        }
        return SSL_export_keying_material(
                   Ssl_, Output.data(), Output.size(), reinterpret_cast<const char *>(Label.data()), Label.size(),
                   reinterpret_cast<const std::uint8_t *>(Context.data()), Context.size(), 1) == 1;
    }

    auto NativeConnection::DatagramProvider() -> SharedDatagramProvider
    {
        if (ClosedAtomic_.load(std::memory_order_acquire) || !Datagram_)
        {
            return nullptr;
        }
        return std::make_shared<NativeDatagram>(weak_from_this(), Datagram_);
    }

    auto NativeConnection::Health() const noexcept -> Preview::Quic::NativeConnectionHealth
    {
        return {SocketReadyAtomic_.load(std::memory_order_acquire),
                ReceiveLoopReadyAtomic_.load(std::memory_order_acquire),
                HandshakeReadyAtomic_.load(std::memory_order_acquire),
                ProtocolReadyAtomic_.load(std::memory_order_acquire),
                ClosedAtomic_.load(std::memory_order_acquire),
                BoundedFailureAtomic_.load(std::memory_order_acquire)};
    }

    auto NativeConnection::WriteStream(
        const std::int64_t StreamId,
        std::vector<std::byte> Data,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        const auto Self = shared_from_this();
        (void)Self;
        ErrorCode.clear();
        if (Closed_ || !Conn_ || Data.empty())
        {
            if (Data.empty() && !Closed_ && Conn_)
            {
                co_return 0;
            }
            ErrorCode = ToStdError(Preview::Error::BrokenPipe);
            co_return 0;
        }

        boost::system::error_code PermitError;
        co_await WritePermit_.async_receive(Net::redirect_error(Net::use_awaitable, PermitError));
        if (PermitError || Closed_ || !Conn_)
        {
            ErrorCode = ToStdError(Preview::Error::BrokenPipe);
            co_return 0;
        }

        std::size_t Offset = 0;
        std::size_t RetryCount = 0;
        Net::steady_timer RetryTimer(Executor_);
        while (Offset < Data.size() && !Closed_ && Conn_)
        {
            std::array<std::byte, 65536> Packet{};
            ngtcp2_path_storage PathStorage{};
            auto Local = Socket_->local_endpoint();
            auto *Path = MakePath(PathStorage, Local, Peer_);
            ngtcp2_pkt_info PacketInfo{};
            ngtcp2_ssize Accepted = -1;
            ngtcp2_vec Vector{
                reinterpret_cast<std::uint8_t *>(Data.data() + Offset), Data.size() - Offset};
            const auto PacketLength = ngtcp2_conn_writev_stream(
                Conn_, Path, &PacketInfo, reinterpret_cast<std::uint8_t *>(Packet.data()), Packet.size(),
                &Accepted, NGTCP2_STREAM_DATA_FLAG_NONE, StreamId, &Vector, 1, Now());
            if (RandomFailed_)
            {
                ErrorCode = ToStdError(Preview::Error::IoError);
                break;
            }
            if (PacketLength == NGTCP2_ERR_WRITE_MORE)
            {
                if (Accepted <= 0 || static_cast<std::size_t>(Accepted) > Data.size() - Offset)
                {
                    ErrorCode = ToStdError(Preview::Error::IoError);
                    break;
                }
                Offset += static_cast<std::size_t>(Accepted);
                continue;
            }
            if (PacketLength == NGTCP2_ERR_STREAM_DATA_BLOCKED)
            {
                boost::system::error_code FlowError;
                co_await FlowNotify_.async_receive(Net::redirect_error(Net::use_awaitable, FlowError));
                if (FlowError || Closed_ || !Conn_)
                {
                    ErrorCode = ToStdError(Preview::Error::BrokenPipe);
                    break;
                }
                continue;
            }
            if (PacketLength < 0)
            {
                ErrorCode = ToStdError(Preview::Error::IoError);
                break;
            }
            if (Accepted > 0)
            {
                if (static_cast<std::size_t>(Accepted) > Data.size() - Offset)
                {
                    ErrorCode = ToStdError(Preview::Error::IoError);
                    break;
                }
                Offset += static_cast<std::size_t>(Accepted);
            }
            if (PacketLength > 0)
            {
                RetryCount = 0;
                QueuePacket(Packet.data(), static_cast<std::size_t>(PacketLength), Peer_);
            }
            if (PacketLength == 0 || Accepted == 0)
            {
                if (++RetryCount > 1000)
                {
                    ErrorCode = ToStdError(Preview::Error::IoError);
                    break;
                }
                RetryTimer.expires_after(std::chrono::milliseconds(1));
                boost::system::error_code TimerError;
                co_await RetryTimer.async_wait(Net::redirect_error(Net::use_awaitable, TimerError));
                if (TimerError || Closed_ || !Conn_)
                {
                    ErrorCode = ToStdError(Preview::Error::BrokenPipe);
                    break;
                }
            }
        }
        if (Conn_)
        {
            ngtcp2_conn_update_pkt_tx_time(Conn_, Now());
        }
        if (!ErrorCode && !co_await WaitForSendDrain())
        {
            ErrorCode = ToStdError(Preview::Error::BrokenPipe);
        }
        (void)WritePermit_.try_send(boost::system::error_code{});
        if (ErrorCode)
        {
            co_return Offset;
        }
        co_return Offset;
    }

    auto NativeConnection::WriteDatagram(
        std::vector<std::byte> Data,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        const auto Self = shared_from_this();
        (void)Self;
        ErrorCode.clear();
        if (Closed_ || !Conn_ || Data.empty())
        {
            if (Data.empty() && !Closed_ && Conn_)
            {
                co_return 0;
            }
            ErrorCode = ToStdError(Preview::Error::BrokenPipe);
            co_return 0;
        }

        boost::system::error_code PermitError;
        co_await WritePermit_.async_receive(Net::redirect_error(Net::use_awaitable, PermitError));
        if (PermitError || Closed_ || !Conn_)
        {
            ErrorCode = ToStdError(Preview::Error::BrokenPipe);
            co_return 0;
        }

        std::size_t RetryCount = 0;
        Net::steady_timer RetryTimer(Executor_);
        while (!Closed_ && Conn_ && RetryCount < 1000)
        {
            std::array<std::byte, 65536> Packet{};
            ngtcp2_path_storage PathStorage{};
            auto Local = Socket_->local_endpoint();
            auto *Path = MakePath(PathStorage, Local, Peer_);
            ngtcp2_pkt_info PacketInfo{};
            int Accepted = 0;
            const ngtcp2_vec Vector{
                reinterpret_cast<std::uint8_t *>(Data.data()), Data.size()};
            const auto PacketLength = ngtcp2_conn_writev_datagram(
                Conn_, Path, &PacketInfo, reinterpret_cast<std::uint8_t *>(Packet.data()), Packet.size(), &Accepted,
                NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 0, &Vector, 1, Now());
            if (RandomFailed_)
            {
                ErrorCode = ToStdError(Preview::Error::IoError);
                break;
            }
            if (PacketLength < 0)
            {
                ErrorCode = ToStdError(Preview::Error::IoError);
                break;
            }
            if (PacketLength > 0)
            {
                QueuePacket(Packet.data(), static_cast<std::size_t>(PacketLength), Peer_);
            }
            if (Accepted > 0)
            {
                ngtcp2_conn_update_pkt_tx_time(Conn_, Now());
                if (!co_await WaitForSendDrain())
                {
                    ErrorCode = ToStdError(Preview::Error::BrokenPipe);
                    (void)WritePermit_.try_send(boost::system::error_code{});
                    co_return 0;
                }
                (void)WritePermit_.try_send(boost::system::error_code{});
                co_return Data.size();
            }
            RetryTimer.expires_after(std::chrono::milliseconds(1));
            boost::system::error_code TimerError;
            co_await RetryTimer.async_wait(Net::redirect_error(Net::use_awaitable, TimerError));
            if (TimerError || Closed_ || !Conn_)
            {
                ErrorCode = ToStdError(Preview::Error::BrokenPipe);
                break;
            }
            ++RetryCount;
        }
        if (!ErrorCode)
        {
            ErrorCode = ToStdError(Preview::Error::IoError);
        }
        (void)WritePermit_.try_send(boost::system::error_code{});
        co_return 0;
    }

    auto NativeConnection::CloseStream(const std::shared_ptr<StreamState> &State) -> void
    {
        if (!State || Closed_)
        {
            return;
        }
        State->Closed = true;
        State->PeerFin = true;
        (void)State->Notify.try_send(boost::system::error_code{});
        if (Conn_)
        {
            (void)ngtcp2_conn_shutdown_stream(Conn_, 0, State->Id, 0);
            QueueFlush();
        }
    }

    auto NativeConnection::OnStreamReadConsumed(
        const std::int64_t StreamId,
        const std::size_t Bytes) -> void
    {
        if (Closed_ || !Conn_ || Bytes == 0)
        {
            return;
        }
        if (ngtcp2_conn_extend_max_stream_offset(Conn_, StreamId, Bytes) != 0)
        {
            CloseOnExecutor();
            return;
        }
        ngtcp2_conn_extend_max_offset(Conn_, Bytes);
        QueueFlush();
    }

    auto NativeConnection::ShutdownStreamWrite(const std::shared_ptr<StreamState> &State) -> void
    {
        if (!State || Closed_ || State->Closed || State->LocalWriteClosed == false)
        {
            return;
        }
        if (Conn_)
        {
            std::array<std::byte, 65536> Packet{};
            ngtcp2_path_storage PathStorage{};
            auto Local = Socket_->local_endpoint();
            auto *Path = MakePath(PathStorage, Local, Peer_);
            ngtcp2_pkt_info PacketInfo{};
            ngtcp2_ssize Accepted = -1;
            const auto PacketLength = ngtcp2_conn_writev_stream(
                Conn_, Path, &PacketInfo, reinterpret_cast<std::uint8_t *>(Packet.data()), Packet.size(), &Accepted,
                NGTCP2_WRITE_STREAM_FLAG_FIN, State->Id, nullptr, 0, Now());
            if (RandomFailed_)
            {
                CloseOnExecutor();
                return;
            }
            if (PacketLength > 0)
            {
                QueuePacket(Packet.data(), static_cast<std::size_t>(PacketLength), Peer_);
            }
            else if (PacketLength == NGTCP2_ERR_WRITE_MORE || Accepted > 0)
            {
                QueueFlush();
            }
            ngtcp2_conn_update_pkt_tx_time(Conn_, Now());
        }
    }

    auto NativeConnection::CloseDatagram(const std::shared_ptr<DatagramState> &State) -> void
    {
        if (State)
        {
            State->Closed = true;
            (void)State->Notify.try_send(boost::system::error_code{});
        }
    }

    auto NativeConnection::FillRandom(std::uint8_t *Destination, const std::size_t Length) const -> bool
    {
        if (Length == 0)
        {
            return true;
        }
        if (!Destination || Length > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
        {
            return false;
        }
        int Result = 0;
        if (Random_)
        {
            Result = Random_(Destination, static_cast<int>(Length));
        }
        else
        {
            Result = RAND_bytes(Destination, static_cast<int>(Length));
        }
        return Result == 1;
    }

    auto NativeConnection::InitializeClient() -> bool
    {
        if (!FillRandom(LocalCid_.data, 8) || !FillRandom(RemoteCid_.data, 8))
        {
            return false;
        }
        LocalCid_.datalen = 8;
        RemoteCid_.datalen = 8;

        ngtcp2_settings Settings;
        ngtcp2_settings_default(&Settings);
        Settings.initial_ts = Now();
        Settings.max_tx_udp_payload_size = 1472;
        Settings.rand_ctx.native_handle = this;

        ngtcp2_transport_params Params;
        ngtcp2_transport_params_default(&Params);
        Params.initial_max_stream_data_bidi_local = 65536;
        Params.initial_max_stream_data_bidi_remote = 65536;
        Params.initial_max_stream_data_uni = 65536;
        Params.initial_max_data = 1 << 20;
        Params.initial_max_streams_bidi = 1024;
        Params.initial_max_streams_uni = 1024;
        Params.max_datagram_frame_size = 1400;

        ngtcp2_path_storage PathStorage{};
        auto Local = Socket_->local_endpoint();
        auto *Path = MakePath(PathStorage, Local, Peer_);
        const auto Callbacks = MakeCallbacks(false);
        const auto Result = ngtcp2_conn_client_new(
            &Conn_, &RemoteCid_, &LocalCid_, Path, NGTCP2_PROTO_VER_V1, &Callbacks, &Settings, &Params, nullptr,
            this);
        return Result == 0 && !RandomFailed_;
    }

    auto NativeConnection::InitializeServer(const ngtcp2_version_cid &VersionCid) -> bool
    {
        if (VersionCid.dcidlen < NGTCP2_MIN_INITIAL_DCIDLEN || VersionCid.dcidlen > NGTCP2_MAX_CIDLEN ||
            VersionCid.scidlen > NGTCP2_MAX_CIDLEN || !VersionCid.dcid || !VersionCid.scid)
        {
            return false;
        }
        RemoteCid_.datalen = VersionCid.scidlen;
        std::memcpy(RemoteCid_.data, VersionCid.scid, VersionCid.scidlen);
        LocalCid_.datalen = 8;
        if (!FillRandom(LocalCid_.data, LocalCid_.datalen))
        {
            return false;
        }

        ngtcp2_cid OriginalDcid{};
        OriginalDcid.datalen = VersionCid.dcidlen;
        std::memcpy(OriginalDcid.data, VersionCid.dcid, VersionCid.dcidlen);

        ngtcp2_settings Settings;
        ngtcp2_settings_default(&Settings);
        Settings.initial_ts = Now();
        Settings.max_tx_udp_payload_size = 1472;
        Settings.rand_ctx.native_handle = this;

        ngtcp2_transport_params Params;
        ngtcp2_transport_params_default(&Params);
        Params.initial_max_stream_data_bidi_local = 65536;
        Params.initial_max_stream_data_bidi_remote = 65536;
        Params.initial_max_stream_data_uni = 65536;
        Params.initial_max_data = 1 << 20;
        Params.initial_max_streams_bidi = 1024;
        Params.initial_max_streams_uni = 1024;
        Params.max_datagram_frame_size = 1400;
        Params.original_dcid = OriginalDcid;
        Params.original_dcid_present = 1;
        Params.active_connection_id_limit = 2;

        ngtcp2_path_storage PathStorage{};
        auto Local = Socket_->local_endpoint();
        auto *Path = MakePath(PathStorage, Local, Peer_);
        const auto Callbacks = MakeCallbacks(true);
        const auto Result = ngtcp2_conn_server_new(
            &Conn_, &RemoteCid_, &LocalCid_, Path, NGTCP2_PROTO_VER_V1, &Callbacks, &Settings, &Params, nullptr,
            this);
        return Result == 0 && !RandomFailed_;
    }

    auto NativeConnection::InitializeTls(const bool Server) -> bool
    {
        Ssl_ = SSL_new(TlsContext_);
        if (!Ssl_ || SSL_set_quic_method(Ssl_, &QuicMethod) != 1)
        {
            return false;
        }
        SSL_set_app_data(Ssl_, this);
        if (SSL_set_min_proto_version(Ssl_, TLS1_3_VERSION) != 1 ||
            SSL_set_max_proto_version(Ssl_, TLS1_3_VERSION) != 1)
        {
            return false;
        }
        SSL_set_quic_use_legacy_codepoint(Ssl_, 0);
        if (Server)
        {
            SSL_set_accept_state(Ssl_);
        }
        else
        {
            SSL_set_connect_state(Ssl_);
            if (!ServerName_.empty() && SSL_set_tlsext_host_name(Ssl_, ServerName_.c_str()) != 1)
            {
                return false;
            }
        }

        std::array<std::uint8_t, 512> TransportParams{};
        const auto *LocalParams = ngtcp2_conn_get_local_transport_params2(Conn_);
        const auto TransportParamsLength =
            ngtcp2_transport_params_encode(TransportParams.data(), TransportParams.size(), LocalParams);
        if (TransportParamsLength < 0 ||
            SSL_set_quic_transport_params(Ssl_, TransportParams.data(),
                                           static_cast<std::size_t>(TransportParamsLength)) != 1)
        {
            return false;
        }

        ngtcp2_conn_set_tls_native_handle(Conn_, Ssl_);
        const auto Result = SSL_do_handshake(Ssl_);
        if (Result != 1)
        {
            const auto ErrorCode = SSL_get_error(Ssl_, Result);
            if (ErrorCode != SSL_ERROR_WANT_READ && ErrorCode != SSL_ERROR_WANT_WRITE)
            {
                return false;
            }
        }
        return true;
    }

    auto NativeConnection::DecodeAndRead(
        const Udp::endpoint &From,
        const std::span<const std::byte> Data) -> DecodeResult
    {
        if (Closed_ || Data.empty())
        {
            return DecodeResult::Ignored;
        }
        bool InitializedServer = false;
        if (Role_ == Role::Client && From != Peer_)
        {
            return DecodeResult::Ignored;
        }
        if (Role_ == Role::Server && !ServerReady_)
        {
            Peer_ = From;
            ngtcp2_version_cid VersionCid{};
            const auto Result = ngtcp2_pkt_decode_version_cid(
                &VersionCid, reinterpret_cast<const std::uint8_t *>(Data.data()), Data.size(), NGTCP2_MAX_CIDLEN);
            if (Result < 0 || VersionCid.version != NGTCP2_PROTO_VER_V1)
            {
                return DecodeResult::Ignored;
            }
            if (!InitializeServer(VersionCid) || !InitializeTls(true))
            {
                return DecodeResult::Fatal;
            }
            ServerReady_ = true;
            InitializedServer = true;
        }
        if (!Conn_ || !Ssl_)
        {
            return DecodeResult::Fatal;
        }
        if (ServerReady_ && !InitializedServer && !AcceptsPacket(Data))
        {
            return DecodeResult::Ignored;
        }

        ngtcp2_path_storage PathStorage{};
        auto Local = Socket_->local_endpoint();
        auto *Path = MakePath(PathStorage, Local, Peer_);
        ngtcp2_pkt_info PacketInfo{};
        const auto Result = ngtcp2_conn_read_pkt(
            Conn_, Path, &PacketInfo, reinterpret_cast<const std::uint8_t *>(Data.data()), Data.size(), Now());
        if (Result != 0 || RandomFailed_)
        {
            // Some Mihomo/HTTP3 clients send a padded Initial before the
            // ClientHello-bearing Initial. ngtcp2 reports ERR_RETRY when that
            // first packet contains no CRYPTO data. Keep this server owner
            // alive and wait for the following Initial instead of discarding
            // the connection before TLS has had a chance to start.
            if (Result == NGTCP2_ERR_RETRY && Role_ == Role::Server)
            {
                return DecodeResult::Accepted;
            }
            return DecodeResult::Fatal;
        }
        QueueFlush();
        (void)FlowNotify_.try_send(boost::system::error_code{});
        return DecodeResult::Accepted;
    }

    auto NativeConnection::AcceptsPacket(const std::span<const std::byte> Data) const -> bool
    {
        if (!Conn_ || Data.empty())
        {
            return false;
        }

        ngtcp2_pkt_hd Header{};
        ngtcp2_ssize HeaderLength = -1;
        const auto First = std::to_integer<std::uint8_t>(Data.front());
        if ((First & 0x80U) != 0U)
        {
            HeaderLength = ngtcp2_pkt_decode_hd_long(
                &Header, reinterpret_cast<const std::uint8_t *>(Data.data()), Data.size());
        }
        else
        {
            HeaderLength = ngtcp2_pkt_decode_hd_short(
                &Header,
                reinterpret_cast<const std::uint8_t *>(Data.data()),
                Data.size(),
                LocalCid_.datalen);
        }
        if (HeaderLength < 0)
        {
            return false;
        }

        if (ngtcp2_cid_eq(&Header.dcid, &LocalCid_) != 0)
        {
            return true;
        }
        if (const auto *InitialCid = ngtcp2_conn_get_client_initial_dcid2(Conn_);
            InitialCid && ngtcp2_cid_eq(&Header.dcid, InitialCid) != 0)
        {
            return true;
        }

        constexpr std::size_t MaxTrackedCids = 8;
        std::array<ngtcp2_cid, MaxTrackedCids> Scids{};
        const auto Count = ngtcp2_conn_get_scid2(Conn_, nullptr);
        if (Count > Scids.size())
        {
            return false;
        }
        if (Count != 0U)
        {
            const auto Written = ngtcp2_conn_get_scid2(Conn_, Scids.data());
            for (std::size_t Index = 0; Index < Written; ++Index)
            {
                if (ngtcp2_cid_eq(&Header.dcid, &Scids[Index]) != 0)
                {
                    return true;
                }
            }
        }
        return false;
    }

    auto NativeConnection::RunReceiveLoop() -> Net::awaitable<void>
    {
        std::array<std::byte, 65536> Buffer{};
        while (!Closed_ && Socket_ && Socket_->is_open())
        {
            Udp::endpoint From;
            boost::system::error_code ReceiveError;
            const auto Length = co_await Socket_->async_receive_from(
                Net::buffer(Buffer), From, Net::redirect_error(Net::use_awaitable, ReceiveError));
            if (ReceiveError)
            {
                break;
            }
            const auto Result = DecodeAndRead(From, std::span<const std::byte>(Buffer.data(), Length));
            if (Result == DecodeResult::Fatal)
            {
                SignalHandshake(false);
                CloseOnExecutor();
                break;
            }
        }
        if (!Closed_)
        {
            SignalHandshake(false);
            CloseOnExecutor();
        }
    }

    auto NativeConnection::RunSendLoop() -> Net::awaitable<void>
    {
        while (!Closed_ && Socket_ && Socket_->is_open() && !Outbound_.empty())
        {
            auto Packet = std::move(Outbound_.front());
            Outbound_.pop_front();
            boost::system::error_code SendError;
            const auto Length = co_await Socket_->async_send_to(
                Net::buffer(Packet.Data), Packet.Peer, Net::redirect_error(Net::use_awaitable, SendError));
            if (SendError || Length != Packet.Data.size())
            {
                CloseOnExecutor();
                break;
            }
        }
        Sending_ = false;
        for (std::size_t Index = 0; Index < 16; ++Index)
        {
            (void)SendNotify_.try_send(boost::system::error_code{});
        }
    }

    auto NativeConnection::WaitForSendDrain() -> Net::awaitable<bool>
    {
        while (!Closed_ && (Sending_ || !Outbound_.empty()))
        {
            SendNotify_.reset();
            boost::system::error_code NotifyError;
            co_await SendNotify_.async_receive(Net::redirect_error(Net::use_awaitable, NotifyError));
            if (NotifyError && Closed_)
            {
                co_return false;
            }
        }
        co_return !Closed_;
    }

    auto NativeConnection::RunPumpLoop() -> Net::awaitable<void>
    {
        while (!Closed_ && !RandomFailed_)
        {
            auto Delay = std::chrono::milliseconds(100);
            if (Conn_)
            {
                const auto Current = Now();
                const auto Expiry = ngtcp2_conn_get_expiry2(Conn_);
                if (Expiry != std::numeric_limits<ngtcp2_tstamp>::max())
                {
                    if (Expiry <= Current)
                    {
                        const auto Result = ngtcp2_conn_handle_expiry(Conn_, Current);
                        if (Result != 0 || RandomFailed_)
                        {
                            CloseOnExecutor();
                            co_return;
                        }
                        QueueFlush();
                        continue;
                    }
                    const auto Remaining = Expiry - Current;
                    Delay = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::microseconds(Remaining));
                    if (Delay <= std::chrono::milliseconds::zero())
                    {
                        Delay = std::chrono::milliseconds(1);
                    }
                    Delay = std::min(Delay, std::chrono::milliseconds(100));
                }
            }
            PumpTimer_.expires_after(Delay);
            boost::system::error_code TimerError;
            co_await PumpTimer_.async_wait(Net::redirect_error(Net::use_awaitable, TimerError));
            if (Closed_)
            {
                co_return;
            }
            if (!TimerError && Conn_)
            {
                const auto Current = Now();
                if (ngtcp2_conn_get_expiry2(Conn_) <= Current)
                {
                    const auto Result = ngtcp2_conn_handle_expiry(Conn_, Current);
                    if (Result != 0 || RandomFailed_)
                    {
                        CloseOnExecutor();
                        co_return;
                    }
                }
                QueueFlush();
            }
        }
        if (RandomFailed_ && !Closed_)
        {
            CloseOnExecutor();
        }
    }

    auto NativeConnection::QueueFlush() -> void
    {
        if (Closed_ || RandomFailed_ || !Conn_ || !Socket_ || !Socket_->is_open())
        {
            if (RandomFailed_ && !Closed_)
            {
                CloseOnExecutor();
            }
            return;
        }
        for (std::size_t Count = 0; Count < 128; ++Count)
        {
            std::array<std::byte, 65536> Packet{};
            ngtcp2_path_storage PathStorage{};
            auto Local = Socket_->local_endpoint();
            auto *Path = MakePath(PathStorage, Local, Peer_);
            ngtcp2_pkt_info PacketInfo{};
            const auto Length = ngtcp2_conn_write_pkt(
                Conn_, Path, &PacketInfo, reinterpret_cast<std::uint8_t *>(Packet.data()), Packet.size(), Now());
            if (RandomFailed_)
            {
                CloseOnExecutor();
                return;
            }
            if (Length == NGTCP2_ERR_WRITE_MORE || Length <= 0)
            {
                break;
            }
            QueuePacket(Packet.data(), static_cast<std::size_t>(Length), Peer_);
        }
        ngtcp2_conn_update_pkt_tx_time(Conn_, Now());
    }

    auto NativeConnection::QueuePacket(
        const std::byte *Data,
        const std::size_t Length,
        const Udp::endpoint &Peer) -> void
    {
        if (Closed_ || Length == 0)
        {
            return;
        }
        Outbound_.push_back(OutboundPacket{std::vector<std::byte>(Data, Data + Length), Peer});
        StartSendLoop();
    }

    auto NativeConnection::StartSendLoop() -> void
    {
        if (Sending_ || Closed_ || Outbound_.empty())
        {
            return;
        }
        Sending_ = true;
        auto Self = shared_from_this();
        Net::co_spawn(Executor_, [Self]() -> Net::awaitable<void> { co_await Self->RunSendLoop(); },
                      Net::detached);
    }

    auto NativeConnection::CloseOnExecutor() -> void
    {
        if (Closed_ && !Conn_ && !Ssl_ && !SocketToken_)
        {
            return;
        }
        Closed_ = true;
        if (!CloseNotified_)
        {
            CloseNotified_ = true;
            if (OnClosed_)
            {
                try
                {
                    OnClosed_();
                }
                catch (...)
                {
                }
            }
        }
        ClosedAtomic_.store(true, std::memory_order_release);
        SocketReadyAtomic_.store(false, std::memory_order_release);
        ReceiveLoopReadyAtomic_.store(false, std::memory_order_release);
        HandshakeReadyAtomic_.store(false, std::memory_order_release);
        ProtocolReadyAtomic_.store(false, std::memory_order_release);
        SignalHandshake(false);
        if (Socket_ && !ExternalReceive_ && (SocketToken_ || !Started_))
        {
            boost::system::error_code ErrorCode;
            Socket_->cancel(ErrorCode);
            Socket_->close(ErrorCode);
        }
        if (SocketToken_)
        {
            ReleaseSocketToken(Socket_, SocketToken_);
            SocketToken_.reset();
        }
        PumpTimer_.cancel();
        IncomingNotify_.cancel();
        IncomingUnidirectionalNotify_.cancel();
        HandshakeNotify_.cancel();
        WritePermit_.cancel();
        SendNotify_.cancel();
        FlowNotify_.cancel();
        for (const auto &[StreamId, State] : Streams_)
        {
            (void)StreamId;
            if (State)
            {
                State->Closed = true;
                State->PeerFin = true;
                State->Notify.cancel();
            }
        }
        if (Datagram_)
        {
            Datagram_->Closed = true;
            Datagram_->Notify.cancel();
        }
        IncomingStreams_.clear();
        IncomingUnidirectionalStreams_.clear();
        Outbound_.clear();
        if (Conn_)
        {
            ngtcp2_conn_del(Conn_);
            Conn_ = nullptr;
        }
        if (Ssl_)
        {
            SSL_set_app_data(Ssl_, nullptr);
            SSL_free(Ssl_);
            Ssl_ = nullptr;
        }
    }

    auto NativeConnection::SignalHandshake(const bool Success) -> void
    {
        if (HandshakeSignaled_)
        {
            return;
        }
        HandshakeSignaled_ = true;
        HandshakeResult_ = Success;
        HandshakeReadyAtomic_.store(Success, std::memory_order_release);
        for (std::size_t Index = 0; Index < 16; ++Index)
        {
            (void)HandshakeNotify_.try_send(boost::system::error_code{}, Success);
        }
    }

    auto NativeConnection::MakeStream(const std::int64_t StreamId, const bool Incoming,
                                      const bool Unidirectional) -> SharedStreamProvider
    {
        auto State = std::make_shared<StreamState>(Executor_, StreamId);
        State->Owner = weak_from_this();
        auto Provider = std::make_shared<NativeStream>(weak_from_this(), State);
        Streams_[StreamId] = std::move(State);
        if (Incoming)
        {
            if (Unidirectional)
            {
                IncomingUnidirectionalStreams_.push_back(Provider);
                (void)IncomingUnidirectionalNotify_.try_send(boost::system::error_code{});
                if (OnUnidirectional_)
                {
                    try
                    {
                        OnUnidirectional_(Provider);
                    }
                    catch (...)
                    {
                    }
                }
            }
            else
            {
                IncomingStreams_.push_back(Provider);
                (void)IncomingNotify_.try_send(boost::system::error_code{});
                if (OnStream_)
                {
                    try
                    {
                        OnStream_(Provider);
                    }
                    catch (...)
                    {
                    }
                }
            }
        }
        return Provider;
    }

    auto NativeConnection::OnStreamOpen(const std::int64_t StreamId) -> void
    {
        if (Streams_.contains(StreamId))
        {
            return;
        }
        const bool Unidirectional = (StreamId & 2) != 0;
        bool PeerInitiated = false;
        if (Role_ == Role::Server)
        {
            PeerInitiated = (StreamId & 1) == 0;
        }
        else
        {
            PeerInitiated = (StreamId & 1) == 1;
        }
        (void)MakeStream(StreamId, PeerInitiated, Unidirectional);
    }

    auto NativeConnection::OnStreamData(
        const std::int64_t StreamId,
        const std::uint32_t Flags,
        const std::byte *Data,
        const std::size_t Length) -> void
    {
        if (!Streams_.contains(StreamId))
        {
            OnStreamOpen(StreamId);
        }
        const auto StreamIterator = Streams_.find(StreamId);
        if (StreamIterator == Streams_.end() || !StreamIterator->second)
        {
            return;
        }
        auto &State = StreamIterator->second;
        if (Length != 0)
        {
            State->Received.emplace_back(Data, Data + Length);
        }
        if ((Flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0)
        {
            State->PeerFin = true;
        }
        (void)State->Notify.try_send(boost::system::error_code{});
    }

    auto NativeConnection::OnStreamClose(const std::int64_t StreamId) -> void
    {
        const auto StreamIterator = Streams_.find(StreamId);
        if (StreamIterator == Streams_.end() || !StreamIterator->second)
        {
            return;
        }
        StreamIterator->second->PeerFin = true;
        (void)StreamIterator->second->Notify.try_send(boost::system::error_code{});
    }

    auto NativeConnection::OnDatagram(const std::span<const std::byte> Data) -> void
    {
        if (!Datagram_ || Datagram_->Closed)
        {
            return;
        }
        Datagram_->Received.emplace_back(Data.begin(), Data.end());
        (void)Datagram_->Notify.try_send(boost::system::error_code{});
    }

    auto NativeConnection::OnHandshakeComplete() -> void
    {
        std::string Alpn;
        const unsigned char *Selected = nullptr;
        unsigned int Length = 0;
        if (Ssl_)
        {
            SSL_get0_alpn_selected(Ssl_, &Selected, &Length);
        }
        if (Selected != nullptr && Length != 0U)
        {
            Alpn.assign(reinterpret_cast<const char *>(Selected), Length);
        }
        if (!ExpectedAlpn_.empty() && Alpn != ExpectedAlpn_)
        {
            SignalHandshake(false);
            CloseOnExecutor();
            return;
        }
        if (!ExpectedServerName_.empty())
        {
            const auto *ServerName = Ssl_ ? SSL_get_servername(
                                                Ssl_, TLSEXT_NAMETYPE_host_name)
                                          : nullptr;
            if (!ServerName || ExpectedServerName_ != ServerName)
            {
                SignalHandshake(false);
                CloseOnExecutor();
                return;
            }
        }
        SignalHandshake(true);
        if (OnExporter_)
        {
            try
            {
                const std::weak_ptr<NativeConnection> Weak = weak_from_this();
                OnExporter_([Weak](std::span<std::uint8_t> Output,
                                   std::span<const std::uint8_t> Label,
                                   std::string_view Context) -> bool
                {
                    const auto Owner = Weak.lock();
                    return Owner && Owner->ExportKeyingMaterial(Output, Label, Context);
                });
            }
            catch (...)
            {
            }
        }
        if (OnEstablished_)
        {
            try
            {
                OnEstablished_(std::move(Alpn));
            }
            catch (...)
            {
            }
        }
        if (OnDatagram_)
        {
            try
            {
                OnDatagram_(DatagramProvider());
            }
            catch (...)
            {
            }
        }
    }

    auto NativeConnection::MakeCallbacks(const bool Server) -> ngtcp2_callbacks
    {
        ngtcp2_callbacks Callbacks{};
        if (Server)
        {
            Callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
        }
        else
        {
            Callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
        }
        Callbacks.recv_crypto_data = &NativeConnection::RecvCryptoData;
        Callbacks.handshake_completed = &NativeConnection::HandshakeCompleted;
        Callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
        Callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
        Callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
        Callbacks.recv_stream_data = &NativeConnection::RecvStreamData;
        Callbacks.stream_open = &NativeConnection::StreamOpen;
        Callbacks.stream_close = &NativeConnection::StreamClose;
        Callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
        Callbacks.rand = &NativeConnection::Random;
        Callbacks.get_new_connection_id = &NativeConnection::NewConnectionId;
        Callbacks.update_key = ngtcp2_crypto_update_key_cb;
        Callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        Callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        Callbacks.recv_datagram = &NativeConnection::RecvDatagram;
        Callbacks.ack_datagram = &NativeConnection::AckDatagram;
        Callbacks.get_path_challenge_data = &NativeConnection::PathChallenge;
        Callbacks.version_negotiation = &NativeConnection::VersionNegotiation;
        return Callbacks;
    }

    int NativeConnection::SetReadSecret(
        SSL *Ssl,
        const ssl_encryption_level_t Level,
        const SSL_CIPHER *Cipher,
        const std::uint8_t *Secret,
        const std::size_t SecretLength)
    {
        (void)Cipher;
        auto *Connection = static_cast<NativeConnection *>(SSL_get_app_data(Ssl));
        if (!Connection || !Connection->Conn_)
        {
            return 0;
        }
        const auto Result = ngtcp2_crypto_derive_and_install_rx_key(
            Connection->Conn_, nullptr, nullptr, nullptr,
            ngtcp2_crypto_boringssl_from_ssl_encryption_level(Level), Secret, SecretLength);
        if (Result == 0)
        {
            return 1;
        }
        return 0;
    }

    int NativeConnection::SetWriteSecret(
        SSL *Ssl,
        const ssl_encryption_level_t Level,
        const SSL_CIPHER *Cipher,
        const std::uint8_t *Secret,
        const std::size_t SecretLength)
    {
        (void)Cipher;
        auto *Connection = static_cast<NativeConnection *>(SSL_get_app_data(Ssl));
        if (!Connection || !Connection->Conn_)
        {
            return 0;
        }
        const auto Result = ngtcp2_crypto_derive_and_install_tx_key(
            Connection->Conn_, nullptr, nullptr, nullptr,
            ngtcp2_crypto_boringssl_from_ssl_encryption_level(Level), Secret, SecretLength);
        if (Result == 0)
        {
            return 1;
        }
        return 0;
    }

    int NativeConnection::AddHandshakeData(
        SSL *Ssl,
        const ssl_encryption_level_t Level,
        const std::uint8_t *Data,
        const std::size_t Length)
    {
        auto *Connection = static_cast<NativeConnection *>(SSL_get_app_data(Ssl));
        if (!Connection || !Connection->Conn_)
        {
            return 0;
        }
        const auto Result = ngtcp2_conn_submit_crypto_data(
            Connection->Conn_, ngtcp2_crypto_boringssl_from_ssl_encryption_level(Level), Data, Length);
        if (Result == 0)
        {
            return 1;
        }
        return 0;
    }

    int NativeConnection::FlushFlight(SSL *Ssl)
    {
        if (SSL_get_app_data(Ssl) != nullptr)
        {
            return 1;
        }
        return 0;
    }

    int NativeConnection::SendAlert(
        SSL *Ssl,
        ssl_encryption_level_t Level,
        std::uint8_t Alert)
    {
        (void)Level;
        (void)Alert;
        if (SSL_get_app_data(Ssl) != nullptr)
        {
            return 1;
        }
        return 0;
    }

    int NativeConnection::HandshakeCompleted(ngtcp2_conn *Conn, void *UserData)
    {
        (void)Conn;
        auto *Connection = static_cast<NativeConnection *>(UserData);
        if (Connection)
        {
            Connection->OnHandshakeComplete();
        }
        return 0;
    }

    int NativeConnection::RecvCryptoData(
        ngtcp2_conn *Conn,
        const ngtcp2_encryption_level Level,
        const std::uint64_t Offset,
        const std::uint8_t *Data,
        const std::size_t Length,
        void *UserData)
    {
        const auto Result = ngtcp2_crypto_recv_crypto_data_cb(Conn, Level, Offset, Data, Length, UserData);
        return Result;
    }

    int NativeConnection::RecvStreamData(
        ngtcp2_conn *Conn,
        const std::uint32_t Flags,
        const std::int64_t StreamId,
        const std::uint64_t Offset,
        const std::uint8_t *Data,
        const std::size_t Length,
        void *UserData,
        void *StreamUserData)
    {
        (void)Conn;
        (void)Offset;
        (void)StreamUserData;
        auto *Connection = static_cast<NativeConnection *>(UserData);
        if (Connection)
        {
            Connection->OnStreamData(StreamId, Flags, reinterpret_cast<const std::byte *>(Data), Length);
        }
        return 0;
    }

    int NativeConnection::StreamOpen(
        ngtcp2_conn *Conn,
        const std::int64_t StreamId,
        void *UserData)
    {
        (void)Conn;
        auto *Connection = static_cast<NativeConnection *>(UserData);
        if (Connection)
        {
            Connection->OnStreamOpen(StreamId);
        }
        return 0;
    }

    int NativeConnection::StreamClose(
        ngtcp2_conn *Conn,
        const std::uint32_t Flags,
        const std::int64_t StreamId,
        const std::uint64_t AppErrorCode,
        void *UserData,
        void *StreamUserData)
    {
        (void)Conn;
        (void)Flags;
        (void)AppErrorCode;
        (void)StreamUserData;
        auto *Connection = static_cast<NativeConnection *>(UserData);
        if (Connection)
        {
            Connection->OnStreamClose(StreamId);
        }
        return 0;
    }

    int NativeConnection::RecvDatagram(
        ngtcp2_conn *Conn,
        const std::uint32_t Flags,
        const std::uint8_t *Data,
        const std::size_t Length,
        void *UserData)
    {
        (void)Conn;
        (void)Flags;
        auto *Connection = static_cast<NativeConnection *>(UserData);
        if (Connection)
        {
            Connection->OnDatagram(std::span<const std::byte>(reinterpret_cast<const std::byte *>(Data), Length));
        }
        return 0;
    }

    int NativeConnection::AckDatagram(
        ngtcp2_conn *Conn,
        const std::uint64_t DatagramId,
        void *UserData)
    {
        (void)Conn;
        (void)DatagramId;
        (void)UserData;
        return 0;
    }

    int NativeConnection::RecvRetry(
        ngtcp2_conn *Conn,
        const ngtcp2_pkt_hd *Header,
        void *UserData)
    {
        (void)Conn;
        (void)Header;
        (void)UserData;
        return 0;
    }

    int NativeConnection::VersionNegotiation(
        ngtcp2_conn *Conn,
        const std::uint32_t Version,
        const ngtcp2_cid *ClientDcid,
        void *UserData)
    {
        (void)Conn;
        (void)Version;
        (void)ClientDcid;
        (void)UserData;
        return 0;
    }

    auto NativeConnection::Random(
        std::uint8_t *Destination,
        const std::size_t Length,
        const ngtcp2_rand_ctx *Context) -> void
    {
        NativeConnection *Connection = nullptr;
        if (Context)
        {
            Connection = static_cast<NativeConnection *>(Context->native_handle);
        }
        bool Success = false;
        if (Connection)
        {
            Success = Connection->FillRandom(Destination, Length);
        }
        else if (Length == 0)
        {
            Success = true;
        }
        else if (Destination &&
                 Length <= static_cast<std::size_t>((std::numeric_limits<int>::max)()) &&
                 RAND_bytes(Destination, static_cast<int>(Length)) == 1)
        {
            Success = true;
        }
        if (!Success)
        {
            if (Destination && Length > 0)
            {
                std::fill_n(Destination, Length, std::uint8_t{0});
            }
            if (Connection)
            {
                Connection->RandomFailed_ = true;
            }
        }
    }

    int NativeConnection::NewConnectionId(
        ngtcp2_conn *Conn,
        ngtcp2_cid *Cid,
        std::uint8_t *Token,
        const std::size_t CidLength,
        void *UserData)
    {
        (void)Conn;
        auto *Connection = static_cast<NativeConnection *>(UserData);
        if (!Cid || CidLength > NGTCP2_MAX_CIDLEN || !Connection || !Connection->FillRandom(Cid->data, CidLength))
        {
            if (Connection)
            {
                Connection->RandomFailed_ = true;
            }
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        Cid->datalen = CidLength;
        if (Token && !Connection->FillRandom(Token, NGTCP2_STATELESS_RESET_TOKENLEN))
        {
            Connection->RandomFailed_ = true;
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    int NativeConnection::PathChallenge(
        ngtcp2_conn *Conn,
        std::uint8_t *Data,
        void *UserData)
    {
        (void)Conn;
        auto *Connection = static_cast<NativeConnection *>(UserData);
        if (Data && Connection && Connection->FillRandom(Data, NGTCP2_PATH_CHALLENGE_DATALEN))
        {
            return 0;
        }
        if (Connection)
        {
            Connection->RandomFailed_ = true;
        }
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    auto NativeConnection::MakePath(
        ngtcp2_path_storage &Storage,
        const Udp::endpoint &Local,
        const Udp::endpoint &Remote) -> ngtcp2_path *
    {
        ngtcp2_path_storage_init(&Storage, reinterpret_cast<const ngtcp2_sockaddr *>(Local.data()), Local.size(),
                                 reinterpret_cast<const ngtcp2_sockaddr *>(Remote.data()), Remote.size(), nullptr);
        return &Storage.path;
    }

} // namespace Preview::Quic::Detail

namespace Preview::Quic
{

    Client::Client(const ClientOptions &Options)
        : Connection_(std::make_shared<Detail::NativeConnection>(Detail::NativeConnection::Role::Client,
                                                                  Options.Executor, Options.Socket,
                                                                  Options.Peer, Options.TlsContext,
                                                                  Options.ServerName,
                                                                  Options.Random))
    {
    }

    Client::~Client() noexcept
    {
        if (Connection_)
        {
            Connection_->Close();
        }
    }

    auto Client::Start() -> void
    {
        if (Connection_)
        {
            Connection_->Start();
        }
    }

    auto Client::WaitHandshake() -> Net::awaitable<bool>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return false;
        }
        co_return co_await Connection->WaitHandshake();
    }

    auto Client::MarkProtocolReady() -> Net::awaitable<bool>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return false;
        }
        co_return co_await Connection->MarkProtocolReady();
    }

    auto Client::OpenBidirectionalStream() -> Net::awaitable<SharedStreamProvider>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return nullptr;
        }
        co_return co_await Connection->OpenBidirectionalStream();
    }

    auto Client::OpenUnidirectionalStream() -> Net::awaitable<SharedStreamProvider>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return nullptr;
        }
        co_return co_await Connection->OpenUnidirectionalStream();
    }

    auto Client::AcceptUnidirectionalStream() -> Net::awaitable<SharedStreamProvider>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return nullptr;
        }
        co_return co_await Connection->AcceptUnidirectionalStream();
    }

    auto Client::ExportKeyingMaterial(
        std::span<std::uint8_t> Output,
        std::span<const std::uint8_t> Label,
        std::string_view Context) const -> bool
    {
        return Connection_ && Connection_->ExportKeyingMaterial(Output, Label, Context);
    }

    auto Client::Datagram() const -> SharedDatagramProvider
    {
        if (Connection_)
        {
            return Connection_->DatagramProvider();
        }
        return nullptr;
    }

    auto Client::Close() -> void
    {
        if (Connection_)
        {
            Connection_->Close();
        }
    }

    auto Client::Health() const noexcept -> NativeConnectionHealth
    {
        return Connection_ ? Connection_->Health() : NativeConnectionHealth{.Closed = true};
    }

    Server::Server(const ServerOptions &Options)
        : Connection_(std::make_shared<Detail::NativeConnection>(Detail::NativeConnection::Role::Server,
                                                                  Options.Executor, Options.Socket,
                                                                  Net::ip::udp::endpoint{},
                                                                  Options.TlsContext, std::string{},
                                                                  Options.Random,
                                                                  Options.ExternalReceive,
                                                                  Options.ExpectedAlpn,
                                                                  Options.ExpectedServerName,
                                                                  Options.MaxStreams,
                                                                  Options.MaxDatagrams,
                                                                  Options.OnEstablished,
                                                                  Options.OnStream,
                                                                  Options.OnUnidirectional,
                                                                  Options.OnDatagram,
                                                                  Options.OnClosed,
                                                                  Options.OnExporter)),
          OnStarted_(Options.OnStarted)
    {
    }

    Server::~Server() noexcept
    {
        if (Connection_)
        {
            Connection_->Close();
        }
    }

    auto Server::Start() -> void
    {
        if (Connection_)
        {
            Connection_->Start();
        }
        if (OnStarted_)
        {
            try
            {
                OnStarted_(shared_from_this());
            }
            catch (...)
            {
            }
        }
    }

    auto Server::ReceivePacket(
        const std::span<const std::byte> Data,
        const Net::ip::udp::endpoint &Peer) -> bool
    {
        return Connection_ && Connection_->ReceivePacket(Peer, Data);
    }

    auto Server::WaitHandshake() -> Net::awaitable<bool>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return false;
        }
        co_return co_await Connection->WaitHandshake();
    }

    auto Server::MarkProtocolReady() -> Net::awaitable<bool>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return false;
        }
        co_return co_await Connection->MarkProtocolReady();
    }

    auto Server::AcceptBidirectionalStream() -> Net::awaitable<SharedStreamProvider>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return nullptr;
        }
        co_return co_await Connection->AcceptBidirectionalStream();
    }

    auto Server::OpenUnidirectionalStream() -> Net::awaitable<SharedStreamProvider>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return nullptr;
        }
        co_return co_await Connection->OpenUnidirectionalStream();
    }

    auto Server::AcceptUnidirectionalStream() -> Net::awaitable<SharedStreamProvider>
    {
        const auto Connection = Connection_;
        if (!Connection)
        {
            co_return nullptr;
        }
        co_return co_await Connection->AcceptUnidirectionalStream();
    }

    auto Server::ExportKeyingMaterial(
        std::span<std::uint8_t> Output,
        std::span<const std::uint8_t> Label,
        std::string_view Context) const -> bool
    {
        return Connection_ && Connection_->ExportKeyingMaterial(Output, Label, Context);
    }

    auto Server::Datagram() const -> SharedDatagramProvider
    {
        if (Connection_)
        {
            return Connection_->DatagramProvider();
        }
        return nullptr;
    }

    auto Server::Close() -> void
    {
        if (Connection_)
        {
            Connection_->Close();
        }
    }

    auto Server::Health() const noexcept -> NativeConnectionHealth
    {
        return Connection_ ? Connection_->Health() : NativeConnectionHealth{.Closed = true};
    }

    Gateway::Gateway(ServerOptions Options) : Server_(std::make_shared<Server>(std::move(Options)))
    {
    }

    auto Gateway::Start() -> void
    {
        if (Server_)
        {
            Server_->Start();
        }
    }

    auto Gateway::WaitHandshake() -> Net::awaitable<bool>
    {
        const auto Server = Server_;
        if (!Server)
        {
            co_return false;
        }
        co_return co_await Server->WaitHandshake();
    }

    auto Gateway::MarkProtocolReady() -> Net::awaitable<bool>
    {
        const auto Server = Server_;
        if (!Server)
        {
            co_return false;
        }
        co_return co_await Server->MarkProtocolReady();
    }

    auto Gateway::AcceptBidirectionalStream() -> Net::awaitable<SharedStreamProvider>
    {
        const auto Server = Server_;
        if (!Server)
        {
            co_return nullptr;
        }
        co_return co_await Server->AcceptBidirectionalStream();
    }

    auto Gateway::OpenUnidirectionalStream() -> Net::awaitable<SharedStreamProvider>
    {
        const auto Server = Server_;
        if (!Server)
        {
            co_return nullptr;
        }
        co_return co_await Server->OpenUnidirectionalStream();
    }

    auto Gateway::AcceptUnidirectionalStream() -> Net::awaitable<SharedStreamProvider>
    {
        const auto Server = Server_;
        if (!Server)
        {
            co_return nullptr;
        }
        co_return co_await Server->AcceptUnidirectionalStream();
    }

    auto Gateway::ExportKeyingMaterial(
        std::span<std::uint8_t> Output,
        std::span<const std::uint8_t> Label,
        std::string_view Context) const -> bool
    {
        return Server_ && Server_->ExportKeyingMaterial(Output, Label, Context);
    }

    auto Gateway::Datagram() const -> SharedDatagramProvider
    {
        if (Server_)
        {
            return Server_->Datagram();
        }
        return nullptr;
    }

    auto Gateway::Close() -> void
    {
        if (Server_)
        {
            Server_->Close();
        }
    }

    auto Gateway::Health() const noexcept -> NativeConnectionHealth
    {
        return Server_ ? Server_->Health() : NativeConnectionHealth{.Closed = true};
    }

} // namespace Preview::Quic
