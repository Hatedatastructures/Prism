/**
 * @file Native.cpp
 * @brief Preview 原生 ngtcp2 QUIC 连接实现
 */

#include <preview/Protocols/Quic/Native.hpp>

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

    namespace net = boost::asio;
    using Udp = net::ip::udp;

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

    struct StreamState
    {
        StreamState(net::any_io_executor ExecutorValue, const std::int64_t StreamIdValue)
            : Executor(std::move(ExecutorValue)), Id(StreamIdValue), Notify(Executor, 1)
        {
        }

        net::any_io_executor Executor;
        std::int64_t Id;
        net::experimental::channel<void(boost::system::error_code)> Notify;
        std::deque<std::vector<std::byte>> Received;
        std::weak_ptr<NativeConnection> Owner;
        bool PeerFin{false};
        bool Closed{false};
        bool Canceled{false};
    };

    struct DatagramState
    {
        explicit DatagramState(net::any_io_executor ExecutorValue)
            : Executor(std::move(ExecutorValue)), Notify(Executor, 1)
        {
        }

        net::any_io_executor Executor;
        net::experimental::channel<void(boost::system::error_code)> Notify;
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

        [[nodiscard]] auto Read(std::span<std::byte> Buffer, std::error_code &ErrorCode)
            -> net::awaitable<std::size_t> override;

        [[nodiscard]] auto Write(std::span<const std::byte> Buffer, std::error_code &ErrorCode)
            -> net::awaitable<std::size_t> override;

        void Close() override;

        [[nodiscard]] auto StreamId() const noexcept -> std::int64_t override
        {
            return State_ ? State_->Id : -1;
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

        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return State_ ? State_->Executor : net::any_io_executor{};
        }

        [[nodiscard]] auto Receive(std::span<std::byte> Buffer, std::error_code &ErrorCode)
            -> net::awaitable<std::size_t> override;

        [[nodiscard]] auto Send(std::span<const std::byte> Buffer, std::error_code &ErrorCode)
            -> net::awaitable<std::size_t> override;

        void Close() override;
        void Cancel() override;

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

        NativeConnection(Role ConnectionRole, net::any_io_executor ExecutorValue,
                         std::shared_ptr<Udp::socket> SocketValue, Udp::endpoint PeerValue,
                         SSL_CTX *TlsContextValue, std::string ServerNameValue)
            : Role_(ConnectionRole),
              Executor_(std::move(ExecutorValue)),
              Socket_(std::move(SocketValue)),
              Peer_(std::move(PeerValue)),
              TlsContext_(TlsContextValue),
              ServerName_(std::move(ServerNameValue)),
              HandshakeNotify_(Executor_, 16),
              IncomingNotify_(Executor_, 1),
              WritePermit_(Executor_, 1),
              PumpTimer_(Executor_),
              Datagram_(std::make_shared<DatagramState>(Executor_))
        {
            (void)WritePermit_.try_send(boost::system::error_code{});
        }

        ~NativeConnection() noexcept
        {
            CloseOnExecutor();
        }

        NativeConnection(const NativeConnection &) = delete;
        auto operator=(const NativeConnection &) -> NativeConnection & = delete;

        void Start();
        void Close();

        [[nodiscard]] auto WaitHandshake() -> net::awaitable<bool>;
        [[nodiscard]] auto OpenBidirectionalStream() -> net::awaitable<SharedStreamProvider>;
        [[nodiscard]] auto AcceptBidirectionalStream() -> net::awaitable<SharedStreamProvider>;
        [[nodiscard]] auto DatagramProvider() -> SharedDatagramProvider;

        [[nodiscard]] auto WriteStream(std::int64_t StreamId, std::vector<std::byte> Data,
                                       std::error_code &ErrorCode) -> net::awaitable<std::size_t>;
        [[nodiscard]] auto WriteDatagram(std::vector<std::byte> Data, std::error_code &ErrorCode)
            -> net::awaitable<std::size_t>;

        void CloseStream(const std::shared_ptr<StreamState> &State);
        void CloseDatagram(const std::shared_ptr<DatagramState> &State);

    private:
        struct OutboundPacket
        {
            std::vector<std::byte> Data;
            Udp::endpoint Peer;
        };

        using NotifyChannel = net::experimental::channel<void(boost::system::error_code)>;
        using HandshakeChannel = net::experimental::channel<void(boost::system::error_code, bool)>;

        [[nodiscard]] auto InitializeClient() -> bool;
        [[nodiscard]] auto InitializeServer(const ngtcp2_version_cid &VersionCid) -> bool;
        [[nodiscard]] auto InitializeTls(bool Server) -> bool;
        [[nodiscard]] auto DecodeAndRead(const Udp::endpoint &From, std::span<const std::byte> Data) -> bool;

        [[nodiscard]] auto RunReceiveLoop() -> net::awaitable<void>;
        [[nodiscard]] auto RunSendLoop() -> net::awaitable<void>;
        [[nodiscard]] auto RunPumpLoop() -> net::awaitable<void>;
        void QueueFlush();
        void QueuePacket(const std::byte *Data, std::size_t Length, const Udp::endpoint &Peer);
        void StartSendLoop();
        void CloseOnExecutor();
        void SignalHandshake(bool Success);

        [[nodiscard]] auto MakeStream(std::int64_t StreamId, bool Incoming) -> SharedStreamProvider;
        void OnStreamOpen(std::int64_t StreamId);
        void OnStreamData(std::int64_t StreamId, std::uint32_t Flags, const std::byte *Data, std::size_t Length);
        void OnStreamClose(std::int64_t StreamId);
        void OnDatagram(std::span<const std::byte> Data);
        void OnHandshakeComplete();

    public:
        [[nodiscard]] static auto MakeCallbacks(bool Server) -> ngtcp2_callbacks;
        static int SetReadSecret(SSL *Ssl, ssl_encryption_level_t Level, const SSL_CIPHER *Cipher,
                                 const std::uint8_t *Secret, std::size_t SecretLength);
        static int SetWriteSecret(SSL *Ssl, ssl_encryption_level_t Level, const SSL_CIPHER *Cipher,
                                  const std::uint8_t *Secret, std::size_t SecretLength);
        static int AddHandshakeData(SSL *Ssl, ssl_encryption_level_t Level, const std::uint8_t *Data,
                                    std::size_t Length);
        static int FlushFlight(SSL *Ssl);
        static int SendAlert(SSL *Ssl, ssl_encryption_level_t Level, std::uint8_t Alert);
        static int HandshakeCompleted(ngtcp2_conn *Conn, void *UserData);
        static int RecvCryptoData(ngtcp2_conn *Conn, ngtcp2_encryption_level Level, std::uint64_t Offset,
                                  const std::uint8_t *Data, std::size_t Length, void *UserData);
        static int RecvStreamData(ngtcp2_conn *Conn, std::uint32_t Flags, std::int64_t StreamId,
                                  std::uint64_t Offset, const std::uint8_t *Data, std::size_t Length,
                                  void *UserData, void *StreamUserData);
        static int StreamOpen(ngtcp2_conn *Conn, std::int64_t StreamId, void *UserData);
        static int StreamClose(ngtcp2_conn *Conn, std::uint32_t Flags, std::int64_t StreamId,
                               std::uint64_t AppErrorCode, void *UserData, void *StreamUserData);
        static int RecvDatagram(ngtcp2_conn *Conn, std::uint32_t Flags, const std::uint8_t *Data,
                                std::size_t Length, void *UserData);
        static int AckDatagram(ngtcp2_conn *Conn, std::uint64_t DatagramId, void *UserData);
        static int RecvRetry(ngtcp2_conn *Conn, const ngtcp2_pkt_hd *Header, void *UserData);
        static int VersionNegotiation(ngtcp2_conn *Conn, std::uint32_t Version,
                                      const ngtcp2_cid *ClientDcid, void *UserData);
        static void Random(std::uint8_t *Destination, std::size_t Length, const ngtcp2_rand_ctx *Context);
        static int NewConnectionId(ngtcp2_conn *Conn, ngtcp2_cid *Cid, std::uint8_t *Token,
                                   std::size_t CidLength, void *UserData);
        static int PathChallenge(ngtcp2_conn *Conn, std::uint8_t *Data, void *UserData);

        [[nodiscard]] static auto MakePath(ngtcp2_path_storage &Storage, const Udp::endpoint &Local,
                                           const Udp::endpoint &Remote) -> ngtcp2_path *;

    private:
        Role Role_;
        net::any_io_executor Executor_;
        std::shared_ptr<Udp::socket> Socket_;
        Udp::endpoint Peer_;
        SSL_CTX *TlsContext_{nullptr};
        std::string ServerName_;
        ngtcp2_conn *Conn_{nullptr};
        SSL *Ssl_{nullptr};
        ngtcp2_cid LocalCid_{};
        ngtcp2_cid RemoteCid_{};
        bool Started_{false};
        bool Closed_{false};
        bool HandshakeSignaled_{false};
        bool HandshakeResult_{false};
        bool Sending_{false};
        bool ServerReady_{false};
        HandshakeChannel HandshakeNotify_;
        NotifyChannel IncomingNotify_;
        NotifyChannel WritePermit_;
        net::steady_timer PumpTimer_;
        std::shared_ptr<DatagramState> Datagram_;
        std::deque<SharedStreamProvider> IncomingStreams_;
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

    auto NativeStream::Read(const std::span<std::byte> Buffer, std::error_code &ErrorCode)
        -> net::awaitable<std::size_t>
    {
        ErrorCode.clear();
        if (!State_ || Buffer.empty())
        {
            co_return 0;
        }
        co_await net::dispatch(State_->Executor, net::use_awaitable);
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
                co_return Length;
            }
            if (State_->Closed || State_->PeerFin)
            {
                co_return 0;
            }

            State_->Notify.reset();
            boost::system::error_code NotifyError;
            co_await State_->Notify.async_receive(net::redirect_error(net::use_awaitable, NotifyError));
            if (NotifyError && State_->Closed)
            {
                co_return 0;
            }
        }
    }

    auto NativeStream::Write(const std::span<const std::byte> Buffer, std::error_code &ErrorCode)
        -> net::awaitable<std::size_t>
    {
        ErrorCode.clear();
        if (!State_ || State_->Closed)
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

    void NativeStream::Close()
    {
        if (!State_ || State_->Closed)
        {
            return;
        }
        State_->Closed = true;
        (void)State_->Notify.try_send(boost::system::error_code{});
        if (const auto Owner = Owner_.lock())
        {
            Owner->CloseStream(State_);
        }
    }

    auto NativeDatagram::Receive(const std::span<std::byte> Buffer, std::error_code &ErrorCode)
        -> net::awaitable<std::size_t>
    {
        ErrorCode.clear();
        if (!State_ || Buffer.empty())
        {
            co_return 0;
        }
        co_await net::dispatch(State_->Executor, net::use_awaitable);
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
            co_await State_->Notify.async_receive(net::redirect_error(net::use_awaitable, NotifyError));
            if (NotifyError && State_->Closed)
            {
                ErrorCode = ToStdError(Preview::Error::BrokenPipe);
                co_return 0;
            }
        }
    }

    auto NativeDatagram::Send(const std::span<const std::byte> Buffer, std::error_code &ErrorCode)
        -> net::awaitable<std::size_t>
    {
        ErrorCode.clear();
        if (!State_ || State_->Closed)
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

    void NativeDatagram::Close()
    {
        if (!State_)
        {
            return;
        }
        State_->Closed = true;
        (void)State_->Notify.try_send(boost::system::error_code{});
        if (const auto Owner = Owner_.lock())
        {
            Owner->CloseDatagram(State_);
        }
    }

    void NativeDatagram::Cancel()
    {
        if (!State_ || State_->Closed)
        {
            return;
        }
        State_->Canceled = true;
        (void)State_->Notify.try_send(boost::system::error_code{});
    }

    void NativeConnection::Start()
    {
        if (Started_ || Closed_)
        {
            return;
        }
        Started_ = true;
        if (!Socket_ || !Socket_->is_open() || !TlsContext_)
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
        net::co_spawn(Executor_, [Self]() -> net::awaitable<void> { co_await Self->RunReceiveLoop(); },
                      net::detached);
        net::co_spawn(Executor_, [Self]() -> net::awaitable<void> { co_await Self->RunPumpLoop(); },
                      net::detached);
    }

    void NativeConnection::Close()
    {
        CloseOnExecutor();
    }

    auto NativeConnection::WaitHandshake() -> net::awaitable<bool>
    {
        if (HandshakeSignaled_)
        {
            co_return HandshakeResult_;
        }
        boost::system::error_code ReceiveError;
        const auto Result = co_await HandshakeNotify_.async_receive(
            net::redirect_error(net::use_awaitable, ReceiveError));
        if (ReceiveError)
        {
            co_return false;
        }
        co_return Result;
    }

    auto NativeConnection::OpenBidirectionalStream() -> net::awaitable<SharedStreamProvider>
    {
        if (Role_ != Role::Client || Closed_ || !Conn_ || !HandshakeSignaled_ || !HandshakeResult_)
        {
            co_return nullptr;
        }

        boost::system::error_code PermitError;
        co_await WritePermit_.async_receive(net::redirect_error(net::use_awaitable, PermitError));
        if (PermitError || Closed_ || !Conn_)
        {
            co_return nullptr;
        }

        std::int64_t StreamId = -1;
        const auto Result = ngtcp2_conn_open_bidi_stream(Conn_, &StreamId, nullptr);
        std::shared_ptr<StreamState> State;
        SharedStreamProvider Provider;
        if (Result == 0)
        {
            Provider = MakeStream(StreamId, false);
        }
        else
        {
            Provider = nullptr;
        }
        (void)WritePermit_.try_send(boost::system::error_code{});
        co_return Provider;
    }

    auto NativeConnection::AcceptBidirectionalStream() -> net::awaitable<SharedStreamProvider>
    {
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
            co_await IncomingNotify_.async_receive(net::redirect_error(net::use_awaitable, NotifyError));
            if (NotifyError && Closed_)
            {
                co_return nullptr;
            }
        }
    }

    auto NativeConnection::DatagramProvider() -> SharedDatagramProvider
    {
        if (Closed_ || !Datagram_)
        {
            return nullptr;
        }
        return std::make_shared<NativeDatagram>(weak_from_this(), Datagram_);
    }

    auto NativeConnection::WriteStream(const std::int64_t StreamId, std::vector<std::byte> Data,
                                       std::error_code &ErrorCode) -> net::awaitable<std::size_t>
    {
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
        co_await WritePermit_.async_receive(net::redirect_error(net::use_awaitable, PermitError));
        if (PermitError || Closed_ || !Conn_)
        {
            ErrorCode = ToStdError(Preview::Error::BrokenPipe);
            co_return 0;
        }

        std::size_t Offset = 0;
        std::size_t RetryCount = 0;
        net::steady_timer RetryTimer(Executor_);
        while (Offset < Data.size())
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
                co_await RetryTimer.async_wait(net::redirect_error(net::use_awaitable, TimerError));
                if (TimerError || Closed_)
                {
                    ErrorCode = ToStdError(Preview::Error::BrokenPipe);
                    break;
                }
            }
        }
        ngtcp2_conn_update_pkt_tx_time(Conn_, Now());
        (void)WritePermit_.try_send(boost::system::error_code{});
        if (ErrorCode)
        {
            co_return Offset;
        }
        co_return Offset;
    }

    auto NativeConnection::WriteDatagram(std::vector<std::byte> Data, std::error_code &ErrorCode)
        -> net::awaitable<std::size_t>
    {
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
        co_await WritePermit_.async_receive(net::redirect_error(net::use_awaitable, PermitError));
        if (PermitError || Closed_ || !Conn_)
        {
            ErrorCode = ToStdError(Preview::Error::BrokenPipe);
            co_return 0;
        }

        std::size_t RetryCount = 0;
        net::steady_timer RetryTimer(Executor_);
        while (!Closed_ && RetryCount < 1000)
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
                (void)WritePermit_.try_send(boost::system::error_code{});
                co_return Data.size();
            }
            RetryTimer.expires_after(std::chrono::milliseconds(1));
            boost::system::error_code TimerError;
            co_await RetryTimer.async_wait(net::redirect_error(net::use_awaitable, TimerError));
            if (TimerError || Closed_)
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

    void NativeConnection::CloseStream(const std::shared_ptr<StreamState> &State)
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

    void NativeConnection::CloseDatagram(const std::shared_ptr<DatagramState> &State)
    {
        if (State)
        {
            State->Closed = true;
            (void)State->Notify.try_send(boost::system::error_code{});
        }
    }

    auto NativeConnection::InitializeClient() -> bool
    {
        if (RAND_bytes(LocalCid_.data, 8) != 1 || RAND_bytes(RemoteCid_.data, 8) != 1)
        {
            return false;
        }
        LocalCid_.datalen = 8;
        RemoteCid_.datalen = 8;

        ngtcp2_settings Settings;
        ngtcp2_settings_default(&Settings);
        Settings.initial_ts = Now();
        Settings.max_tx_udp_payload_size = 1472;

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
        return Result == 0;
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
        if (RAND_bytes(LocalCid_.data, LocalCid_.datalen) != 1)
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
        return Result == 0;
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

    auto NativeConnection::DecodeAndRead(const Udp::endpoint &From, const std::span<const std::byte> Data) -> bool
    {
        if (Closed_ || Data.empty())
        {
            return false;
        }
        if (Role_ == Role::Client && From != Peer_)
        {
            return true;
        }
        if (Role_ == Role::Server && !ServerReady_)
        {
            Peer_ = From;
            ngtcp2_version_cid VersionCid{};
            const auto Result = ngtcp2_pkt_decode_version_cid(
                &VersionCid, reinterpret_cast<const std::uint8_t *>(Data.data()), Data.size(), NGTCP2_MAX_CIDLEN);
            if (Result < 0 || VersionCid.version != NGTCP2_PROTO_VER_V1 || !InitializeServer(VersionCid) ||
                !InitializeTls(true))
            {
                return false;
            }
            ServerReady_ = true;
        }
        if (!Conn_ || !Ssl_)
        {
            return false;
        }

        ngtcp2_path_storage PathStorage{};
        auto Local = Socket_->local_endpoint();
        auto *Path = MakePath(PathStorage, Local, Peer_);
        ngtcp2_pkt_info PacketInfo{};
        const auto Result = ngtcp2_conn_read_pkt(
            Conn_, Path, &PacketInfo, reinterpret_cast<const std::uint8_t *>(Data.data()), Data.size(), Now());
        if (Result != 0)
        {
            return false;
        }
        QueueFlush();
        return true;
    }

    auto NativeConnection::RunReceiveLoop() -> net::awaitable<void>
    {
        std::array<std::byte, 65536> Buffer{};
        while (!Closed_ && Socket_ && Socket_->is_open())
        {
            Udp::endpoint From;
            boost::system::error_code ReceiveError;
            const auto Length = co_await Socket_->async_receive_from(
                net::buffer(Buffer), From, net::redirect_error(net::use_awaitable, ReceiveError));
            if (ReceiveError)
            {
                break;
            }
            if (Length != 0 && !DecodeAndRead(From, std::span<const std::byte>(Buffer.data(), Length)))
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

    auto NativeConnection::RunSendLoop() -> net::awaitable<void>
    {
        while (!Closed_ && Socket_ && Socket_->is_open() && !Outbound_.empty())
        {
            auto Packet = std::move(Outbound_.front());
            Outbound_.pop_front();
            boost::system::error_code SendError;
            const auto Length = co_await Socket_->async_send_to(
                net::buffer(Packet.Data), Packet.Peer, net::redirect_error(net::use_awaitable, SendError));
            if (SendError || Length != Packet.Data.size())
            {
                CloseOnExecutor();
                break;
            }
        }
        Sending_ = false;
    }

    auto NativeConnection::RunPumpLoop() -> net::awaitable<void>
    {
        while (!Closed_)
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
                        if (Result != 0)
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
            co_await PumpTimer_.async_wait(net::redirect_error(net::use_awaitable, TimerError));
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
                    if (Result != 0)
                    {
                        CloseOnExecutor();
                        co_return;
                    }
                }
                QueueFlush();
            }
        }
    }

    void NativeConnection::QueueFlush()
    {
        if (Closed_ || !Conn_ || !Socket_ || !Socket_->is_open())
        {
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
            if (Length == NGTCP2_ERR_WRITE_MORE || Length <= 0)
            {
                break;
            }
            QueuePacket(Packet.data(), static_cast<std::size_t>(Length), Peer_);
        }
        ngtcp2_conn_update_pkt_tx_time(Conn_, Now());
    }

    void NativeConnection::QueuePacket(const std::byte *Data, const std::size_t Length,
                                       const Udp::endpoint &Peer)
    {
        if (Closed_ || Length == 0)
        {
            return;
        }
        Outbound_.push_back(OutboundPacket{std::vector<std::byte>(Data, Data + Length), Peer});
        StartSendLoop();
    }

    void NativeConnection::StartSendLoop()
    {
        if (Sending_ || Closed_ || Outbound_.empty())
        {
            return;
        }
        Sending_ = true;
        auto Self = shared_from_this();
        net::co_spawn(Executor_, [Self]() -> net::awaitable<void> { co_await Self->RunSendLoop(); },
                      net::detached);
    }

    void NativeConnection::CloseOnExecutor()
    {
        if (Closed_ && !Conn_ && !Ssl_)
        {
            return;
        }
        Closed_ = true;
        SignalHandshake(false);
        if (Socket_)
        {
            boost::system::error_code ErrorCode;
            Socket_->cancel(ErrorCode);
            Socket_->close(ErrorCode);
        }
        PumpTimer_.cancel();
        IncomingNotify_.cancel();
        HandshakeNotify_.cancel();
        WritePermit_.cancel();
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

    void NativeConnection::SignalHandshake(const bool Success)
    {
        if (HandshakeSignaled_)
        {
            return;
        }
        HandshakeSignaled_ = true;
        HandshakeResult_ = Success;
        for (std::size_t I = 0; I < 16; ++I)
        {
            (void)HandshakeNotify_.try_send(boost::system::error_code{}, Success);
        }
    }

    auto NativeConnection::MakeStream(const std::int64_t StreamId, const bool Incoming) -> SharedStreamProvider
    {
        auto State = std::make_shared<StreamState>(Executor_, StreamId);
        State->Owner = weak_from_this();
        auto Provider = std::make_shared<NativeStream>(weak_from_this(), State);
        Streams_[StreamId] = std::move(State);
        if (Incoming)
        {
            IncomingStreams_.push_back(Provider);
            (void)IncomingNotify_.try_send(boost::system::error_code{});
        }
        return Provider;
    }

    void NativeConnection::OnStreamOpen(const std::int64_t StreamId)
    {
        if ((StreamId & 2) != 0 || Streams_.contains(StreamId))
        {
            return;
        }
        (void)MakeStream(StreamId, Role_ == Role::Server);
    }

    void NativeConnection::OnStreamData(const std::int64_t StreamId, const std::uint32_t Flags,
                                        const std::byte *Data, const std::size_t Length)
    {
        if (!Streams_.contains(StreamId))
        {
            OnStreamOpen(StreamId);
        }
        const auto It = Streams_.find(StreamId);
        if (It == Streams_.end() || !It->second)
        {
            return;
        }
        auto &State = It->second;
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

    void NativeConnection::OnStreamClose(const std::int64_t StreamId)
    {
        const auto It = Streams_.find(StreamId);
        if (It == Streams_.end() || !It->second)
        {
            return;
        }
        It->second->PeerFin = true;
        (void)It->second->Notify.try_send(boost::system::error_code{});
    }

    void NativeConnection::OnDatagram(const std::span<const std::byte> Data)
    {
        if (!Datagram_ || Datagram_->Closed)
        {
            return;
        }
        Datagram_->Received.emplace_back(Data.begin(), Data.end());
        (void)Datagram_->Notify.try_send(boost::system::error_code{});
    }

    void NativeConnection::OnHandshakeComplete()
    {
        SignalHandshake(true);
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

    int NativeConnection::SetReadSecret(SSL *Ssl, const ssl_encryption_level_t Level,
                                        const SSL_CIPHER *Cipher, const std::uint8_t *Secret,
                                        const std::size_t SecretLength)
    {
        (void)Cipher;
        auto *Connection = static_cast<NativeConnection *>(SSL_get_app_data(Ssl));
        if (!Connection || !Connection->Conn_)
        {
            return 0;
        }
        return ngtcp2_crypto_derive_and_install_rx_key(
                   Connection->Conn_, nullptr, nullptr, nullptr,
                   ngtcp2_crypto_boringssl_from_ssl_encryption_level(Level), Secret, SecretLength) == 0
                   ? 1
                   : 0;
    }

    int NativeConnection::SetWriteSecret(SSL *Ssl, const ssl_encryption_level_t Level,
                                         const SSL_CIPHER *Cipher, const std::uint8_t *Secret,
                                         const std::size_t SecretLength)
    {
        (void)Cipher;
        auto *Connection = static_cast<NativeConnection *>(SSL_get_app_data(Ssl));
        if (!Connection || !Connection->Conn_)
        {
            return 0;
        }
        return ngtcp2_crypto_derive_and_install_tx_key(
                   Connection->Conn_, nullptr, nullptr, nullptr,
                   ngtcp2_crypto_boringssl_from_ssl_encryption_level(Level), Secret, SecretLength) == 0
                   ? 1
                   : 0;
    }

    int NativeConnection::AddHandshakeData(SSL *Ssl, const ssl_encryption_level_t Level,
                                            const std::uint8_t *Data, const std::size_t Length)
    {
        auto *Connection = static_cast<NativeConnection *>(SSL_get_app_data(Ssl));
        if (!Connection || !Connection->Conn_)
        {
            return 0;
        }
        return ngtcp2_conn_submit_crypto_data(
                   Connection->Conn_, ngtcp2_crypto_boringssl_from_ssl_encryption_level(Level), Data, Length) == 0
                   ? 1
                   : 0;
    }

    int NativeConnection::FlushFlight(SSL *Ssl)
    {
        return SSL_get_app_data(Ssl) != nullptr ? 1 : 0;
    }

    int NativeConnection::SendAlert(SSL *Ssl, ssl_encryption_level_t Level, std::uint8_t Alert)
    {
        (void)Level;
        (void)Alert;
        return SSL_get_app_data(Ssl) != nullptr ? 1 : 0;
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

    int NativeConnection::RecvCryptoData(ngtcp2_conn *Conn, const ngtcp2_encryption_level Level,
                                         const std::uint64_t Offset, const std::uint8_t *Data,
                                         const std::size_t Length, void *UserData)
    {
        const auto Result = ngtcp2_crypto_recv_crypto_data_cb(Conn, Level, Offset, Data, Length, UserData);
        return Result;
    }

    int NativeConnection::RecvStreamData(ngtcp2_conn *Conn, const std::uint32_t Flags,
                                         const std::int64_t StreamId, const std::uint64_t Offset,
                                         const std::uint8_t *Data, const std::size_t Length, void *UserData,
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

    int NativeConnection::StreamOpen(ngtcp2_conn *Conn, const std::int64_t StreamId, void *UserData)
    {
        (void)Conn;
        auto *Connection = static_cast<NativeConnection *>(UserData);
        if (Connection)
        {
            Connection->OnStreamOpen(StreamId);
        }
        return 0;
    }

    int NativeConnection::StreamClose(ngtcp2_conn *Conn, const std::uint32_t Flags,
                                      const std::int64_t StreamId, const std::uint64_t AppErrorCode,
                                      void *UserData, void *StreamUserData)
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

    int NativeConnection::RecvDatagram(ngtcp2_conn *Conn, const std::uint32_t Flags,
                                       const std::uint8_t *Data, const std::size_t Length, void *UserData)
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

    int NativeConnection::AckDatagram(ngtcp2_conn *Conn, const std::uint64_t DatagramId, void *UserData)
    {
        (void)Conn;
        (void)DatagramId;
        (void)UserData;
        return 0;
    }

    int NativeConnection::RecvRetry(ngtcp2_conn *Conn, const ngtcp2_pkt_hd *Header, void *UserData)
    {
        (void)Conn;
        (void)Header;
        (void)UserData;
        return 0;
    }

    int NativeConnection::VersionNegotiation(ngtcp2_conn *Conn, const std::uint32_t Version,
                                             const ngtcp2_cid *ClientDcid, void *UserData)
    {
        (void)Conn;
        (void)Version;
        (void)ClientDcid;
        (void)UserData;
        return 0;
    }

    void NativeConnection::Random(std::uint8_t *Destination, const std::size_t Length,
                                  const ngtcp2_rand_ctx *Context)
    {
        (void)Context;
        if (Length > 0)
        {
            (void)RAND_bytes(Destination, static_cast<int>(Length));
        }
    }

    int NativeConnection::NewConnectionId(ngtcp2_conn *Conn, ngtcp2_cid *Cid, std::uint8_t *Token,
                                           const std::size_t CidLength, void *UserData)
    {
        (void)Conn;
        (void)UserData;
        if (!Cid || CidLength > NGTCP2_MAX_CIDLEN || RAND_bytes(Cid->data, static_cast<int>(CidLength)) != 1)
        {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        Cid->datalen = CidLength;
        if (Token && RAND_bytes(Token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1)
        {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    int NativeConnection::PathChallenge(ngtcp2_conn *Conn, std::uint8_t *Data, void *UserData)
    {
        (void)Conn;
        (void)UserData;
        return Data && RAND_bytes(Data, NGTCP2_PATH_CHALLENGE_DATALEN) == 1 ? 0
                                                                            : NGTCP2_ERR_CALLBACK_FAILURE;
    }

    auto NativeConnection::MakePath(ngtcp2_path_storage &Storage, const Udp::endpoint &Local,
                                     const Udp::endpoint &Remote) -> ngtcp2_path *
    {
        ngtcp2_path_storage_init(&Storage, reinterpret_cast<const ngtcp2_sockaddr *>(Local.data()), Local.size(),
                                 reinterpret_cast<const ngtcp2_sockaddr *>(Remote.data()), Remote.size(), nullptr);
        return &Storage.path;
    }

} // namespace Preview::Quic::Detail

namespace Preview::Quic
{

    Client::Client(ClientOptions Options)
        : Connection_(std::make_shared<Detail::NativeConnection>(Detail::NativeConnection::Role::Client,
                                                                  Options.Executor, std::move(Options.Socket),
                                                                  Options.Peer, Options.TlsContext,
                                                                  std::move(Options.ServerName)))
    {
    }

    Client::~Client() noexcept = default;

    void Client::Start()
    {
        if (Connection_)
        {
            Connection_->Start();
        }
    }

    auto Client::WaitHandshake() -> net::awaitable<bool>
    {
        if (!Connection_)
        {
            co_return false;
        }
        co_return co_await Connection_->WaitHandshake();
    }

    auto Client::OpenBidirectionalStream() -> net::awaitable<SharedStreamProvider>
    {
        if (!Connection_)
        {
            co_return nullptr;
        }
        co_return co_await Connection_->OpenBidirectionalStream();
    }

    auto Client::Datagram() const -> SharedDatagramProvider
    {
        return Connection_ ? Connection_->DatagramProvider() : nullptr;
    }

    void Client::Close()
    {
        if (Connection_)
        {
            Connection_->Close();
        }
    }

    Server::Server(ServerOptions Options)
        : Connection_(std::make_shared<Detail::NativeConnection>(Detail::NativeConnection::Role::Server,
                                                                  Options.Executor, std::move(Options.Socket),
                                                                  net::ip::udp::endpoint{},
                                                                  Options.TlsContext, std::string{}))
    {
    }

    Server::~Server() noexcept = default;

    void Server::Start()
    {
        if (Connection_)
        {
            Connection_->Start();
        }
    }

    auto Server::WaitHandshake() -> net::awaitable<bool>
    {
        if (!Connection_)
        {
            co_return false;
        }
        co_return co_await Connection_->WaitHandshake();
    }

    auto Server::AcceptBidirectionalStream() -> net::awaitable<SharedStreamProvider>
    {
        if (!Connection_)
        {
            co_return nullptr;
        }
        co_return co_await Connection_->AcceptBidirectionalStream();
    }

    auto Server::Datagram() const -> SharedDatagramProvider
    {
        return Connection_ ? Connection_->DatagramProvider() : nullptr;
    }

    void Server::Close()
    {
        if (Connection_)
        {
            Connection_->Close();
        }
    }

    Gateway::Gateway(ServerOptions Options) : Server_(std::make_shared<Server>(std::move(Options)))
    {
    }

    void Gateway::Start()
    {
        if (Server_)
        {
            Server_->Start();
        }
    }

    auto Gateway::WaitHandshake() -> net::awaitable<bool>
    {
        if (!Server_)
        {
            co_return false;
        }
        co_return co_await Server_->WaitHandshake();
    }

    auto Gateway::AcceptBidirectionalStream() -> net::awaitable<SharedStreamProvider>
    {
        if (!Server_)
        {
            co_return nullptr;
        }
        co_return co_await Server_->AcceptBidirectionalStream();
    }

    auto Gateway::Datagram() const -> SharedDatagramProvider
    {
        return Server_ ? Server_->Datagram() : nullptr;
    }

    void Gateway::Close()
    {
        if (Server_)
        {
            Server_->Close();
        }
    }

} // namespace Preview::Quic
