/**
 * @file NativeConnectionTransport.hpp
 * @brief 原生 QUIC transport/pump owner。
 * @details 负责随机源、client/server ngtcp2 初始化、TLS transport params、
 *          CID 接收过滤、UDP 收发和 expiry pump。
 */

#pragma once

#include <Prism/Protocols/Quic/Detail/NativeConnection.hpp>

namespace Prism::Quic::Detail
{
    inline auto NativeConnection::FillRandom(std::uint8_t *Destination, const std::size_t Length) const -> bool
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

    inline auto NativeConnection::InitializeClient() -> bool
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

    inline auto NativeConnection::InitializeServer(const ngtcp2_version_cid &VersionCid) -> bool
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
        Params.initial_max_streams_bidi = static_cast<std::uint64_t>(MaxActiveBidirectionalStreams_);
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

    inline auto NativeConnection::InitializeTls(const bool Server) -> bool
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

    inline auto NativeConnection::DecodeAndRead(
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
                EmitLifecycle(Prism::Quic::ServerLifecycleStage::InitialRejected, Result);
                return DecodeResult::Ignored;
            }
            if (!InitializeServer(VersionCid))
            {
                EmitLifecycle(Prism::Quic::ServerLifecycleStage::ServerInitializationFailed);
                return DecodeResult::Fatal;
            }
            EmitLifecycle(Prism::Quic::ServerLifecycleStage::ServerInitialized);
            if (!InitializeTls(true))
            {
                EmitLifecycle(Prism::Quic::ServerLifecycleStage::TlsInitializationFailed);
                return DecodeResult::Fatal;
            }
            EmitLifecycle(Prism::Quic::ServerLifecycleStage::TlsInitialized);
            ServerReady_ = true;
            InitializedServer = true;
        }
        if (!Conn_ || !Ssl_)
        {
            return DecodeResult::Fatal;
        }
        // Registry 已将该 Native server 绑定到唯一的 peer。握手期间客户端
        // 可能在 long/short header 之间轮换 destination CID；在握手完成前
        // 不能用最终 CID 白名单丢弃合法的后续 Initial/Handshake 包。
        if (ServerReady_ && !InitializedServer && HandshakeSignaled_ && !AcceptsPacket(Data))
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
                EmitLifecycle(Prism::Quic::ServerLifecycleStage::PacketAccepted, Result);
                return DecodeResult::Accepted;
            }
            EmitLifecycle(Prism::Quic::ServerLifecycleStage::PacketRejected, Result);
            return DecodeResult::Fatal;
        }
        QueueFlush();
        (void)FlowNotify_.try_send(boost::system::error_code{});
        EmitLifecycle(Prism::Quic::ServerLifecycleStage::PacketAccepted, Result);
        return DecodeResult::Accepted;
    }

    inline auto NativeConnection::AcceptsPacket(const std::span<const std::byte> Data) const -> bool
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

    inline auto NativeConnection::RunReceiveLoop() -> Net::awaitable<void>
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

    inline auto NativeConnection::RunSendLoop() -> Net::awaitable<void>
    {
        while (!Closed_ && !Outbound_.empty())
        {
            auto Packet = std::move(Outbound_.front());
            Outbound_.pop_front();
            boost::system::error_code SendError;
            if (Role_ == Role::Server)
            {
                SendError = co_await Sender_->SendTo(Packet.Data, Packet.Peer);
            }
            else
            {
                const auto Length = co_await Socket_->async_send_to(
                    Net::buffer(Packet.Data), Packet.Peer,
                    Net::redirect_error(Net::use_awaitable, SendError));
                if (!SendError && Length != Packet.Data.size())
                {
                    SendError = boost::system::errc::make_error_code(
                        boost::system::errc::message_size);
                }
            }
            if (SendError)
            {
                if (!SendFailure_.Failed())
                {
                    SendFailure_ = Prism::Fault::FromNative(
                        static_cast<std::error_code>(SendError));
                }
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

    inline auto NativeConnection::WaitForSendDrain() -> Net::awaitable<bool>
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

    inline auto NativeConnection::RunPumpLoop() -> Net::awaitable<void>
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

    inline auto NativeConnection::QueueFlush() -> void
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

    inline auto NativeConnection::QueuePacket(
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

    inline auto NativeConnection::RunTrackedLoop(const LoopKind Kind) -> Net::awaitable<void>
    {
        if (Kind == LoopKind::Receive)
        {
            co_await RunReceiveLoop();
        }
        else if (Kind == LoopKind::Pump)
        {
            co_await RunPumpLoop();
        }
        else
        {
            co_await RunSendLoop();
        }
    }

    inline auto NativeConnection::StartTrackedLoop(const LoopKind Kind) -> bool
    {
        if (!Loops_.Enter())
        {
            return false;
        }
        const auto Self = shared_from_this();
        auto Work = [Self, Kind]() -> Net::awaitable<void>
        {
            co_await Self->RunTrackedLoop(Kind);
        };
        try
        {
            Net::co_spawn(Executor_, std::move(Work),
                [Self, Kind](std::exception_ptr Error)
                {
                    Self->CompleteTrackedLoop(Kind, std::move(Error));
                });
        }
        catch (...)
        {
            Fatal_->Publish(std::current_exception());
            Loops_.Leave();
            return false;
        }
        return true;
    }

    inline auto NativeConnection::CompleteTrackedLoop(
        const LoopKind Kind,
        std::exception_ptr Error) noexcept -> void
    {
        if (Error)
        {
            Fatal_->Publish(std::move(Error));
            BoundedFailureAtomic_.store(true, std::memory_order_release);
            CloseOnExecutor();
        }
        else if (Kind != LoopKind::Send && !Closed_)
        {
            BoundedFailureAtomic_.store(true, std::memory_order_release);
            CloseOnExecutor();
        }
        if (Kind == LoopKind::Send)
        {
            Sending_ = false;
            if (!Closed_ && !Outbound_.empty())
            {
                StartSendLoop();
            }
        }
        Loops_.Leave();
    }

    inline auto NativeConnection::StartSendLoop() -> void
    {
        if (Sending_ || Closed_ || Outbound_.empty())
        {
            return;
        }
        Sending_ = true;
        if (!StartTrackedLoop(LoopKind::Send))
        {
            Sending_ = false;
            BoundedFailureAtomic_.store(true, std::memory_order_release);
            CloseOnExecutor();
        }
    }


} // namespace Prism::Quic::Detail
