/**
 * @file NativeConnectionCallbacks.cpp
 * @brief ngtcp2 与 BoringSSL 的 QUIC callback owner。
 * @details 只负责 callback table、TLS secret bridge、CID/random/path callback；
 *          callback 通过 UserData 回到 NativeConnection，不拥有连接生命周期。
 */
#include <Prism/Protocols/Quic/Detail/NativeConnection.hpp>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

namespace Prism::Quic::Detail
{
    struct StreamAcknowledgement final
    {
        std::int64_t StreamId{0};
        std::uint64_t Offset{0};
        std::uint64_t DataLength{0};
    };

    struct StreamResetNotification final
    {
        std::int64_t StreamId{0};
        std::uint64_t FinalSize{0};
        std::uint64_t ApplicationErrorCode{0};
    };

    struct PeerStopSendingNotification final
    {
        std::int64_t StreamId{0};
        std::uint64_t ApplicationErrorCode{0};
    };

    /** @brief 将 ngtcp2 ACK 范围事件转交给连接状态机。 */
    inline auto AcknowledgedStreamDataCallback(
        void *UserData,
        const StreamAcknowledgement Event) -> int
    {
        auto *Owner = static_cast<NativeConnection *>(UserData);
        if (Owner)
        {
            Owner->OnStreamDataAcknowledged(Event.StreamId, Event.Offset, Event.DataLength);
        }
        return 0;
    }

    /** @brief 将 ngtcp2 RESET_STREAM 事件转交给连接状态机。 */
    inline auto StreamResetCallback(
        void *UserData,
        const StreamResetNotification Event) -> int
    {
        auto *Owner = static_cast<NativeConnection *>(UserData);
        if (Owner)
        {
            Owner->OnStreamReset(Event.StreamId, Event.FinalSize, Event.ApplicationErrorCode);
        }
        return 0;
    }

    /** @brief 将 ngtcp2 STOP_SENDING 事件转交给连接状态机。 */
    inline auto PeerStopSendingCallback(
        void *UserData,
        const PeerStopSendingNotification Event) -> int
    {
        auto *Owner = static_cast<NativeConnection *>(UserData);
        if (Owner)
        {
            Owner->OnPeerStopSending(Event.StreamId, Event.ApplicationErrorCode);
        }
        return 0;
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
        Callbacks.acked_stream_data_offset = [](ngtcp2_conn *, std::int64_t StreamId,
            std::uint64_t Offset, std::uint64_t DataLength, void *UserData, void *) -> int
        {
            return AcknowledgedStreamDataCallback(
                UserData, {StreamId, Offset, DataLength});
        };
        Callbacks.stream_open = &NativeConnection::StreamOpen;
        Callbacks.stream_close = &NativeConnection::StreamClose;
        Callbacks.stream_reset = [](ngtcp2_conn *, std::int64_t StreamId,
            std::uint64_t FinalSize, std::uint64_t ApplicationErrorCode,
            void *UserData, void *) -> int
        {
            return StreamResetCallback(
                UserData, {StreamId, FinalSize, ApplicationErrorCode});
        };
        Callbacks.recv_stop_sending = [](ngtcp2_conn *, std::int64_t StreamId,
            std::uint64_t ApplicationErrorCode, void *UserData, void *) -> int
        {
            return PeerStopSendingCallback(
                UserData, {StreamId, ApplicationErrorCode});
        };
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
            return Connection->OnHandshakeComplete();
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
            return Connection->OnStreamData(StreamId,Flags,
                std::span<const std::byte>(reinterpret_cast<const std::byte*>(Data),Length));
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
            return Connection->OnStreamOpen(StreamId);
        }
        return 0;
    }

    int NativeConnection::StreamClose(
        ngtcp2_conn *Conn,
        const std::uint32_t Flags,
        const std::int64_t StreamId,
        const std::uint64_t AppErrorCode,
        void *UserData,
        void *)
    {
        auto *Connection = static_cast<NativeConnection *>(UserData);
        if (Connection)
        {
            Connection->OnStreamClose(StreamId, Flags, AppErrorCode);
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


} // namespace Prism::Quic::Detail

