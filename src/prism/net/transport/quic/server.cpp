/**
 * @file server.cpp
 * @brief QUIC 服务端/客户端连接封装实现
 */

#include <prism/net/transport/quic/server.hpp>
#include <prism/diagnose/diagnose.hpp>
#include <prism/net/transport/transmission.hpp>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>

#include <openssl/rand.h>

#include <chrono>
#include <cstring>

using namespace psm::diagnose;

namespace psm::quic
{

    namespace
    {
        // === BoringSSL QUIC 桥接 ===

        void server_log_printf(void *user_data, const char *fmt, ...);

        int set_read_secret(SSL *ssl, enum ssl_encryption_level_t level,
                            const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len)
        {
            auto *s = static_cast<server *>(SSL_get_app_data(ssl));
            if (!s)
                return 0;
            (void)cipher;
            if (ngtcp2_crypto_derive_and_install_rx_key(
                    s->native_conn(), nullptr, nullptr, nullptr,
                    ngtcp2_crypto_boringssl_from_ssl_encryption_level(level),
                    secret, secret_len) != 0)
            {
                return 0;
            }
            return 1;
        }

        int set_write_secret(SSL *ssl, enum ssl_encryption_level_t level,
                             const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len)
        {
            auto *s = static_cast<server *>(SSL_get_app_data(ssl));
            if (!s)
                return 0;
            (void)cipher;
            if (ngtcp2_crypto_derive_and_install_tx_key(
                    s->native_conn(), nullptr, nullptr, nullptr,
                    ngtcp2_crypto_boringssl_from_ssl_encryption_level(level),
                    secret, secret_len) != 0)
            {
                return 0;
            }
            return 1;
        }

        int add_handshake_data(SSL *ssl, enum ssl_encryption_level_t level,
                               const uint8_t *data, size_t len)
        {
            auto *s = static_cast<server *>(SSL_get_app_data(ssl));
            if (!s)
                return 0;
            auto rv = ngtcp2_conn_submit_crypto_data(
                s->native_conn(),
                ngtcp2_crypto_boringssl_from_ssl_encryption_level(level),
                data, len);
            if (rv != 0)
                return 0;
            return 1;
        }

        int flush_flight(SSL *ssl)
        {
            auto *s = static_cast<server *>(SSL_get_app_data(ssl));
            if (!s)
                return 0;
            return 1;
        }

        int send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert)
        {
            auto *s = static_cast<server *>(SSL_get_app_data(ssl));
            if (!s)
                return 0;
            (void)level;
            (void)alert;
            return 1;
        }

        const SSL_QUIC_METHOD quic_method = {
            set_read_secret,
            set_write_secret,
            add_handshake_data,
            flush_flight,
            send_alert,
        };

        // === ngtcp2 应用层回调（server 与 client 共用） ===

        int cb_handshake_completed(ngtcp2_conn *conn, void *user_data)
        {
            auto *s = static_cast<server *>(user_data);
            (void)conn;
            if (s)
                s->on_handshake_done();
            return 0;
        }

        int cb_stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data)
        {
            auto *s = static_cast<server *>(user_data);
            (void)conn;
            if (s)
                s->on_stream_open(stream_id);
            return 0;
        }

        int cb_recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                                uint64_t offset, const uint8_t *data, size_t datalen,
                                void *user_data, void *stream_user_data)
        {
            auto *s = static_cast<server *>(user_data);
            (void)conn;
            (void)flags;
            (void)offset;
            (void)stream_user_data;
            if (s)
                s->on_stream_data(stream_id, std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(data), datalen));
            return 0;
        }

        int cb_stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                            uint64_t app_error_code, void *user_data, void *stream_user_data)
        {
            auto *s = static_cast<server *>(user_data);
            (void)conn;
            (void)flags;
            (void)app_error_code;
            (void)stream_user_data;
            if (s)
                s->on_stream_close(stream_id);
            return 0;
        }

        int cb_recv_retry(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, void *user_data)
        {
            (void)conn;
            (void)hd;
            (void)user_data;
            return 0;
        }

        void cb_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
        {
            (void)rand_ctx;
            RAND_bytes(dest, static_cast<int>(destlen));
        }

        int cb_recv_datagram(ngtcp2_conn *conn, uint32_t flags,
                             const uint8_t *data, size_t datalen, void *user_data)
        {
            auto *s = static_cast<server *>(user_data);
            (void)conn;
            (void)flags;
            if (s)
                s->on_datagram_data(std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(data), datalen));
            return 0;
        }

        int cb_ack_datagram(ngtcp2_conn *conn, uint64_t dgram_id, void *user_data)
        {
            (void)conn;
            (void)dgram_id;
            (void)user_data;
            return 0;
        }

        int cb_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                     uint8_t *token, size_t cidlen, void *user_data)
        {
            auto *s = static_cast<server *>(user_data);
            (void)conn;
            (void)cidlen;
            if (!s)
                return NGTCP2_ERR_CALLBACK_FAILURE;
            if (RAND_bytes(cid->data, NGTCP2_MAX_CIDLEN) != 1)
                return NGTCP2_ERR_CALLBACK_FAILURE;
            cid->datalen = NGTCP2_MAX_CIDLEN;
            if (token && RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1)
                return NGTCP2_ERR_CALLBACK_FAILURE;
            return 0;
        }

        int cb_get_path_challenge_data(ngtcp2_conn *conn, uint8_t *data, void *user_data)
        {
            auto *s = static_cast<server *>(user_data);
            (void)conn;
            if (!s)
                return NGTCP2_ERR_CALLBACK_FAILURE;
            RAND_bytes(data, 8);
            return 0;
        }

        void server_log_printf(void *user_data, const char *fmt, ...)
        {
            (void)user_data;
            va_list ap;
            va_start(ap, fmt);
            char buf[1024];
            vsnprintf(buf, sizeof(buf), fmt, ap);
            va_end(ap);
            diagnose::debug("ngtcp2-server: {}", buf);
        }

        void client_log_printf(void *user_data, const char *fmt, ...)
        {
            (void)user_data;
            va_list ap;
            va_start(ap, fmt);
            char buf[1024];
            vsnprintf(buf, sizeof(buf), fmt, ap);
            va_end(ap);
            diagnose::debug("ngtcp2-client: {}", buf);
        }

        const ngtcp2_callbacks ngtcp2_callbacks_instance = {
            .recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
            .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
            .handshake_completed = cb_handshake_completed,
            .encrypt = ngtcp2_crypto_encrypt_cb,
            .decrypt = ngtcp2_crypto_decrypt_cb,
            .hp_mask = ngtcp2_crypto_hp_mask_cb,
            .recv_stream_data = cb_recv_stream_data,
            .stream_open = cb_stream_open,
            .stream_close = cb_stream_close,
            .recv_retry = cb_recv_retry,
            .rand = cb_rand,
            .get_new_connection_id = cb_get_new_connection_id,
            .update_key = ngtcp2_crypto_update_key_cb,
            .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
            .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
            .recv_datagram = cb_recv_datagram,
            .ack_datagram = cb_ack_datagram,
            .get_path_challenge_data = cb_get_path_challenge_data,
        };

        // === client 回调 ===

        int cb_client_handshake_completed(ngtcp2_conn *conn, void *user_data)
        {
            auto *c = static_cast<client *>(user_data);
            (void)conn;
            if (c)
                c->on_handshake_done();
            return 0;
        }

        int cb_client_recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                                       uint64_t offset, const uint8_t *data, size_t datalen,
                                       void *user_data, void *stream_user_data)
        {
            auto *c = static_cast<client *>(user_data);
            (void)conn;
            (void)flags;
            (void)offset;
            (void)stream_user_data;
            if (c && c->on_stream_data)
                c->on_stream_data(stream_id, std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(data), datalen));
            return 0;
        }

        const ngtcp2_callbacks ngtcp2_client_callbacks_instance = {
            .client_initial = ngtcp2_crypto_client_initial_cb,
            .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
            .handshake_completed = cb_client_handshake_completed,
            .encrypt = ngtcp2_crypto_encrypt_cb,
            .decrypt = ngtcp2_crypto_decrypt_cb,
            .hp_mask = ngtcp2_crypto_hp_mask_cb,
            .recv_stream_data = cb_client_recv_stream_data,
            .recv_retry = cb_recv_retry,
            .rand = cb_rand,
            .get_new_connection_id = cb_get_new_connection_id,
            .update_key = ngtcp2_crypto_update_key_cb,
            .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
            .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
            .recv_datagram = cb_recv_datagram,
            .ack_datagram = cb_ack_datagram,
            .get_path_challenge_data = cb_get_path_challenge_data,
        };

        /// 用真实 UDP 端点填充 path_storage（ngtcp2 要求 sockaddr 有效）
        [[nodiscard]] inline auto make_path(ngtcp2_path_storage &ps,
                                            const net::ip::udp::endpoint &local,
                                            const net::ip::udp::endpoint &remote) -> ngtcp2_path *
        {
            ngtcp2_path_storage_zero(&ps);
            ps.path.local.addr = const_cast<sockaddr *>(local.data());
            ps.path.local.addrlen = local.size();
            ps.path.remote.addr = const_cast<sockaddr *>(remote.data());
            ps.path.remote.addrlen = remote.size();
            return &ps.path;
        }

        /// 当前微秒时间戳（ngtcp2_tstamp）
        [[nodiscard]] inline auto now_tstamp() -> ngtcp2_tstamp
        {
            return static_cast<ngtcp2_tstamp>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count());
        }
    } // namespace

    // === stream 实现 ===

    stream::stream(net::any_io_executor executor, std::shared_ptr<server> owner,
                   const std::int64_t stream_id, const memory::resource_pointer mr)
        : executor_(std::move(executor))
        , owner_(std::move(owner))
        , stream_id_(stream_id)
        , mr_(mr)
        , channel_(executor_, 256)
        , recv_buf_(mr_)
    {
    }

    auto stream::executor() const -> executor_type
    {
        return executor_;
    }

    auto stream::async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        while (recv_offset_ >= recv_buf_.size())
        {
            if (closed_)
            {
                ec = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }
            if (fin_)
            {
                ec = psm::fault::make_error_code(psm::fault::code::eof);
                co_return 0;
            }
            boost::system::error_code ch_ec;
            auto token = net::redirect_error(net::use_awaitable, ch_ec);
            auto block = co_await channel_.async_receive(token);
            if (ch_ec)
            {
                ec = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }
            if (block.empty())
            {
                ec = psm::fault::make_error_code(psm::fault::code::eof);
                co_return 0;
            }
            recv_buf_ = std::move(block);
            recv_offset_ = 0;
        }
        const auto n = std::min(buffer.size(), recv_buf_.size() - recv_offset_);
        std::memcpy(buffer.data(), recv_buf_.data() + recv_offset_, n);
        recv_offset_ += n;
        if (recv_offset_ >= recv_buf_.size())
        {
            recv_buf_.clear();
            recv_offset_ = 0;
        }
        ec = {};
        co_return n;
    }

    auto stream::async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        if (closed_ || !owner_)
        {
            ec = std::make_error_code(std::errc::not_connected);
            co_return 0;
        }
        co_await owner_->write_stream_data(stream_id_, buffer);
        ec = {};
        co_return buffer.size();
    }

    void stream::close()
    {
        closed_ = true;
        channel_.cancel();
    }

    void stream::cancel()
    {
        closed_ = true;
        channel_.cancel();
    }

    void stream::push(const std::span<const std::byte> data)
    {
        if (closed_ || data.empty())
            return;
        memory::vector<std::byte> copy(data.begin(), data.end(), mr_);
        channel_.try_send(boost::system::error_code{}, std::move(copy));
    }

    void stream::notify_fin()
    {
        if (!closed_)
            channel_.try_send(boost::system::error_code{}, memory::vector<std::byte>(mr_));
    }

    // === server 实现 ===

    server::server(server_options opts)
        : opts_(std::move(opts))
        , mr_(opts_.mr)
        , peer_(opts_.peer)
    {
    }

    server::~server() noexcept
    {
        if (ssl_)
        {
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
        if (conn_)
        {
            ngtcp2_conn_del(conn_);
            conn_ = nullptr;
        }
    }

    void server::start()
    {
        // 延迟创建：首个 Initial 包到达时解析 DCID 并建立连接
        diagnose::debug(opts_.prefix, "quic: server ready (lazy setup)");
    }

    void server::close()
    {
        if (closed_)
            return;
        closed_ = true;
        for (auto &[id, st] : streams_)
        {
            (void)id;
            if (st)
                st->close();
        }
        streams_.clear();
    }

    auto server::setup_ngtcp2(const ngtcp2_cid &original_dcid, const ngtcp2_cid &peer_scid) -> bool
    {
        std::array<uint8_t, NGTCP2_MAX_CIDLEN> scid_buf{};
        if (RAND_bytes(scid_buf.data(), NGTCP2_MAX_CIDLEN) != 1)
            return false;
        scid_ = std::make_unique<ngtcp2_cid>();
        scid_->datalen = NGTCP2_MAX_CIDLEN;
        std::memcpy(scid_->data, scid_buf.data(), NGTCP2_MAX_CIDLEN);

        ngtcp2_settings settings;
        ngtcp2_settings_default(&settings);
        settings.initial_ts = now_tstamp();
        settings.max_tx_udp_payload_size = 1472;
        settings.log_printf = server_log_printf;

        ngtcp2_transport_params params;
        ngtcp2_transport_params_default(&params);
        params.initial_max_stream_data_bidi_local = 65536;
        params.initial_max_stream_data_bidi_remote = 65536;
        params.initial_max_stream_data_uni = 65536;
        params.initial_max_data = 1 << 20;
        params.initial_max_streams_bidi = 1024;
        params.initial_max_streams_uni = 1024;
        params.max_datagram_frame_size = 1400;
        params.original_dcid = original_dcid;
        params.original_dcid_present = 1;
        params.active_connection_id_limit = 2;

        ngtcp2_path_storage path_storage;
        auto *path = make_path(path_storage, opts_.udp->local_endpoint(), peer_);
        const auto rv = ngtcp2_conn_server_new(
            &conn_, &peer_scid, scid_.get(), path, NGTCP2_PROTO_VER_V1,
            &ngtcp2_callbacks_instance, &settings, &params, nullptr, this);
        if (rv != 0)
            return false;
        return true;
    }

    auto server::setup_tls() -> bool
    {
        if (!opts_.ssl_ctx)
            return false;

        ssl_ = SSL_new(opts_.ssl_ctx);
        if (!ssl_)
            return false;

        SSL_set_app_data(ssl_, this);
        SSL_set_quic_method(ssl_, &quic_method);
        SSL_set_quic_use_legacy_codepoint(ssl_, 0);
        SSL_set_accept_state(ssl_);

        // QUIC TLS 要求 transport_params 编码进 TLS 扩展
        const auto *local_params = ngtcp2_conn_get_local_transport_params2(conn_);
        std::array<std::uint8_t, 256> tp_buf{};
        const auto tp_len = ngtcp2_transport_params_encode(tp_buf.data(), tp_buf.size(), local_params);
        if (tp_len < 0)
            return false;
        if (SSL_set_quic_transport_params(ssl_, tp_buf.data(), static_cast<size_t>(tp_len)) != 1)
            return false;

        ngtcp2_conn_set_tls_native_handle(conn_, ssl_);

        const auto hs_rv = SSL_do_handshake(ssl_);
        if (hs_rv != 1)
        {
            const auto err = SSL_get_error(ssl_, hs_rv);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                return false;
        }
        return true;
    }

    auto server::send_udp(const std::span<const std::byte> data) -> net::awaitable<void>
    {
        if (closed_ || data.empty() || !opts_.udp)
            co_return;
        boost::system::error_code ec;
        co_await opts_.udp->async_send_to(net::buffer(data.data(), data.size()), peer_,
                                          net::redirect_error(net::use_awaitable, ec));
    }

    auto server::flush_handshake() -> net::awaitable<void>
    {
        // 输出握手期间累积的 QUIC 包
        while (true)
        {
            std::array<std::byte, 65536> buf{};
            ngtcp2_path_storage path_storage;
            auto *path = make_path(path_storage, opts_.udp->local_endpoint(), peer_);
            ngtcp2_pkt_info pi{};
            const auto nwrite = ngtcp2_conn_write_pkt(
                conn_, path, &pi,
                reinterpret_cast<uint8_t *>(buf.data()), buf.size(), now_tstamp());
            if (nwrite == NGTCP2_ERR_WRITE_MORE)
                break;
            if (nwrite <= 0)
                break;
            co_await send_udp(std::span<const std::byte>(buf.data(), nwrite));
        }
    }

    auto server::handle_datagram(const net::ip::udp::endpoint &from, const std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        if (closed_ || data.empty())
            co_return;
        peer_ = from;

        // 首个包：解析客户端 DCID 并延迟建立连接
        if (conn_ == nullptr)
        {
            ngtcp2_version_cid vc;
            const auto dlen = ngtcp2_pkt_decode_version_cid(
                &vc, reinterpret_cast<const uint8_t *>(data.data()), data.size(), NGTCP2_MAX_CIDLEN);
            if (dlen < 0 || vc.dcidlen == 0)
            {
                diagnose::debug(opts_.prefix, "quic: cannot decode initial DCID");
                co_return;
            }
            ngtcp2_cid original_dcid;
            original_dcid.datalen = vc.dcidlen;
            std::memcpy(original_dcid.data, vc.dcid, vc.dcidlen);
            ngtcp2_cid peer_scid;
            peer_scid.datalen = vc.scidlen;
            std::memcpy(peer_scid.data, vc.scid, vc.scidlen);
            if (!setup_ngtcp2(original_dcid, peer_scid) || !setup_tls())
            {
                diagnose::error(opts_.prefix, "quic: lazy setup failed");
                close();
                co_return;
            }
            diagnose::debug(opts_.prefix, "quic: connection created (cid len {})", vc.dcidlen);
        }

        ngtcp2_path_storage path_storage;
        auto *path = make_path(path_storage, opts_.udp->local_endpoint(), peer_);
        ngtcp2_pkt_info pi{};

        const auto rv = ngtcp2_conn_read_pkt(conn_, path, &pi,
                                             reinterpret_cast<const uint8_t *>(data.data()), data.size(),
                                             now_tstamp());
        if (rv != 0)
        {
            diagnose::debug(opts_.prefix, "quic: read_pkt error {}", static_cast<int>(rv));
            co_return;
        }

        co_await flush_handshake();
    }

    auto server::write_stream_data(const std::int64_t stream_id, const std::span<const std::byte> data)
        -> net::awaitable<fault::code>
    {
        std::size_t offset = 0;
        while (offset < data.size())
        {
            std::array<std::byte, 2048> buf{};
            ngtcp2_path_storage path_storage;
            auto *path = make_path(path_storage, opts_.udp->local_endpoint(), peer_);
            ngtcp2_pkt_info pi{};
            ngtcp2_ssize ndatalen = 0;
            ngtcp2_vec vec{reinterpret_cast<uint8_t *>(const_cast<std::byte *>(data.data() + offset)),
                           data.size() - offset};
            const auto nwrite = ngtcp2_conn_writev_stream(
                conn_, path, &pi,
                reinterpret_cast<uint8_t *>(buf.data()), buf.size(), &ndatalen,
                NGTCP2_STREAM_DATA_FLAG_NONE, stream_id, &vec, 1, now_tstamp());
            if (nwrite < 0)
            {
                if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED)
                {
                    // 流控阻塞：剩余数据无法发送，等待对端窗口更新
                    break;
                }
                if (nwrite == NGTCP2_ERR_WRITE_MORE)
                {
                    // 有更多数据待发：本次已生成包，继续循环
                    if (ndatalen > 0)
                        offset += static_cast<std::size_t>(ndatalen);
                    continue;
                }
                co_return fault::code::io_error;
            }
            if (ndatalen > 0)
                offset += static_cast<std::size_t>(ndatalen);
            if (nwrite > 0)
                co_await send_udp(std::span<const std::byte>(buf.data(), nwrite));
            if (nwrite == 0)
            {
                // 无包可发（拥塞/流控）：数据已入 ngtcp2 队列，等待 ACK 驱动重发
                break;
            }
        }
        co_return fault::code::success;
    }

    auto server::write_datagram(const std::span<const std::byte> data) -> net::awaitable<fault::code>
    {
        std::array<std::byte, 2048> buf{};
        ngtcp2_path_storage path_storage;
        auto *path = make_path(path_storage, opts_.udp->local_endpoint(), peer_);
        ngtcp2_pkt_info pi{};
        int accepted = 0;
        ngtcp2_vec dgram_vec{reinterpret_cast<uint8_t *>(const_cast<std::byte *>(data.data())), data.size()};
        const auto nwrite = ngtcp2_conn_writev_datagram(
            conn_, path, &pi,
            reinterpret_cast<uint8_t *>(buf.data()), buf.size(), &accepted, 0, 0, &dgram_vec, 1,
            now_tstamp());
        if (nwrite < 0)
            co_return fault::code::io_error;
        if (nwrite > 0)
            co_await send_udp(std::span<const std::byte>(buf.data(), nwrite));
        co_return fault::code::success;
    }

    auto server::get_stream(const std::int64_t stream_id) const -> shared_stream
    {
        const auto it = streams_.find(stream_id);
        if (it == streams_.end())
            return nullptr;
        return it->second;
    }

    auto server::open_uni_stream() -> std::int64_t
    {
        std::int64_t stream_id = 0;
        const auto rv = ngtcp2_conn_open_uni_stream(conn_, &stream_id, nullptr);
        if (rv != 0)
            return -1;
        return stream_id;
    }

    void server::on_stream_data(const std::int64_t stream_id, const std::span<const std::byte> data)
    {
        auto st = get_stream(stream_id);
        if (st)
        {
            st->push(data);
        }
    }

    void server::on_stream_open(const std::int64_t stream_id)
    {
        if (streams_.contains(stream_id))
            return;
        auto st = std::make_shared<stream>(opts_.executor, shared_from_this(), stream_id, mr_);
        streams_[stream_id] = st;
        if (on_stream)
            on_stream(st);
    }

    void server::on_stream_close(const std::int64_t stream_id)
    {
        auto it = streams_.find(stream_id);
        if (it != streams_.end())
        {
            if (it->second)
                it->second->notify_fin();
            streams_.erase(it);
        }
    }

    void server::on_datagram_data(const std::span<const std::byte> data)
    {
        if (on_datagram)
            on_datagram(memory::vector<std::byte>(data.begin(), data.end(), mr_));
    }

    void server::on_handshake_done()
    {
        if (handshake_complete_.exchange(true, std::memory_order_acq_rel))
            return;
        diagnose::debug(opts_.prefix, "quic: handshake completed");
        if (on_handshake_complete)
            on_handshake_complete();
    }

    // === client 实现 ===

    client::client(client_options opts)
        : opts_(std::move(opts))
    {
    }

    client::~client() noexcept
    {
        if (ssl_)
        {
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
        if (conn_)
        {
            ngtcp2_conn_del(conn_);
            conn_ = nullptr;
        }
    }

    void client::start()
    {
        if (!setup_ngtcp2() || !setup_tls())
        {
            diagnose::error(opts_.prefix, "quic: client setup failed");
            close();
            return;
        }
        diagnose::debug(opts_.prefix, "quic: client started");
    }

    void client::close()
    {
        if (closed_)
            return;
        closed_ = true;
    }

    auto client::setup_ngtcp2() -> bool
    {
        // 客户端生成 dcid/scid
        std::array<uint8_t, NGTCP2_MAX_CIDLEN> dcid_buf{};
        std::array<uint8_t, NGTCP2_MAX_CIDLEN> scid_buf{};
        if (RAND_bytes(dcid_buf.data(), NGTCP2_MAX_CIDLEN) != 1)
            return false;
        if (RAND_bytes(scid_buf.data(), NGTCP2_MAX_CIDLEN) != 1)
            return false;
        dcid_ = std::make_unique<ngtcp2_cid>();
        dcid_->datalen = NGTCP2_MAX_CIDLEN;
        std::memcpy(dcid_->data, dcid_buf.data(), NGTCP2_MAX_CIDLEN);
        scid_ = std::make_unique<ngtcp2_cid>();
        scid_->datalen = NGTCP2_MAX_CIDLEN;
        std::memcpy(scid_->data, scid_buf.data(), NGTCP2_MAX_CIDLEN);

        ngtcp2_settings settings;
        ngtcp2_settings_default(&settings);
        settings.initial_ts = now_tstamp();
        settings.max_tx_udp_payload_size = 1472;


        ngtcp2_transport_params params;
        ngtcp2_transport_params_default(&params);
        params.initial_max_stream_data_bidi_local = 65536;
        params.initial_max_stream_data_bidi_remote = 65536;
        params.initial_max_stream_data_uni = 65536;
        params.initial_max_data = 1 << 20;
        params.initial_max_streams_bidi = 1024;
        params.initial_max_streams_uni = 1024;
        params.max_datagram_frame_size = 1400;
        settings.log_printf = client_log_printf;

        ngtcp2_path_storage path_storage;
        auto *path = make_path(path_storage, opts_.udp->local_endpoint(), opts_.peer);
        const auto rv = ngtcp2_conn_client_new(
            &conn_, dcid_.get(), scid_.get(), path, NGTCP2_PROTO_VER_V1,
            &ngtcp2_client_callbacks_instance, &settings, &params, nullptr, this);
        if (rv != 0)
            return false;
        return true;
    }

    auto client::setup_tls() -> bool
    {
        if (!opts_.ssl_ctx)
            return false;

        ssl_ = SSL_new(opts_.ssl_ctx);
        if (!ssl_)
            return false;

        SSL_set_app_data(ssl_, this);
        SSL_set_quic_method(ssl_, &quic_method);
        SSL_set_quic_use_legacy_codepoint(ssl_, 0);
        SSL_set_connect_state(ssl_);
        SSL_set_tlsext_host_name(ssl_, opts_.host.c_str());

        // QUIC TLS 要求 transport_params 编码进 TLS 扩展
        const auto *local_params = ngtcp2_conn_get_local_transport_params2(conn_);
        std::array<std::uint8_t, 256> tp_buf{};
        const auto tp_len = ngtcp2_transport_params_encode(tp_buf.data(), tp_buf.size(), local_params);
        if (tp_len < 0)
            return false;
        if (SSL_set_quic_transport_params(ssl_, tp_buf.data(), static_cast<size_t>(tp_len)) != 1)
            return false;

        ngtcp2_conn_set_tls_native_handle(conn_, ssl_);

        const auto hs_rv = SSL_do_handshake(ssl_);
        if (hs_rv != 1)
        {
            const auto err = SSL_get_error(ssl_, hs_rv);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                return false;
        }
        return true;
    }

    auto client::send_udp(const std::span<const std::byte> data) -> net::awaitable<void>
    {
        if (closed_ || data.empty() || !opts_.udp)
            co_return;
        boost::system::error_code ec;
        co_await opts_.udp->async_send_to(net::buffer(data.data(), data.size()), opts_.peer,
                                          net::redirect_error(net::use_awaitable, ec));

    }

    auto client::flush_handshake() -> net::awaitable<void>
    {
        // 输出握手期间累积的 QUIC 包

        while (true)
        {
            std::array<std::byte, 65536> buf{};
            ngtcp2_path_storage path_storage;
            auto *path = make_path(path_storage, opts_.udp->local_endpoint(), opts_.peer);
            ngtcp2_pkt_info pi{};
            const auto nwrite = ngtcp2_conn_write_pkt(
                conn_, path, &pi,
                reinterpret_cast<uint8_t *>(buf.data()), buf.size(), now_tstamp());

            if (nwrite == NGTCP2_ERR_WRITE_MORE)
                break;
            if (nwrite <= 0)
                break;
            co_await send_udp(std::span<const std::byte>(buf.data(), nwrite));
        }
    }

    auto client::handle_datagram(const net::ip::udp::endpoint &from, const std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        if (closed_ || data.empty())
            co_return;
        if (from != opts_.peer)
            co_return;

        ngtcp2_path_storage path_storage;
        auto *path = make_path(path_storage, opts_.udp->local_endpoint(), opts_.peer);
        ngtcp2_pkt_info pi{};

        const auto rv = ngtcp2_conn_read_pkt(conn_, path, &pi,
                                             reinterpret_cast<const uint8_t *>(data.data()), data.size(),
                                             now_tstamp());
        if (rv != 0)
        {
            diagnose::debug(opts_.prefix, "quic: client read_pkt error {}", static_cast<int>(rv));
            co_return;
        }
        diagnose::debug(opts_.prefix, "quic: client read_pkt ok n={}", data.size());

        co_await flush_handshake();
    }

    auto client::open_stream() -> std::int64_t
    {
        std::int64_t stream_id = 0;
        const auto rv = ngtcp2_conn_open_bidi_stream(conn_, &stream_id, nullptr);
        if (rv != 0)
            return -1;
        return stream_id;
    }

    auto client::open_uni_stream() -> std::int64_t
    {
        std::int64_t stream_id = 0;
        const auto rv = ngtcp2_conn_open_uni_stream(conn_, &stream_id, nullptr);
        if (rv != 0)
            return -1;
        return stream_id;
    }

    auto client::write_stream_data(const std::int64_t stream_id, const std::span<const std::byte> data)
        -> net::awaitable<fault::code>
    {
        std::size_t offset = 0;
        while (offset < data.size())
        {
            std::array<std::byte, 2048> buf{};
            ngtcp2_path_storage path_storage;
            auto *path = make_path(path_storage, opts_.udp->local_endpoint(), opts_.peer);
            ngtcp2_pkt_info pi{};
            ngtcp2_ssize ndatalen = 0;
            ngtcp2_vec vec{reinterpret_cast<uint8_t *>(const_cast<std::byte *>(data.data() + offset)),
                           data.size() - offset};
            const auto nwrite = ngtcp2_conn_writev_stream(
                conn_, path, &pi,
                reinterpret_cast<uint8_t *>(buf.data()), buf.size(), &ndatalen,
                NGTCP2_STREAM_DATA_FLAG_NONE, stream_id, &vec, 1, now_tstamp());
            if (nwrite < 0)
            {
                if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED)
                    break;
                co_return fault::code::io_error;
            }
            if (ndatalen > 0)
                offset += static_cast<std::size_t>(ndatalen);
            if (nwrite > 0)
                co_await send_udp(std::span<const std::byte>(buf.data(), nwrite));
            if (nwrite == 0)
                break;
        }
        co_return fault::code::success;
    }

    auto client::write_datagram(const std::span<const std::byte> data) -> net::awaitable<fault::code>
    {
        std::array<std::byte, 2048> buf{};
        ngtcp2_path_storage path_storage;
        auto *path = make_path(path_storage, opts_.udp->local_endpoint(), opts_.peer);
        ngtcp2_pkt_info pi{};
        int accepted = 0;
        ngtcp2_vec dgram_vec{reinterpret_cast<uint8_t *>(const_cast<std::byte *>(data.data())), data.size()};
        const auto nwrite = ngtcp2_conn_writev_datagram(
            conn_, path, &pi,
            reinterpret_cast<uint8_t *>(buf.data()), buf.size(), &accepted, 0, 0, &dgram_vec, 1,
            now_tstamp());
        if (nwrite < 0)
            co_return fault::code::io_error;
        if (nwrite > 0)
            co_await send_udp(std::span<const std::byte>(buf.data(), nwrite));
        co_return fault::code::success;
    }

    void client::on_handshake_done()
    {
        if (handshake_complete_.exchange(true, std::memory_order_acq_rel))
            return;
        diagnose::debug(opts_.prefix, "quic: client handshake completed");
        if (on_handshake_complete)
            on_handshake_complete();
    }

} // namespace psm::quic
