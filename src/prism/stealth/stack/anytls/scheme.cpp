#include <prism/stealth/stack/anytls/scheme.hpp>

#include <prism/config.hpp>
#include <prism/connect.hpp>
#include <prism/connect/tunnel/forward.hpp>
#include <prism/connect/util.hpp>
#include <prism/fault/handling.hpp>
#include <prism/memory/container.hpp>
#include <prism/memory/pool.hpp>
#include <prism/protocol/common/address.hpp>
#include <prism/protocol/common/framing.hpp>
#include <prism/protocol/common/target.hpp>
#include <prism/protocol/types.hpp>
#include <prism/stealth/stack/anytls/mux/session.hpp>
#include <prism/stealth/stack/anytls/mux/transport.hpp>
#include <prism/stealth/stack/anytls/padding.hpp>
#include <prism/trace.hpp>
#include <prism/transport/encrypted.hpp>
#include <prism/transport/preview.hpp>

#include <boost/asio.hpp>
#include <openssl/sha.h>

#include <array>
#include <cstring>

namespace psm::stealth::anytls
{

    using hello_features = protocol::tls::hello_features;

    namespace
    {
        struct sha256_hash
        {
            auto operator()(const std::array<std::uint8_t, 32> &key) const
                -> std::size_t
            {
                std::size_t h = 0;
                for (std::size_t i = 0; i < 32; i += sizeof(std::size_t))
                {
                    std::size_t v = 0;
                    std::memcpy(&v, key.data() + i, std::min(sizeof(std::size_t), 32 - i));
                    h ^= v + 0x9e3779b9 + (h << 6) + (h >> 2);
                }
                return h;
            }
        };

        using user_map_type = memory::unordered_map<
            std::array<std::uint8_t, 32>, memory::string, sha256_hash>;

        auto parse_socks_target(std::span<const std::byte> data, memory::resource_pointer mr)
            -> std::pair<fault::code, protocol::target>
        {
            protocol::target target(mr);

            // safe: casting byte span to uint8_t span for protocol frame parsing, same memory layout
            auto buf = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(data.data()), data.size());

            if (buf.empty())
            {
                return {fault::code::bad_message, std::move(target)};
            }

            const auto atyp = buf[0];
            buf = buf.subspan(1);

            switch (atyp)
            {
            case 0x01: // IPv4
            {
                auto [ec, addr] = protocol::common::framing::parse_ipv4(buf);
                if (fault::failed(ec))
                    return {ec, std::move(target)};
                buf = buf.subspan(4);
                auto [pec, port] = protocol::common::framing::parse_port(buf);
                if (fault::failed(pec))
                    return {pec, std::move(target)};

                std::array<char, INET_ADDRSTRLEN> ip_str{};
                inet_ntop(AF_INET, addr.bytes.data(), ip_str.data(), ip_str.size());
                target.host.assign(ip_str.data());
                target.port = memory::string(std::to_string(port), mr);
                return {fault::code::success, std::move(target)};
            }
            case 0x03: // Domain
            {
                auto [ec, addr] = protocol::common::framing::parse_domain(buf);
                if (fault::failed(ec))
                    return {ec, std::move(target)};
                buf = buf.subspan(1 + addr.length);
                auto [pec, port] = protocol::common::framing::parse_port(buf);
                if (fault::failed(pec))
                    return {pec, std::move(target)};

                target.host = addr.to_string(mr);
                target.port = memory::string(std::to_string(port), mr);
                return {fault::code::success, std::move(target)};
            }
            case 0x04: // IPv6
            {
                auto [ec, addr] = protocol::common::framing::parse_ipv6(buf);
                if (fault::failed(ec))
                    return {ec, std::move(target)};
                buf = buf.subspan(16);
                auto [pec, port] = protocol::common::framing::parse_port(buf);
                if (fault::failed(pec))
                    return {pec, std::move(target)};

                std::array<char, INET6_ADDRSTRLEN> ip_str{};
                inet_ntop(AF_INET6, addr.bytes.data(), ip_str.data(), ip_str.size());
                target.host.assign(ip_str.data());
                target.port = memory::string(std::to_string(port), mr);
                return {fault::code::success, std::move(target)};
            }
            default:
                return {fault::code::bad_message, std::move(target)};
            }
        }

        constexpr std::string_view tag = "[AnyTLS]";

        auto build_user_map(const memory::vector<user> &users)
            -> user_map_type
        {
            user_map_type map;
            for (const auto &u : users)
            {
                std::array<std::uint8_t, SHA256_DIGEST_LENGTH> digest{};
                // safe: SSL API requires unsigned char*, string data is not modified by SHA256
                SHA256(reinterpret_cast<const std::uint8_t *>(u.password.data()),
                       u.password.size(), digest.data());
                map[digest] = memory::string(u.username.data(), u.username.size());
            }
            return map;
        }

        struct auth_frame
        {
            std::array<std::byte, 32> password_hash{}; ///< SHA-256(password)
        };

        struct tls_hs_result
        {
            fault::code error{fault::code::success};                  ///< 错误码
            std::shared_ptr<transport::encrypted> encrypted_trans;    ///< 加密传输层
            transport::shared_transmission recovered;                 ///< 失败时恢复的传输层
        };

        auto perform_tls_handshake(stealth::handshake_context &ctx)
            -> net::awaitable<tls_hs_result>
        {
            tls_hs_result res;

            auto raw = connect::peel(std::move(ctx.inbound));
            if (!raw)
            {
                trace::warn("[AnyTLS] Cannot unwrap transport layers");
                res.error = fault::code::not_supported;
                co_return res;
            }

            auto preread_span = std::span<const std::byte>(ctx.preread.data(), ctx.preread.size());
            auto clean_inbound = transport::wrap_with_preview(
                std::move(raw), preread_span, ctx.session->frame_arena.get());

            auto [ssl_ec, ssl_stream, recovered] = co_await transport::encrypted::ssl_handshake(
                std::move(clean_inbound), *ctx.session->server_ctx.ssl_ctx);

            if (fault::failed(ssl_ec) || !ssl_stream)
            {
                res.recovered = std::move(recovered);
                trace::warn("[AnyTLS] TLS handshake failed: {}", fault::describe(ssl_ec));
                res.error = ssl_ec;
                co_return res;
            }

            trace::debug("[AnyTLS] TLS handshake succeeded");
            res.encrypted_trans = std::make_shared<transport::encrypted>(ssl_stream);
            co_return res;
        }

        auto read_auth_frame(transport::encrypted &trans,
                              auth_frame &frame)
            -> net::awaitable<fault::code>
        {
            std::error_code read_ec;
            auto hash_read = co_await transport::async_read(trans,
                std::span<std::byte>(frame.password_hash.data(), frame.password_hash.size()),
                read_ec);
            if (read_ec || hash_read < 32)
            {
                trace::warn("[AnyTLS] Failed to read password hash: {}", read_ec.message());
                co_return fault::to_code(read_ec);
            }

            std::array<std::byte, 2> pad_len_buf{};
            auto pad_read = co_await transport::async_read(trans,
                std::span<std::byte>(pad_len_buf.data(), pad_len_buf.size()), read_ec);
            if (read_ec || pad_read < 2)
            {
                trace::warn("[AnyTLS] Failed to read padding length: {}", read_ec.message());
                co_return fault::to_code(read_ec);
            }

            auto pad_len = (static_cast<std::uint16_t>(pad_len_buf[0]) << 8) |
                           static_cast<std::uint16_t>(pad_len_buf[1]);
            if (pad_len > 0)
            {
                memory::vector<std::byte> padding(pad_len);
                co_await transport::async_read(trans,
                    std::span<std::byte>(padding.data(), padding.size()), read_ec);
                if (read_ec)
                {
                    trace::warn("[AnyTLS] Failed to read padding: {}", read_ec.message());
                    co_return fault::to_code(read_ec);
                }
            }

            co_return fault::code::success;
        }

        auto verify_user(const auth_frame &frame,
                          const memory::vector<user> &users)
            -> const memory::string *
        {
            auto user_map = build_user_map(users);
            std::array<std::uint8_t, 32> key;
            std::memcpy(key.data(), frame.password_hash.data(), 32);
            auto it = user_map.find(key);
            if (it == user_map.end())
            {
                trace::warn("[AnyTLS] Authentication failed: unknown password hash");
                return nullptr;
            }
            trace::debug("[AnyTLS] Authenticated as user: {}", it->second);
            return &it->second;
        }

        auto handle_subsequent_stream(context::session *session_ptr,
                                        std::shared_ptr<transport::transmission> inbound,
                                        memory::vector<std::uint8_t> preread_data)
            -> net::awaitable<void>
        {
            if (preread_data.empty())
            {
                trace::warn("{} Subsequent stream with empty preread", tag);
                co_return;
            }

            // safe: casting byte buffer to const byte span for SOCKS target parsing
            auto preread_span = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(preread_data.data()),
                preread_data.size());

            auto [parse_ec, target] = parse_socks_target(
                preread_span, session_ptr->frame_arena.get());
            if (fault::failed(parse_ec))
            {
                trace::warn("{} failed to parse SOCKS target: {}",
                    tag, fault::describe(parse_ec));
                co_return;
            }

            trace::info("{} -> {}:{}", tag, target.host, target.port);
            co_await psm::connect::forward(
                *session_ptr, {"AnyTLS", target, std::move(inbound)});
        }


        auto make_stream_callback(context::session *session_ptr,
                                   std::shared_ptr<void> keepalive)
            -> anytls_session::stream_callback
        {
            return [session_ptr, keepalive = std::move(keepalive)](std::uint32_t /*stream_id*/,
                                  std::shared_ptr<transport::transmission> inbound,
                                  memory::vector<std::uint8_t> preread_data)
            {
                auto subsequent_task = [inbound = std::move(inbound),
                                         preread = std::move(preread_data),
                                         session_ptr, keepalive]() -> net::awaitable<void>
                {
                    try
                    {
                        co_await handle_subsequent_stream(session_ptr,
                            std::move(inbound), std::move(preread));
                    }
                    catch (const std::exception &e)
                    {
                        trace::error("{} subsequent stream exception: {}", tag, e.what());
                    }
                    catch (...)
                    {
                        trace::error("{} subsequent stream unknown exception", tag);
                    }
                };
                net::co_spawn(session_ptr->worker_ctx.io_context.get_executor(),
                    std::move(subsequent_task), net::detached);
            };
        }

        auto handle_first_stream(std::shared_ptr<anytls_session> anytls_sess,
                                  context::session *session_ptr,
                                  memory::resource_pointer frame_arena_mr,
                                  std::shared_ptr<void> keepalive)
            -> net::awaitable<fault::code>
        {
            auto [wait_ec, stream_info] = co_await anytls_sess->wait_first_stream();
            if (fault::failed(wait_ec))
            {
                trace::warn("[AnyTLS] Failed to get first stream: {}", fault::describe(wait_ec));
                anytls_sess->close();
                co_return wait_ec;
            }

            auto [stream_id, preread_data] = std::move(stream_info);
            trace::debug("[AnyTLS] First stream ready, stream_id={}, preread={} bytes",
                         stream_id, preread_data.size());

            if (preread_data.empty())
            {
                co_return fault::code::success;
            }

            // safe: casting byte buffer to const byte span for SOCKS target parsing
            auto preread_span = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(preread_data.data()),
                preread_data.size());

            auto [parse_ec, target] = parse_socks_target(preread_span, frame_arena_mr);
            if (fault::failed(parse_ec))
            {
                trace::warn("{} failed to parse first stream SOCKS target: {}",
                    tag, fault::describe(parse_ec));
                anytls_sess->close();
                co_return parse_ec;
            }

            trace::info("{} -> {}:{}", tag, target.host, target.port);

            // 第一个流的 SYNACK：v2+ 客户端等待此确认后才发送后续数据
            std::error_code synack_ec;
            co_await anytls_sess->write_synack(stream_id, synack_ec);
            if (synack_ec)
            {
                trace::warn("{} failed to send SYNACK for first stream: {}",
                    tag, synack_ec.message());
            }

            auto channel = anytls_sess->get_stream_channel(stream_id);
            auto stream_transport = std::make_shared<anytls_stream_transport>(
                anytls_sess, stream_id, channel);

            auto forward_task = [session_ptr, keepalive = std::move(keepalive),
                                  target = std::move(target),
                                  stream_transport = std::move(stream_transport)]() -> net::awaitable<void>
            {
                try
                {
                    co_await psm::connect::forward(
                        *session_ptr, {"AnyTLS", target, std::move(stream_transport)});
                }
                catch (const std::exception &e)
                {
                    trace::error("{} first stream forward exception: {}", tag, e.what());
                }
                catch (...)
                {
                    trace::error("{} first stream forward unknown exception", tag);
                }
            };
            net::co_spawn(session_ptr->worker_ctx.io_context.get_executor(),
                std::move(forward_task), net::detached);

            co_return fault::code::success;
        }

    } // namespace

    auto scheme::active(const psm::config &cfg) const noexcept
        -> bool
    {
        return cfg.stealth.anytls.enabled();
    }


    auto scheme::name() const noexcept
        -> std::string_view
    {
        return "anytls";
    }


    auto scheme::snis(const psm::config &cfg) const
        -> memory::vector<memory::string>
    {
        return make_sni_list(cfg.stealth.anytls.server_names);
    }


    auto scheme::verify(const hello_features &features,
                         std::span<const std::byte> raw,
                         const psm::config &cfg) const
        -> verify_result
    {
        if (!cfg.stealth.anytls.ech_key.empty())
        {
            auto bitmap = recognition::tls::build_bitmap(features);

            if (recognition::tls::has_feature(bitmap, recognition::tls::feature_bit::has_ech))
            {
                trace::debug("[AnyTLS] ECH extension present, key configured");
                return {
                    .score = 300,
                    .solo_flag = 0,
                    .note = "ECH extension present, may be AnyTLS"};
            }
        }

        return {.score = 0, .solo_flag = 0, .note = "no ECH"};
    }


    auto scheme::guess(const psm::config &cfg) const
        -> verify_result
    {
        return {
            .score = 100,
            .solo_flag = 0,
            .note = "AnyTLS: rely on SNI match"};
    }


    auto scheme::handshake(stealth::handshake_context ctx)
        -> net::awaitable<stealth::handshake_result>
    {
        stealth::handshake_result result;

        if (!ctx.session)
        {
            result.error = fault::code::not_supported;
            co_return result;
        }

        if (!ctx.session->server_ctx.ssl_ctx)
        {
            trace::warn("[AnyTLS] No SSL context configured");
            result.error = fault::code::not_supported;
            co_return result;
        }

        const auto &cfg = ctx.cfg->stealth.anytls;

        auto hs_res = co_await perform_tls_handshake(ctx);
        if (fault::failed(hs_res.error))
        {
            ctx.inbound = std::move(hs_res.recovered);
            result.error = hs_res.error;
            co_return result;
        }

        auth_frame frame;
        auto read_ec = co_await read_auth_frame(*hs_res.encrypted_trans, frame);
        if (fault::failed(read_ec))
        {
            result.polluted = true;
            result.error = read_ec;
            co_return result;
        }

        auto username = verify_user(frame, cfg.users);
        if (!username)
        {
            result.polluted = true;
            result.error = fault::code::auth_failed;
            co_return result;
        }

        auto scheme_view = std::string_view(cfg.padding_scheme.data(), cfg.padding_scheme.size());
        auto padding = std::make_shared<padding_factory>(scheme_view);

        auto keepalive_copy = ctx.session_keepalive; // 拷贝给 handle_first_stream
        auto on_new_stream = make_stream_callback(ctx.session, std::move(ctx.session_keepalive));

        auto anytls_sess = std::make_shared<anytls_session>(
            hs_res.encrypted_trans, padding, std::move(on_new_stream));
        anytls_sess->start();

        auto stream_ec = co_await handle_first_stream(
            anytls_sess, ctx.session, ctx.session->frame_arena.get(), std::move(keepalive_copy));
        if (fault::failed(stream_ec))
        {
            result.polluted = true;
            result.error = stream_ec;
            co_return result;
        }

        result.detected = protocol::protocol_type::unknown;
        result.error = fault::code::success;

        co_return result;
    }

} // namespace psm::stealth::anytls
