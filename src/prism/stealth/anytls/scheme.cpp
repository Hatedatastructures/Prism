#include <prism/stealth/anytls/scheme.hpp>
#include <prism/stealth/anytls/mux/session.hpp>
#include <prism/stealth/anytls/mux/transport.hpp>
#include <prism/stealth/anytls/padding.hpp>
#include <prism/connect.hpp>
#include <prism/connect/util.hpp>
#include <prism/connect/tunnel/forward.hpp>
#include <prism/config.hpp>
#include <prism/transport/encrypted.hpp>
#include <prism/transport/preview.hpp>
#include <prism/protocol/types.hpp>
#include <prism/protocol/common/target.hpp>
#include <prism/protocol/common/framing.hpp>
#include <prism/protocol/common/address.hpp>
#include <prism/trace.hpp>
#include <prism/fault/handling.hpp>
#include <prism/memory/container.hpp>
#include <prism/memory/pool.hpp>

#include <boost/asio.hpp>
#include <openssl/sha.h>

#include <array>
#include <cstring>

namespace psm::stealth::anytls
{
    using hello_features = protocol::tls::hello_features;

    namespace
    {
        // std::array<uint8_t, 32> 的哈希函数
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

        using user_map_type = std::unordered_map<
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
            auto bitmap = recognition::tls::build_feature_bitmap(features);

            if (recognition::tls::has_feature(bitmap, recognition::tls::has_ech))
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

    static auto build_user_map(const memory::vector<user> &users)
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

        // Step 1: TLS 握手（Path A 终结模式）
        auto raw = connect::peel_to_raw(std::move(ctx.inbound));
        if (!raw)
        {
            trace::warn("[AnyTLS] Cannot unwrap transport layers");
            result.error = fault::code::not_supported;
            co_return result;
        }

        auto preread_span = std::span<const std::byte>(ctx.preread.data(), ctx.preread.size());
        auto clean_inbound = transport::wrap_with_preview(
            std::move(raw), preread_span, ctx.session->frame_arena.get());

        auto [ssl_ec, ssl_stream, recovered] = co_await transport::encrypted::ssl_handshake(
            std::move(clean_inbound), *ctx.session->server_ctx.ssl_ctx);

        if (fault::failed(ssl_ec) || !ssl_stream)
        {
            ctx.inbound = std::move(recovered);
            result.error = ssl_ec;
            trace::warn("[AnyTLS] TLS handshake failed: {}", fault::describe(ssl_ec));
            co_return result;
        }

        trace::debug("[AnyTLS] TLS handshake succeeded");

        auto encrypted_trans = std::make_shared<transport::encrypted>(ssl_stream);

        // Step 2: 读取 SHA-256(password) (32 bytes)
        std::array<std::byte, 32> hash_buf{};
        std::error_code read_ec;
        auto hash_read = co_await transport::async_read(*encrypted_trans,
            std::span<std::byte>(hash_buf.data(), hash_buf.size()), read_ec);
        if (read_ec || hash_read < 32)
        {
            trace::warn("[AnyTLS] Failed to read password hash: {}", read_ec.message());
            result.error = fault::to_code(read_ec);
            co_return result;
        }

        // Step 3: 读取 padding_len (2 bytes BE) + padding
        std::array<std::byte, 2> pad_len_buf{};
        auto pad_read = co_await transport::async_read(*encrypted_trans,
            std::span<std::byte>(pad_len_buf.data(), pad_len_buf.size()), read_ec);
        if (read_ec || pad_read < 2)
        {
            trace::warn("[AnyTLS] Failed to read padding length: {}", read_ec.message());
            result.error = fault::to_code(read_ec);
            co_return result;
        }

        auto pad_len = (static_cast<std::uint16_t>(pad_len_buf[0]) << 8) |
                       static_cast<std::uint16_t>(pad_len_buf[1]);
        if (pad_len > 0)
        {
            memory::vector<std::byte> padding(pad_len);
            co_await transport::async_read(*encrypted_trans,
                std::span<std::byte>(padding.data(), padding.size()), read_ec);
            if (read_ec)
            {
                trace::warn("[AnyTLS] Failed to read padding: {}", read_ec.message());
                result.error = fault::to_code(read_ec);
                co_return result;
            }
        }

        // Step 4: 验证用户身份
        auto user_map = build_user_map(cfg.users);
        std::array<std::uint8_t, 32> key;
        std::memcpy(key.data(), hash_buf.data(), 32);
        auto it = user_map.find(key);
        if (it == user_map.end())
        {
            trace::warn("[AnyTLS] Authentication failed: unknown password hash");
            result.error = fault::code::auth_failed;
            co_return result;
        }

        trace::debug("[AnyTLS] Authenticated as user: {}", it->second);

        // Step 5: 创建 padding_factory
        auto padding = std::make_shared<padding_factory>(
            std::string_view(cfg.padding_scheme.data(), cfg.padding_scheme.size()));

        // Step 6: 创建 anytls_session
        // 后续 stream 回调：解析 SOCKS 地址 → dial + tunnel
        auto session_ptr = ctx.session;
        auto on_new_stream = [session_ptr](std::uint32_t stream_id,
                                     std::shared_ptr<transport::transmission> inbound,
                                     std::vector<std::uint8_t> preread_data)
        {
            net::co_spawn(session_ptr->worker_ctx.io_context.get_executor(),
                [inbound = std::move(inbound),
                 preread = std::move(preread_data),
                 session_ptr]() -> net::awaitable<void>
                {
                    if (preread.empty())
                    {
                        trace::warn("{} Subsequent stream with empty preread", tag);
                        co_return;
                    }

                    // safe: casting byte buffer to const byte span for SOCKS target parsing
                    auto preread_span = std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(preread.data()),
                        preread.size());

                    auto [parse_ec, target] = parse_socks_target(preread_span, session_ptr->frame_arena.get());
                    if (fault::failed(parse_ec))
                    {
                        trace::warn("{} failed to parse SOCKS target: {}", tag, fault::describe(parse_ec));
                        co_return;
                    }

                    trace::info("{} -> {}:{}", tag, target.host, target.port);
                    co_await psm::connect::forward(*session_ptr, {"AnyTLS", target, std::move(inbound)});
                },
                net::detached);
        };

        auto session = std::make_shared<anytls_session>(
            encrypted_trans, padding, std::move(on_new_stream));

        // Step 7: 启动 recv_loop
        session->start();

        // Step 8: 等待第一个 stream
        auto [wait_ec, stream_info] = co_await session->wait_first_stream();
        if (fault::failed(wait_ec))
        {
            trace::warn("[AnyTLS] Failed to get first stream: {}", fault::describe(wait_ec));
            session->close();
            result.error = wait_ec;
            co_return result;
        }

        auto [stream_id, preread_data] = std::move(stream_info);

        trace::debug("[AnyTLS] First stream ready, stream_id={}, preread={} bytes",
                     stream_id, preread_data.size());

        // Step 9: 解析第一个 stream 的 SOCKS 地址并直接 forward
        if (!preread_data.empty())
        {
            // safe: casting byte buffer to const byte span for SOCKS target parsing
            auto preread_span = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(preread_data.data()),
                preread_data.size());

            auto [parse_ec, target] = parse_socks_target(preread_span, ctx.session->frame_arena.get());
            if (fault::failed(parse_ec))
            {
                trace::warn("{} failed to parse first stream SOCKS target: {}", tag, fault::describe(parse_ec));
                result.error = parse_ec;
                co_return result;
            }

            trace::info("{} -> {}:{}", tag, target.host, target.port);

            auto channel = session->get_stream_channel(stream_id);
            auto stream_transport = std::make_shared<anytls_stream_transport>(
                session, stream_id, channel);

            // spawn 独立协程处理第一个 stream 的 forward
            net::co_spawn(session_ptr->worker_ctx.io_context.get_executor(),
                [session_ptr, target = std::move(target),
                 stream_transport = std::move(stream_transport)]() -> net::awaitable<void>
                {
                    co_await psm::connect::forward(*session_ptr, {"AnyTLS", target, std::move(stream_transport)});
                },
                net::detached);
        }

        // anytls_session 持有 encrypted_trans，recv_loop 自动处理后续 stream。
        // 返回 detected=tls 让 session 不再做 protocol dispatch。
        result.detected = protocol::protocol_type::tls;

        co_return result;
    }
} // namespace psm::stealth::anytls
