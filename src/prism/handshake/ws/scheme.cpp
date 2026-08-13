/**
 * @file scheme.cpp
 * @brief WebSocket 伪装方案实现
 */

#include <prism/diagnose/diagnose.hpp>
#include <prism/foundation/fault/handling.hpp>
#include <prism/handshake/ws/codec.hpp>
#include <prism/handshake/ws/scheme.hpp>
#include <prism/handshake/ws/transport.hpp>
#include <prism/net/connection/types.hpp>
#include <prism/net/connection/util.hpp>
#include <prism/net/transport/encrypted.hpp>
#include <prism/net/transport/preview.hpp>
#include <prism/resource/session.hpp>
#include <prism/settings/settings.hpp>

#include <boost/asio.hpp>
#include <openssl/ssl.h>

using namespace psm::diagnose;

namespace psm::handshake::ws
{

    namespace net = boost::asio;
    namespace ssl = net::ssl;

    namespace
    {
        /// HTTP 请求解析结果
        struct http_request
        {
            bool valid{false};
            bool is_get{false};
            bool is_upgrade{false};
            memory::string path;
            memory::string sec_key;
            memory::string host;
        };

        /**
         * @brief 逐行解析 HTTP/1.1 请求头（CRLF 结尾）
         * @param data 请求头原始字节序列
         * @param out 解析结果输出
         * @return 是否解析成功
         */
        [[nodiscard]] auto parse_http_request(const std::span<const std::byte> data, http_request &out)
            -> bool
        {
            const std::string_view text(reinterpret_cast<const char *>(data.data()), data.size());
            std::size_t line_start = 0;
            int line_count = 0;
            bool headers_done = false;

            while (line_start < text.size() && line_count < 64)
            {
                const auto line_end = text.find("\r\n", line_start);
                const auto line = (line_end == std::string_view::npos)
                                      ? text.substr(line_start)
                                      : text.substr(line_start, line_end - line_start);

                if (line.empty())
                {
                    headers_done = true;
                    break;
                }

                if (line_count == 0)
                {
                    // 请求行：GET /path HTTP/1.1
                    if (line.rfind("GET ", 0) == 0)
                    {
                        out.is_get = true;
                    }
                    const auto first_space = line.find(' ');
                    const auto second_space = (first_space == std::string_view::npos)
                                                  ? std::string_view::npos
                                                  : line.find(' ', first_space + 1);
                    if (first_space != std::string_view::npos && second_space != std::string_view::npos)
                    {
                        out.path.assign(line.substr(first_space + 1, second_space - first_space - 1));
                    }
                }
                else
                {
                    const auto colon = line.find(':');
                    if (colon == std::string_view::npos)
                    {
                        return false;
                    }
                    const auto name = line.substr(0, colon);
                    auto value = line.substr(colon + 1);
                    while (!value.empty() && value.front() == ' ')
                    {
                        value.remove_prefix(1);
                    }

                    if (name == "Upgrade" && value == "websocket")
                    {
                        out.is_upgrade = true;
                    }
                    else if (name == "Sec-WebSocket-Key")
                    {
                        out.sec_key.assign(value);
                    }
                    else if (name == "Host")
                    {
                        out.host.assign(value);
                    }
                }

                if (line_end == std::string_view::npos)
                {
                    break;
                }
                line_start = line_end + 2;
                ++line_count;
            }

            out.valid = headers_done && out.is_get && out.is_upgrade && !out.sec_key.empty();
            return true;
        }
    } // namespace

    auto scheme::name() const noexcept -> std::string_view
    {
        return "ws";
    }

    auto scheme::active(const psm::settings &cfg) const noexcept -> bool
    {
        return cfg.stealth.ws.enabled();
    }

    auto scheme::snis(const psm::settings &cfg) const -> memory::vector<memory::string>
    {
        return make_sni_list(cfg.stealth.ws.server_names);
    }

    auto scheme::guess(const psm::settings &cfg) const -> verify_result
    {
        return {.score = 100, .solo_flag = 0, .note = "ws: rely on SNI match"};
    }

    auto scheme::handshake(handshake::handshake_context ctx) -> net::awaitable<handshake::handshake_result>
    {
        handshake::handshake_result result;

        if (!ctx.session)
        {
            result.error = fault::code::not_supported;
            co_return result;
        }

        if (!ctx.session->worker->process->ssl)
        {
            diagnose::warn(prefix_, "No SSL context configured");
            result.error = fault::code::not_supported;
            co_return result;
        }

        const auto &cfg = ctx.session->worker->process->cfg->stealth.ws;

        auto raw = connect::peel(std::move(ctx.transport));
        if (!raw)
        {
            diagnose::debug(prefix_, "Cannot unwrap transport layers");
            result.error = fault::code::not_supported;
            co_return result;
        }

        // 独立 SSL_CTX（复用默认 ALPN 行为）
        auto ws_ssl_ctx = std::make_shared<ssl::context>(ssl::context::tlsv13);
        {
            auto &src_ctx = *ctx.session->worker->process->ssl;
            auto *src_native = src_ctx.native_handle();
            auto *dst_native = ws_ssl_ctx->native_handle();

            SSL_CTX_use_certificate(dst_native, SSL_CTX_get0_certificate(src_native));
            SSL_CTX_use_PrivateKey(dst_native, SSL_CTX_get0_privatekey(src_native));
            SSL_CTX_set_min_proto_version(dst_native, SSL_CTX_get_min_proto_version(src_native));
            SSL_CTX_set_max_proto_version(dst_native, SSL_CTX_get_max_proto_version(src_native));
            SSL_CTX_set_session_cache_mode(dst_native, SSL_CTX_get_session_cache_mode(src_native));
        }

        auto preread_span = std::span<const std::byte>(ctx.preread.data(), ctx.preread.size());
        auto clean_inbound = psm::transport::wrap_with_preview(std::move(raw), preread_span);

        auto [ssl_ec, ssl_stream, recovered] =
            co_await psm::transport::encrypted::ssl_handshake(std::move(clean_inbound), *ws_ssl_ctx);

        if (fault::failed(ssl_ec) || !ssl_stream)
        {
            ctx.transport = std::move(recovered);
            result.error = ssl_ec;
            diagnose::debug(prefix_, "TLS handshake failed: {}", fault::describe(ssl_ec));
            co_return result;
        }

        auto encrypted_trans = std::make_shared<psm::transport::encrypted>(ssl_stream);

        // 读取并解析 HTTP 升级请求（≤ 8KB）
        memory::vector<std::byte> http_buf(memory::current_resource());
        http_buf.reserve(8192);
        std::array<std::byte, 2048> chunk{};
        bool upgrade_ok = false;
        http_request req;
        for (int i = 0; i < 8; ++i)
        {
            std::error_code read_ec;
            const auto n = co_await encrypted_trans->async_read_some(chunk, read_ec);
            if (read_ec || n == 0)
            {
                break;
            }
            http_buf.insert(http_buf.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(n));
            if (!parse_http_request(http_buf, req))
            {
                break;
            }
            if (req.valid)
            {
                upgrade_ok = true;
                break;
            }
        }

        if (!upgrade_ok)
        {
            diagnose::debug(prefix_, "ws: no valid upgrade request");
            result.detected = psm::connect::protocol_type::tls;
            result.transport = std::move(encrypted_trans);
            co_return result;
        }

        // 路径匹配
        const std::string_view req_path(req.path.data(), req.path.size());
        const std::string_view expected(cfg.path.data(), cfg.path.size());
        if (req_path != expected && !(expected == "/" && req_path.rfind('/', 0) == 0))
        {
            diagnose::debug(prefix_, "ws: path mismatch '{}'", req_path);
            result.detected = psm::connect::protocol_type::tls;
            result.transport = std::move(encrypted_trans);
            co_return result;
        }

        // 计算 Sec-WebSocket-Accept 并响应 101
        std::array<char, 28> accept{};
        if (!codec::compute_accept(std::string_view(req.sec_key.data(), req.sec_key.size()), accept))
        {
            result.detected = psm::connect::protocol_type::tls;
            result.transport = std::move(encrypted_trans);
            co_return result;
        }

        memory::string response(memory::current_resource());
        response = "HTTP/1.1 101 Switching Protocols\r\n"
                   "Upgrade: websocket\r\n"
                   "Connection: Upgrade\r\n"
                   "Sec-WebSocket-Accept: ";
        response.append(accept.data(), accept.size());
        response.append("\r\n\r\n");

        std::error_code w_ec;
        co_await psm::transport::async_write(
            *encrypted_trans,
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(response.data()), response.size()),
            w_ec);
        if (w_ec)
        {
            result.detected = psm::connect::protocol_type::tls;
            result.transport = std::move(encrypted_trans);
            co_return result;
        }

        // 升级成功：HTTP 请求之后的字节（首个 WS 帧粘包）经 preview 回放
        const std::string_view http_text(reinterpret_cast<const char *>(http_buf.data()), http_buf.size());
        const auto header_end = http_text.find("\r\n\r\n");
        std::size_t consumed = http_buf.size();
        if (header_end != std::string_view::npos)
        {
            consumed = header_end + 4;
        }

        psm::transport::shared_transmission ws_next = encrypted_trans;
        if (consumed < http_buf.size())
        {
            auto extra = std::span<const std::byte>(http_buf.data() + consumed, http_buf.size() - consumed);
            ws_next = psm::transport::wrap_with_preview(encrypted_trans, extra);
        }

        auto ws_transport = make_transport(ws_next, memory::current_resource());

        diagnose::debug(prefix_, "ws: upgraded, path={}", req_path);
        result.transport = std::static_pointer_cast<psm::transport::transmission>(ws_transport);
        result.detected = psm::connect::protocol_type::unknown;
        result.error = fault::code::success;
        co_return result;
    }

} // namespace psm::handshake::ws
