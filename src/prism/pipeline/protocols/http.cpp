#include <prism/pipeline/protocols/http.hpp>
#include <protocol.hpp>
#include <prism/agent/account/directory.hpp>
#include <prism/crypto/sha224.hpp>
#include <prism/crypto/base64.hpp>
#include <prism/memory/container.hpp>
#include <string_view>
#include <algorithm>

// HTTP 代理响应常量
constexpr std::string_view HttpStr = "[Pipeline.Http]";
constexpr std::string_view Resp200 = "HTTP/1.1 200 Connection Established\r\n\r\n";
constexpr std::string_view Resp403 = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
constexpr std::string_view Resp407 = "HTTP/1.1 407 Proxy Authentication Required\r\n"
                                     "Proxy-Authenticate: Basic\r\n"
                                     "Content-Length: 0\r\n"
                                     "\r\n";
constexpr std::string_view Resp502 = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
constexpr std::string_view BasicPrefix = "Basic ";

namespace psm::pipeline
{
    namespace account = psm::agent::account;

    /**
     * @brief 检查字符串是否以指定前缀开头（不区分大小写）
     * @param str 待检查字符串
     * @param prefix 前缀
     * @return 匹配返回 true
     */
    [[nodiscard]] bool iequals_prefix(const std::string_view str, const std::string_view prefix) noexcept
    {
        return str.size() > prefix.size() && std::ranges::equal(str.substr(0, prefix.size()), prefix, {}, tolower, tolower);
    }

    auto http(session_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        // 创建 HTTP 流连接器
        channel::connector stream(std::move(ctx.inbound));
        channel::transport::shared_transmission outbound;

        // 重置帧内存池，准备处理请求
        ctx.frame_arena.reset();
        auto mr = ctx.frame_arena.get();
        beast::basic_flat_buffer read_buffer(protocol::http::network_allocator{mr});

        // 如果有预读数据，填入缓冲区
        if (!data.empty())
        {
            auto dest = read_buffer.prepare(data.size());
            std::memcpy(dest.data(), data.data(), data.size());
            read_buffer.commit(data.size());
        }

        protocol::http::request req(mr);
        {
            // 读取并解析 HTTP 请求
            if (fault::failed(co_await protocol::http::async_read(stream, req, read_buffer, mr)))
            {
                trace::warn("{} read request failed", HttpStr);
                co_return;
            }

            // 写入响应并返回的辅助协程
            auto respond = [&](const std::string_view response) -> net::awaitable<void>
            {
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                co_await net::async_write(stream, net::buffer(response), token);
            };

            // HTTP 代理认证（当 account_directory 已配置时启用）
            if (ctx.account_directory_ptr)
            {   // 检查 http 字段里的 Proxy-Authorization 头
                const auto auth_header = req.at(protocol::http::field::proxy_authorization);

                // 未提供认证信息或不支持的非 Basic 方案，返回 407
                if (!iequals_prefix(auth_header, BasicPrefix))
                {
                    if (auth_header.empty())
                    {
                        trace::warn("{} authentication required", HttpStr);
                    }
                    else
                    {
                        trace::warn("{} unsupported auth scheme: {}", HttpStr, auth_header);
                    }
                    co_await respond(Resp407);
                    co_return;
                }

                // Base64 解码 credential，提取 password 并验证
                const auto decoded = crypto::base64_decode(auth_header.substr(BasicPrefix.size()));
                const auto colon_pos = decoded.find(':');

                if (colon_pos != std::string::npos && colon_pos < decoded.size() - 1)
                {
                    const auto password = std::string_view(decoded).substr(colon_pos + 1);
                    const auto credential = crypto::sha224(password);
                    auto lease = account::try_acquire(*ctx.account_directory_ptr, credential);

                    if (lease)
                    {
                        ctx.account_lease = std::move(lease);
                        trace::debug("{} authentication succeeded", HttpStr);
                    }
                    else
                    {
                        trace::warn("{} credential verification failed", HttpStr);
                        co_await respond(Resp403);
                        co_return;
                    }
                }
                else
                {
                    trace::warn("{} invalid credential format", HttpStr);
                    co_await respond(Resp403);
                    co_return;
                }
            }

            // 解析目标地址
            const auto target = protocol::analysis::resolve(req);
            trace::info("{} {} {} -> {}:{}", HttpStr, req.method_string(), req.target(), target.host, target.port);

            // 连接目标服务器
            std::shared_ptr<resolve::router> router_ptr(&ctx.worker.router, [](resolve::router *) {});
            auto [fst, snd] = co_await primitives::dial(router_ptr, "HTTP", target, true, false);
            if (fault::failed(fst) || !snd)
            {
                trace::warn("{} dial failed, target: {}:{}", HttpStr, target.host, target.port);
                co_await respond(Resp502);
                co_return;
            }
            outbound = std::move(snd);
        }

        // HTTP CONNECT 方法：先回复 200，再进入隧道模式
        if (req.method() == protocol::http::verb::connect)
        {
            boost::system::error_code write_ec;
            auto token = net::redirect_error(net::use_awaitable, write_ec);
            co_await net::async_write(stream, net::buffer(Resp200), token);
            if (!write_ec)
            {
                co_await primitives::tunnel(stream.release(), std::move(outbound), ctx);
            }
            co_return;
        }

        // 普通 HTTP 请求：转发请求到目标服务器
        // 将绝对 URI（http://host/path）转换为相对路径（/path），源站不接受绝对 URI
        if (const auto &t = req.target(); t.starts_with("http://") || t.starts_with("https://"))
        {
            const auto scheme_end = t.find("://");
            const auto authority_end = t.find('/', scheme_end + 3);
            req.target(authority_end != std::string_view::npos ? t.substr(authority_end) : "/");
        }

        std::error_code ec;
        const auto req_data = protocol::http::serialize(req, mr);
        co_await outbound->async_write(std::span(reinterpret_cast<const std::byte *>(req_data.data()), req_data.size()), ec);
        if (ec)
            co_return;

        // 转发预读的请求体数据
        if (read_buffer.size() > 0)
        {
            auto buf = read_buffer.data();
            std::span span(static_cast<const std::byte *>(buf.data()), buf.size());
            co_await outbound->async_write(span, ec);
            if (ec)
                co_return;
        }

        // 进入双向隧道转发
        co_await primitives::tunnel(stream.release(), std::move(outbound), ctx);
    }
} // namespace psm::pipeline
