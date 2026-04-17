#include <prism/protocol/http/relay.hpp>
#include <span>
#include <cstring>

namespace psm::protocol::http
{
    namespace
    {
        // 200 Connection Established 响应
        constexpr std::string_view resp200 = "HTTP/1.1 200 Connection Established\r\n\r\n";

        // 502 Bad Gateway 响应
        constexpr std::string_view resp502 = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";

        // 最大 HTTP 头部大小（防止慢速 OOM 攻击）
        constexpr std::size_t max_header_size = 65536;
    } // namespace

    relay::relay(transport::shared_transmission transport, agent::account::directory *account_directory)
        : transport_(std::move(transport)), account_directory_(account_directory)
    {
        buffer_.resize(4096);
    }

    auto relay::handshake() -> net::awaitable<std::pair<fault::code, proxy_request>>
    {
        // 读取完整 HTTP 请求头
        if (!co_await read_until_header_end())
        {
            co_return std::make_pair(fault::code::io_error, proxy_request{});
        }

        // 解析请求行和头字段
        const auto raw = std::string_view(buffer_.data(), used_);
        proxy_request req;
        if (fault::failed(parse_proxy_request(raw, req)))
        {
            co_return std::make_pair(fault::code::parse_error, proxy_request{});
        }

        // 执行 Basic 认证（若配置了账户目录）
        if (account_directory_)
        { // 认证失败时直接返回 407 响应，成功时保存租约信息以供后续使用
            auto auth = authenticate_proxy_request(req.authorization, *account_directory_);
            if (!auth.authenticated)
            {
                co_await write_bytes(auth.error_response);
                co_return std::make_pair(fault::code::auth_failed, proxy_request{});
            }
            lease_ = std::move(auth.lease);
        }

        co_return std::make_pair(fault::code::success, req);
    }

    auto relay::write_connect_success() -> net::awaitable<fault::code>
    {
        co_return co_await write_bytes(resp200);
    }

    auto relay::write_bad_gateway() -> net::awaitable<fault::code>
    {
        co_return co_await write_bytes(resp502);
    }

    auto relay::forward(const proxy_request &req, transport::shared_transmission outbound, std::pmr::memory_resource *mr)
        -> net::awaitable<void>
    {
        // 构建新请求行：将绝对 URI 重写为相对路径
        const auto new_line = build_forward_request_line(req, mr);

        // 写入新请求行到上游
        std::error_code ec;
        co_await outbound->async_write(std::span(reinterpret_cast<const std::byte *>(new_line.data()), new_line.size()), ec);
        if (ec)
        {
            co_return;
        }

        // 写入请求行之后的剩余数据（headers + \r\n\r\n + body data）
        if (used_ > req.req_line_end)
        {
            std::span span = std::span(reinterpret_cast<const std::byte *>(buffer_.data() + req.req_line_end), used_ - req.req_line_end);
            co_await outbound->async_write(std::move(span), ec);
        }
    }

    auto relay::release() -> transport::shared_transmission
    {
        return std::move(transport_);
    }

    auto relay::read_until_header_end() -> net::awaitable<bool>
    {
        while (true)
        {
            const auto sv = std::string_view(buffer_.data(), used_);
            if (sv.find("\r\n\r\n") != std::string_view::npos)
            {
                co_return true;
            }

            // 缓冲区满时扩容
            if (used_ >= buffer_.size())
            {
                if (buffer_.size() >= max_header_size)
                {
                    co_return false;
                }
                buffer_.resize(buffer_.size() * 2);
            }

            // 从传输层读取数据
            std::error_code ec;
            std::span span = std::span(reinterpret_cast<std::byte *>(buffer_.data() + used_), buffer_.size() - used_);
            const auto n = co_await transport_->async_read_some(std::move(span), ec);
            if (ec)
            {
                co_return false;
            }
            used_ += n;
        }
    }

    auto relay::write_bytes(std::string_view data) -> net::awaitable<fault::code>
    {
        std::error_code ec;
        std::span span = std::span(reinterpret_cast<const std::byte *>(data.data()), data.size());
        co_await transport_->async_write(std::move(span), ec);
        co_return ec ? fault::code::io_error : fault::code::success;
    }
} // namespace psm::protocol::http
