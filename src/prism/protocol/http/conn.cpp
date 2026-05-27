#include <prism/protocol/http/conn.hpp>
#include <prism/transport/transmission.hpp>

#include <cstring>
#include <span>

namespace psm::protocol::http
{

    namespace
    {
        // 200 Connection Established 响应
        constexpr std::string_view resp200 = "HTTP/1.1 200 Connection Established\r\n\r\n";

        // 502 Bad Gateway 响应
        constexpr std::string_view resp502 = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";

        // 最大 HTTP 头部大小（防止慢速 OOM 攻击）
        constexpr std::size_t max_hdr_size = 65536;
    } // namespace

    conn::conn(transport::shared_transmission transport, account::directory *account_directory)
        : transport_(std::move(transport)), acct_dir_(account_directory), buffer_(memory::current_resource())
    {
        buffer_.resize(4096);
    }

    auto conn::handshake()
        -> net::awaitable<std::pair<fault::code, proxy_request>>
    {
        // 读取完整 HTTP 请求头
        if (!co_await read_hdr())
        {
            co_return std::make_pair(fault::code::io_error, proxy_request{});
        }

        // 解析请求行和头字段
        const auto raw = std::string_view(buffer_.data(), used_);
        proxy_request req;
        if (fault::failed(parse_req(raw, req)))
        {
            co_return std::make_pair(fault::code::parse_error, proxy_request{});
        }

        // 执行 Basic 认证（若配置了账户目录）
        if (acct_dir_)
        { // 认证失败时直接返回 407 响应，成功时保存租约信息以供后续使用
            auto auth = authenticate_proxy(req.authorization, *acct_dir_);
            if (!auth.authenticated)
            {
                co_await write_bytes(auth.error_response);
                co_return std::make_pair(fault::code::auth_failed, proxy_request{});
            }
            lease_ = std::move(auth.lease);
        }

        co_return std::make_pair(fault::code::success, req);
    }

    auto conn::send_ok()
        -> net::awaitable<fault::code>
    {
        co_return co_await write_bytes(resp200);
    }

    auto conn::send_gateway_err()
        -> net::awaitable<fault::code>
    {
        co_return co_await write_bytes(resp502);
    }

    auto conn::forward(const proxy_request &req, transport::shared_transmission outbound, std::pmr::memory_resource *mr)
        -> net::awaitable<void>
    {
        // 构建新请求行：将绝对 URI 重写为相对路径
        const auto new_line = build_fwd(req, mr);

        // 写入新请求行到上游
        std::error_code ec;
        // safe: casting string data to byte span for wire transmission
        auto line_span = std::span(reinterpret_cast<const std::byte *>(new_line.data()), new_line.size());
        co_await transport::async_write(*outbound, line_span, ec);
        if (ec)
        {
            co_return;
        }

        // 写入请求行之后的剩余数据（headers + \r\n\r\n + body data）
        if (used_ > req.line_end)
        {
            // safe: casting char buffer to byte span for remaining HTTP data forwarding
            std::span span = std::span(reinterpret_cast<const std::byte *>(buffer_.data() + req.line_end), used_ - req.line_end);
            co_await transport::async_write(*outbound, span, ec);
        }
    }

    auto conn::release()
        -> transport::shared_transmission
    {
        return std::move(transport_);
    }

    auto conn::read_hdr()
        -> net::awaitable<bool>
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
                if (buffer_.size() >= max_hdr_size)
                {
                    co_return false;
                }
                buffer_.resize(buffer_.size() * 2);
            }

            // 从传输层读取数据
            std::error_code ec;
            // safe: casting char buffer region to mutable byte span for async read
            std::span span = std::span(reinterpret_cast<std::byte *>(buffer_.data() + used_), buffer_.size() - used_);
            const auto n = co_await transport_->async_read_some(span, ec);
            if (ec)
            {
                co_return false;
            }
            used_ += n;
        }
    }

    auto conn::write_bytes(std::string_view data)
        -> net::awaitable<fault::code>
    {
        std::error_code ec;
        // safe: casting string_view to byte span for wire transmission
        std::span span = std::span(reinterpret_cast<const std::byte *>(data.data()), data.size());
        co_await transport::async_write(*transport_, span, ec);
        fault::code result;
        if (ec)
        {
            result = fault::code::io_error;
        }
        else
        {
            result = fault::code::success;
        }
        co_return result;
    }
} // namespace psm::protocol::http
