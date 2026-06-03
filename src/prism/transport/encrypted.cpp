#include <prism/transport/encrypted.hpp>
#include <prism/trace.hpp>

namespace
{
    constexpr std::string_view ssl_str = "[Transport.Encrypted]";
}

namespace psm::transport
{

    auto encrypted::ssl_handshake(shared_transmission inbound, ssl::context &ssl_ctx)
        -> net::awaitable<std::tuple<fault::code, encrypted::shared_stream, shared_transmission>>
    {
        if (!inbound)
        {
            trace::warn("{} No inbound transmission for TLS handshake", ssl_str);
            co_return std::make_tuple(fault::code::io_error, nullptr, nullptr);
        }

        connector_type connector(std::move(inbound), {});
        auto stream = std::make_shared<stream_type>(std::move(connector), ssl_ctx);

        boost::system::error_code ec;
        auto token = net::redirect_error(trace::use_prefix_awaitable, ec);
        co_await stream->async_handshake(ssl::stream_base::server, token);
        if (ec)
        {
            trace::warn("{} TLS handshake failed: {} ({})", ssl_str, ec.message(), ec.value());
            auto recovered = stream->lowest_layer().release();
            co_return std::make_tuple(fault::to_code(ec), nullptr, std::move(recovered));
        }

        trace::debug("{} TLS handshake succeeded", ssl_str);
        co_return std::make_tuple(fault::code::success, stream, nullptr);
    }

} // namespace psm::transport
