#include <prism/diagnose/diagnose.hpp>
#include <prism/net/transport/encrypted.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>

#include <chrono>

using namespace psm::diagnose;

namespace psm::transport
{

    auto encrypted::ssl_handshake(shared_transmission inbound, ssl::context &ssl_ctx)
        -> net::awaitable<std::tuple<fault::code, encrypted::shared_stream, shared_transmission>>
    {
        if (!inbound)
        {
            diagnose::warn("No inbound transmission for TLS handshake");
            co_return std::make_tuple(fault::code::io_error, nullptr, nullptr);
        }

        connector_type connector(std::move(inbound), {});
        auto stream = std::make_shared<stream_type>(std::move(connector), ssl_ctx);

        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);

        // TLS 握手超时（30 秒）：防恶意客户端连接后不发 ClientHello 挂起
        using boost::asio::experimental::awaitable_operators::operator||;
        net::steady_timer deadline(stream->get_executor(), std::chrono::seconds(30));
        auto do_handshake = [&stream]() -> net::awaitable<bool>
        {
            boost::system::error_code h_ec;
            co_await stream->async_handshake(ssl::stream_base::server,
                                             net::redirect_error(net::use_awaitable, h_ec));
            co_return !h_ec;
        };
        const auto result = co_await (do_handshake() || deadline.async_wait(net::use_awaitable));
        if (result.index() == 1)
        {
            diagnose::warn("TLS handshake timeout");
            auto recovered = stream->lowest_layer().release();
            co_return std::make_tuple(fault::code::timeout, nullptr, std::move(recovered));
        }
        if (!std::get<0>(result))
        {
            diagnose::warn("TLS handshake failed: {} ({})", ec.message(), ec.value());
            auto recovered = stream->lowest_layer().release();
            co_return std::make_tuple(fault::to_code(ec), nullptr, std::move(recovered));
        }

        diagnose::debug("TLS handshake succeeded");
        co_return std::make_tuple(fault::code::success, stream, nullptr);
    }

} // namespace psm::transport
