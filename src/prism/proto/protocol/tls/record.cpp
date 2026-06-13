#include <prism/proto/protocol/tls/record.hpp>

#include <prism/trace/trace.hpp>
#include <cstring>

namespace psm::tls
{

    namespace
    {

        auto parse_header(const std::span<const std::byte> raw) -> record_header
        {
            const auto *ptr = reinterpret_cast<const std::uint8_t *>(raw.data());
            return record_header{
                ptr[0],
                static_cast<std::uint16_t>((static_cast<std::uint16_t>(ptr[1]) << 8) | static_cast<std::uint16_t>(ptr[2])),
                static_cast<std::uint16_t>((static_cast<std::uint16_t>(ptr[3]) << 8) | static_cast<std::uint16_t>(ptr[4]))};
        }

    } // namespace


    auto record::header() const noexcept -> const record_header &
    {
        return header_;
    }


    auto record::payload() const noexcept -> std::span<const std::byte>
    {
        return payload_;
    }


    auto record::size() const noexcept -> std::size_t
    {
        return protocol::tls::RECORD_HDR_LEN + payload_.size();
    }


    auto record::serialize() const -> memory::vector<std::byte>
    {
        memory::vector<std::byte> buf;
        buf.reserve(size());
        buf.push_back(static_cast<std::byte>(header_.content_type));
        buf.push_back(static_cast<std::byte>((header_.version >> 8) & 0xFF));
        buf.push_back(static_cast<std::byte>(header_.version & 0xFF));
        auto len = static_cast<std::uint16_t>(payload_.size());
        buf.push_back(static_cast<std::byte>((len >> 8) & 0xFF));
        buf.push_back(static_cast<std::byte>(len & 0xFF));
        buf.insert(buf.end(), payload_.begin(), payload_.end());
        return buf;
    }


    auto record::read(transport::transmission &trans)
        -> net::awaitable<std::pair<fault::code, record>>
    {
        // 读取 5 字节头
        std::array<std::byte, protocol::tls::RECORD_HDR_LEN> hdr_buf{};
        std::size_t hdr_read = 0;
        while (hdr_read < protocol::tls::RECORD_HDR_LEN)
        {
            std::error_code ec;
            const auto n = co_await trans.async_read_some(
                std::span<std::byte>(hdr_buf.data() + hdr_read,
                                     protocol::tls::RECORD_HDR_LEN - hdr_read),
                ec);
            if (ec || n == 0)
            {
                co_return std::pair{fault::code::io_error, record{}};
            }
            hdr_read += n;
        }

        auto hdr = parse_header(hdr_buf);

        if (hdr.length > protocol::tls::MAX_RECORD_PAYLOAD)
        {
            co_return std::pair{fault::code::recorderr, record{}};
        }

        // 读取载荷
        memory::vector<std::byte> body(hdr.length);
        if (hdr.length > 0)
        {
            std::size_t body_read = 0;
            while (body_read < hdr.length)
            {
                std::error_code ec;
                const auto n = co_await trans.async_read_some(
                    std::span<std::byte>(body.data() + body_read,
                                         hdr.length - body_read),
                    ec);
                if (ec || n == 0)
                {
                    co_return std::pair{fault::code::io_error, record{}};
                }
                body_read += n;
            }
        }

        record rec;
        rec.header_ = hdr;
        rec.payload_ = std::move(body);
        co_return std::pair{fault::code::success, std::move(rec)};
    }


    auto record::read(net::ip::tcp::socket &sock)
        -> net::awaitable<std::pair<fault::code, record>>
    {
        std::array<std::byte, protocol::tls::RECORD_HDR_LEN> hdr_buf{};
        boost::system::error_code ec;
        auto hdr_n = co_await net::async_read(
            sock, net::buffer(hdr_buf.data(), protocol::tls::RECORD_HDR_LEN),
            net::redirect_error(trace::use_prefix_awaitable, ec));
        if (ec || hdr_n < protocol::tls::RECORD_HDR_LEN)
        {
            co_return std::pair{fault::code::io_error, record{}};
        }

        auto hdr = parse_header(hdr_buf);

        if (hdr.length > protocol::tls::MAX_RECORD_PAYLOAD)
        {
            co_return std::pair{fault::code::recorderr, record{}};
        }

        memory::vector<std::byte> body(hdr.length);
        if (hdr.length > 0)
        {
            auto body_n = co_await net::async_read(
                sock, net::buffer(body.data(), hdr.length),
                net::redirect_error(trace::use_prefix_awaitable, ec));
            if (ec || body_n < hdr.length)
            {
                co_return std::pair{fault::code::io_error, record{}};
            }
        }

        record rec;
        rec.header_ = hdr;
        rec.payload_ = std::move(body);
        co_return std::pair{fault::code::success, std::move(rec)};
    }


    auto record::write(transport::transmission &trans) const
        -> net::awaitable<fault::code>
    {
        auto bytes = serialize();
        std::error_code ec;
        co_await transport::async_write(trans, bytes, ec);
        if (ec)
        {
            co_return fault::code::io_error;
        }
        co_return fault::code::success;
    }


    auto record::write(net::ip::tcp::socket &sock) const
        -> net::awaitable<fault::code>
    {
        auto bytes = serialize();
        boost::system::error_code ec;
        co_await net::async_write(sock, net::buffer(bytes.data(), bytes.size()),
                                   net::redirect_error(trace::use_prefix_awaitable, ec));
        if (ec)
        {
            co_return fault::code::io_error;
        }
        co_return fault::code::success;
    }


    // === builder ===

    auto record::builder::type(std::uint8_t t) noexcept -> builder &
    {
        header_.content_type = t;
        return *this;
    }


    auto record::builder::version(std::uint16_t v) noexcept -> builder &
    {
        header_.version = v;
        return *this;
    }


    auto record::builder::payload(std::span<const std::byte> data) -> builder &
    {
        payload_.assign(data.begin(), data.end());
        header_.length = static_cast<std::uint16_t>(payload_.size());
        return *this;
    }


    auto record::builder::payload_u8(std::span<const std::uint8_t> data) -> builder &
    {
        payload_.resize(data.size());
        std::memcpy(payload_.data(), data.data(), data.size());
        header_.length = static_cast<std::uint16_t>(payload_.size());
        return *this;
    }


    auto record::builder::build() const -> record
    {
        record rec;
        rec.header_ = header_;
        rec.payload_ = payload_;
        return rec;
    }

} // namespace psm::tls
