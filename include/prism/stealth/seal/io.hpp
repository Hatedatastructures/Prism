/**
 * @file io.hpp
 * @brief 模板密封记录 I/O
 * @details 提供异步读/写加密 TLS 记录的模板函数。调用方提供
 * OpenFn/SealFn lambda 处理方案特定的加密操作（AEAD/HMAC/BLAKE3）。
 */
#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/protocol/tls/record.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>

#include <cstddef>
#include <span>
#include <system_error>
#include <utility>


namespace psm::stealth::seal
{

    namespace net = boost::asio;

    /**
     * @brief 从 transmission 读取加密记录并解密
     * @param trans 传输层
     * @param open_fn 解密函数：接受(record_header, payload_span, ec&) 返回 size_t
     * @param ec 错误码输出
     */
    template <typename OpenFn>
    [[nodiscard]] auto read_sealed(transport::transmission &trans, const OpenFn &open_fn, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        auto [read_ec, rec] = co_await tls::record::read(trans);
        if (fault::failed(read_ec))
        {
            ec = std::make_error_code(std::errc::connection_reset);
            co_return 0;
        }

        auto result = open_fn(rec.header(), rec.payload(), ec);
        co_return result;
    }

    /**
     * @brief 从 tcp::socket 读取加密记录并解密
     */
    template <typename OpenFn>
    [[nodiscard]] auto read_sealed(net::ip::tcp::socket &sock, const OpenFn &open_fn, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        auto [read_ec, rec] = co_await tls::record::read(sock);
        if (fault::failed(read_ec))
        {
            ec = std::make_error_code(std::errc::connection_reset);
            co_return 0;
        }

        auto result = open_fn(rec.header(), rec.payload(), ec);
        co_return result;
    }

    /**
     * @brief 加密封写请求
     */
    template <typename SealFn>
    struct seal_request
    {
        std::span<const std::byte> data;
        SealFn seal;
    };

    /**
     * @brief 加密数据并写入 transmission
     * @param req 加密封写请求（含明文和加密函数）
     * @param ec 错误码输出
     */
    template <typename SealFn>
    [[nodiscard]] auto write_sealed(transport::transmission &trans, seal_request<SealFn> req, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        auto [seal_ec, sealed_rec] = req.seal(req.data);
        if (fault::failed(seal_ec))
        {
            ec = std::make_error_code(std::errc::operation_not_permitted);
            co_return 0;
        }

        auto write_ec = co_await sealed_rec.write(trans);
        if (fault::failed(write_ec))
        {
            ec = std::make_error_code(std::errc::connection_reset);
            co_return 0;
        }

        co_return req.data.size();
    }

    /**
     * @brief 加密数据并写入 tcp::socket
     */
    template <typename SealFn>
    [[nodiscard]] auto write_sealed(net::ip::tcp::socket &sock, seal_request<SealFn> req, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        auto [seal_ec, sealed_rec] = req.seal(req.data);
        if (fault::failed(seal_ec))
        {
            ec = std::make_error_code(std::errc::operation_not_permitted);
            co_return 0;
        }

        auto write_ec = co_await sealed_rec.write(sock);
        if (fault::failed(write_ec))
        {
            ec = std::make_error_code(std::errc::connection_reset);
            co_return 0;
        }

        co_return req.data.size();
    }

} // namespace psm::stealth::seal
