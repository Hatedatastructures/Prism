/**
 * @file deserialization.hpp
 * @brief HTTP 协议反序列化
 * @details 提供同步和异步的 HTTP 请求/响应解析功能，基于 Boost.Beast 实现。
 */
#pragma once

#include <string_view>

#include <boost/asio.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/http/error.hpp>
#include <boost/beast/core/flat_buffer.hpp>

#include <forward-engine/memory/container.hpp>
#include <forward-engine/gist.hpp>

#include <forward-engine/protocol/http/request.hpp>
#include <forward-engine/protocol/http/response.hpp>

/**
 * @namespace ngx::protocol::http
 * @brief HTTP 协议实现
 * @details 包含 HTTP/1.1 协议的完整实现，支持请求/响应的序列化与反序列化。
 */
namespace ngx::protocol::http
{
    namespace net = boost::asio;
    namespace beast = boost::beast;

    using network_allocator = memory::allocator<char>;
    using http_body = beast::http::basic_string_body<char, std::char_traits<char>, network_allocator>;

    /**
     * @brief 反序列化 HTTP 请求
     * @param string_value 原始 `HTTP` 请求报文数据
     * @param http_request 用于接收解析结果的 `request` 对象
     * @param mr 内存资源指针
     * @return `gist::code` 解析结果状态码
     */
    [[nodiscard]] auto deserialize(std::string_view string_value, request &http_request, memory::resource_pointer mr = nullptr)
        -> gist::code;

    /**
     * @brief 异步读取并反序列化 HTTP 请求
     * @tparam Transport 支持异步读取的 Transport 类型 (如 `tcp::socket` 或 `ssl::stream`)
     * @tparam DynamicBuffer 动态缓冲区类型，需满足 `boost::beast::flat_buffer` 概念
     * @param socket 数据源 `socket`
     * @param http_request 用于接收解析结果的 `request` 对象 (将被清空并填充)
     * @param buffer 用于存储读取数据的动态缓冲区
     * @param mr 内存资源指针，用于分配解析过程中需要的内存
     * @return `gist::code` 读取结果状态码
     */
    template <class Transport, class DynamicBuffer>
    auto async_read(Transport &socket, request &http_request, DynamicBuffer &buffer, memory::resource_pointer mr)
        -> net::awaitable<gist::code>
    {
        if (!mr)
        {
            mr = memory::current_resource();
        }

        http_request.clear(); // 清空 request 对象, 防止重复解析
        using request_parser = beast::http::request_parser<http_body>;

        request_parser parser(std::piecewise_construct, std::make_tuple(network_allocator{mr}));
        parser.get().body() = http_body::value_type(network_allocator{mr});

        parser.header_limit(16 * 1024);
        parser.body_limit(10 * 1024 * 1024);

        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        co_await beast::http::async_read(socket, buffer, parser, token);
        if (ec)
        {
            if (ec == net::error::eof || ec == beast::http::error::end_of_stream)
            {
                co_return gist::code::eof;
            }
            co_return gist::code::generic_error;
        }

        auto beast_msg = parser.release();

        http_request.method(beast_msg.method_string());
        http_request.target(beast_msg.target());
        http_request.version(beast_msg.version());
        for (const auto &field : beast_msg)
        {
            http_request.set(field.name_string(), field.value());
        }

        if (!beast_msg.body().empty())
        {
            http_request.body(std::move(beast_msg.body()));
        }

        http_request.keep_alive(beast_msg.keep_alive());

        co_return gist::code::success;
    }

    /**
     * @brief 异步读取并反序列化 HTTP 请求 (使用默认缓冲区)
     * @tparam Transport 支持异步读取的 Transport 类型
     * @param socket 数据源 `socket`
     * @param http_request 用于接收解析结果的 `request` 对象
     * @param mr 内存资源指针
     * @return `gist::code` 读取结果状态码
     */
    template <class Transport>
    auto async_read(Transport &socket, request &http_request, const memory::resource_pointer mr)
        -> net::awaitable<gist::code>
    {
        beast::flat_buffer buffer;
        co_return co_await async_read<Transport, beast::flat_buffer>(socket, http_request, buffer, mr);
    }

    /**
     * @brief 反序列化 HTTP 响应
     * @param string_value 原始 `HTTP` 响应报文数据
     * @param http_response 用于接收解析结果的 `response` 对象
     * @return gist::code 解析结果状态码
     */
     [[nodiscard]] auto deserialize(std::string_view string_value, response &http_response)
        -> gist::code;

    /**
     * @brief 异步读取并反序列化 HTTP 响应 (使用默认缓冲区)
     * @tparam Transport 支持异步读取的 Transport 类型
     * @param socket 数据源 `socket`
     * @param http_response 用于接收解析结果的 `response` 对象
     * @param mr 内存资源指针
     * @return `gist::code` 读取结果状态码
     */
    template <class Transport>
    auto async_read(Transport &socket, response &http_response, memory::resource_pointer mr)
        -> net::awaitable<gist::code>
    {
        beast::flat_buffer buffer;
        co_return co_await async_read<Transport, beast::flat_buffer>(socket, http_response, buffer, mr);
    }

    /**
     * @brief 异步读取并反序列化 HTTP 响应
     * @tparam Transport 支持异步读取的 Transport 类型
     * @tparam DynamicBuffer 动态缓冲区类型
     * @param socket 数据源 `socket`
     * @param http_response 用于接收解析结果的 `response` 对象
     * @param buffer 用于存储读取数据的动态缓冲区
     * @param mr 内存资源指针
     * @return `gist::code` 读取结果状态码
     */
    template <class Transport, class DynamicBuffer>
    auto async_read(Transport &socket, response &http_response, DynamicBuffer &buffer, memory::resource_pointer mr)
        -> net::awaitable<gist::code>
    {
        if (!mr)
        {
            mr = memory::current_resource();
        }

        http_response.clear(); // 清空 response 对象, 防止重复解析
        using response_parser = beast::http::response_parser<http_body>;

        response_parser parser(std::piecewise_construct, std::make_tuple(network_allocator{mr}));
        parser.get().body() = http_body::value_type(network_allocator{mr});

        parser.header_limit(16 * 1024);
        parser.body_limit(10 * 1024 * 1024);

        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        co_await beast::http::async_read(socket, buffer, parser, token);
        // 读取完成一个完整的响应窃取到自己的 response 对象
        if (ec)
        {
            if (ec == net::error::eof || ec == beast::http::error::end_of_stream)
            {
                co_return gist::code::eof;
            }
            co_return gist::code::generic_error;
        }

        auto beast_msg = parser.release();

        // 填充 response 对象
        http_response.version(beast_msg.version());
        http_response.status(static_cast<status>(beast_msg.result()));
        for (const auto &field : beast_msg)
        {
            http_response.set(field.name_string(), field.value());
        }

        if (!beast_msg.body().empty())
        {
            http_response.body(std::move(beast_msg.body()));
        }

        http_response.keep_alive(beast_msg.keep_alive());

        co_return gist::code::success;
    }

} // namespace ngx::protocol::http
