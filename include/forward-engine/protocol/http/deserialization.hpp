#pragma once

#include <string_view>

#include <boost/asio.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/core/flat_buffer.hpp>

#include <memory/container.hpp>

#include "request.hpp"
#include "response.hpp"

namespace ngx::protocol::http
{
    namespace net = boost::asio;
    namespace beast = boost::beast;

    using network_allocator = memory::allocator<char>;
    using http_body = beast::http::basic_string_body<char, std::char_traits<char>, network_allocator>;

    /**
     * @brief 反序列化 HTTP 请求
     * @param string_value 原始 `HTTP` 请求报文数据
     * @param http_request 用于接收解析结果的 request 对象
     * @return bool 如果解析成功返回 `true`，否则返回 `false`
     */
    [[nodiscard]] bool deserialize(std::string_view string_value, request &http_request);

    /**
     * @brief 异步读取并反序列化 HTTP 请求
     * @tparam Transport 支持异步反序列化的 Transport 类型 (tcp::socket 或 ssl::stream)
     * @tparam DynamicBuffer 动态缓冲区类型，必须满足 boost::beast::flat_buffer 概念
     * @param socket 数据源
     * @param http_request http模块的 request 对象 (将被填充)
     * @param buffer 用于存储读取数据的动态缓冲区
     * @param mr 内存资源指针，用于分配解析过程中需要的内存
     * @return `true` 读取成功, `false` 读取失败 (连接断开或协议错误)
     */
    template <class Transport, class DynamicBuffer>
    net::awaitable<bool> async_read(Transport &socket, request &http_request,
                                    DynamicBuffer &buffer, memory::resource_pointer mr)
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
            co_return false;
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

        co_return true;
    }

    /**
     * @brief 异步读取并反序列化 HTTP 请求
     * @tparam Transport 支持异步反序列化的 Transport 类型 (tcp::socket 或 ssl::stream)
     * @param socket 数据源
     * @param http_request http模块的 request 对象 (将被填充)
     * @param mr 内存资源指针，用于分配解析过程中需要的内存
     * @return `true` 读取成功, `false` 读取失败 (连接断开或协议错误)
     */
    template <class Transport>
    net::awaitable<bool> async_read(Transport &socket, request &http_request, memory::resource_pointer mr)
    {
        beast::flat_buffer buffer;
        co_return co_await async_read<Transport, beast::flat_buffer>(socket, http_request, buffer, mr);
    }

    /**
     * @brief 反序列化 HTTP 响应
     * @param string_value 原始 `HTTP` 响应报文数据
     * @param http_response 用于接收解析结果的 response 对象
     * @return 如果解析成功返回 `true`，否则返回 `false`
     */
    [[nodiscard]] bool deserialize(std::string_view string_value, response &http_response);

    /**
     * @brief 异步读取并反序列化 HTTP 响应
     * @tparam Transport 支持异步反序列化的 Transport 类型 (tcp::socket 或 ssl::stream)
     * @param socket 数据源
     * @param http_response http模块的 response 对象 (将被填充)
     * @param mr 内存资源指针，用于分配解析过程中需要的内存
     * @return `true` 读取成功, `false` 读取失败 (连接断开或协议错误)
     */
    template <class Transport>
    net::awaitable<bool> async_read(Transport &socket, response &http_response, memory::resource_pointer mr)
    {
        beast::flat_buffer buffer;
        co_return co_await async_read<Transport, beast::flat_buffer>(socket, http_response, buffer, mr);
    }

    /**
     * @brief 异步读取并反序列化 HTTP 响应
     * @tparam Transport 支持异步反序列化的 Transport 类型 (tcp::socket 或 ssl::stream)
     * @tparam DynamicBuffer 动态缓冲区类型，必须满足 beast::flat_buffer 概念
     * @param socket 数据源
     * @param http_response http模块的 response 对象 (将被填充)
     * @param buffer 用于存储读取数据的动态缓冲区
     * @param mr 内存资源指针，用于分配解析过程中需要的内存
     * @return `true` 读取成功, `false` 读取失败 (连接断开或协议错误)
     */
    template <class Transport, class DynamicBuffer>
    net::awaitable<bool> async_read(Transport &socket, response &http_response, DynamicBuffer &buffer, memory::resource_pointer mr)
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
            co_return false;
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

        co_return true;
    }

} // namespace ngx::protocol::http
