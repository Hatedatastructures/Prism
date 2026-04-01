/**
 * @file deserialization.hpp
 * @brief HTTP 协议反序列化
 * @details 提供同步和异步的 HTTP 请求响应解析功能，基于 Boost.Beast 实现。
 * 支持从原始字节流或网络套接字读取并解析 HTTP 报文，将二进制数据转换为
 * 结构化的请求或响应对象。解析器使用 PMR 内存池管理内部缓冲区，避免
 * 热路径堆分配。支持配置头部大小限制和请求体大小限制，防止恶意请求
 * 导致的内存耗尽。
 * @note 异步函数必须在协程上下文中调用，使用 co_await 等待操作完成。
 * @note 解析失败时返回错误码，不抛出异常，便于错误处理和日志记录。
 * @warning 在协程挂起期间不应持有指向栈内存的视图，避免悬垂引用。
 */
#pragma once

#include <string_view>

#include <boost/asio.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/http/error.hpp>
#include <boost/beast/core/flat_buffer.hpp>

#include <prism/memory/container.hpp>
#include <prism/fault.hpp>

#include <prism/protocol/http/request.hpp>
#include <prism/protocol/http/response.hpp>

/**
 * @namespace psm::protocol::http
 * @brief HTTP 协议实现命名空间
 * @details 包含 HTTP/1.1 和 HTTP/2 协议的完整实现，提供请求和响应的序列化
 * 与反序列化、协议状态机管理等功能。模块设计为无状态，仅负责数据报文的
 * 处理，不管理连接生命周期。
 */
namespace psm::protocol::http
{
    namespace net = boost::asio;
    namespace beast = boost::beast;

    using network_allocator = memory::allocator<char>;
    using http_body = beast::http::basic_string_body<char, std::char_traits<char>, network_allocator>;

    /**
     * @brief 反序列化 HTTP 请求
     * @param string_value 原始 HTTP 请求报文数据
     * @param http_request 用于接收解析结果的请求对象
     * @param mr 内存资源指针，用于分配解析过程中的内存
     * @return 解析结果状态码
     * @details 将原始 HTTP 请求报文字符串解析为结构化的请求对象。解析过程包括
     * 请求行解析、头部字段解析和请求体提取。支持 HTTP/1.0 和 HTTP/1.1 协议格式。
     */
    [[nodiscard]] auto deserialize(std::string_view string_value, request &http_request, memory::resource_pointer mr = nullptr)
        -> fault::code;

    /**
     * @brief 异步读取并反序列化 HTTP 请求
     * @tparam Transport 支持异步读取的传输层类型，如 tcp::socket 或 ssl::stream
     * @tparam DynamicBuffer 动态缓冲区类型，需满足 Boost.Beast 的动态缓冲区概念
     * @param socket 数据源套接字
     * @param http_request 用于接收解析结果的请求对象，将被清空并填充
     * @param buffer 用于存储读取数据的动态缓冲区
     * @param mr 内存资源指针，用于分配解析过程中需要的内存
     * @return 协程等待对象，完成后返回读取结果状态码
     * @details 从网络套接字异步读取完整的 HTTP 请求报文并解析。使用 Boost.Beast
     * 的请求解析器处理分块传输编码和持久连接。解析器配置头部限制为 16KB，
     * 请求体限制为 10MB，防止恶意请求导致内存耗尽。
     * @note 函数必须在协程上下文中调用，使用 co_await 等待操作完成。
     * @note 当连接关闭时返回 fault::code::eof，其他错误返回 fault::code::generic_error。
     */
    template <class Transport, class DynamicBuffer>
    auto async_read(Transport &socket, request &http_request, DynamicBuffer &buffer, memory::resource_pointer mr)
        -> net::awaitable<fault::code>
    {
        if (!mr)
        {
            mr = memory::current_resource();
        }

        http_request.clear();
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
                co_return fault::code::eof;
            }
            co_return fault::code::generic_error;
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

        co_return fault::code::success;
    }

    /**
     * @brief 异步读取并反序列化 HTTP 请求（便捷重载）
     * @tparam Transport 支持异步读取的传输层类型
     * @param socket 数据源套接字
     * @param http_request 用于接收解析结果的请求对象
     * @param mr 内存资源指针
     * @return 协程等待对象，完成后返回读取结果状态码
     * @details 使用内部创建的 flat_buffer 作为缓冲区的便捷重载版本。
     * 适用于不需要复用缓冲区的简单场景。
     */
    template <class Transport>
    auto async_read(Transport &socket, request &http_request, const memory::resource_pointer mr)
        -> net::awaitable<fault::code>
    {
        beast::flat_buffer buffer;
        co_return co_await async_read<Transport, beast::flat_buffer>(socket, http_request, buffer, mr);
    }

    /**
     * @brief 反序列化 HTTP 响应
     * @param string_value 原始 HTTP 响应报文数据
     * @param http_response 用于接收解析结果的响应对象
     * @return 解析结果状态码
     * @details 将原始 HTTP 响应报文字符串解析为结构化的响应对象。解析过程包括
     * 状态行解析、头部字段解析和响应体提取。支持 HTTP/1.0 和 HTTP/1.1 协议格式。
     */
     [[nodiscard]] auto deserialize(std::string_view string_value, response &http_response)
        -> fault::code;

    /**
     * @brief 异步读取并反序列化 HTTP 响应（便捷重载）
     * @tparam Transport 支持异步读取的传输层类型
     * @param socket 数据源套接字
     * @param http_response 用于接收解析结果的响应对象
     * @param mr 内存资源指针
     * @return 协程等待对象，完成后返回读取结果状态码
     * @details 使用内部创建的 flat_buffer 作为缓冲区的便捷重载版本。
     * 适用于不需要复用缓冲区的简单场景。
     */
    template <class Transport>
    auto async_read(Transport &socket, response &http_response, memory::resource_pointer mr)
        -> net::awaitable<fault::code>
    {
        beast::flat_buffer buffer;
        co_return co_await async_read<Transport, beast::flat_buffer>(socket, http_response, buffer, mr);
    }

    /**
     * @brief 异步读取并反序列化 HTTP 响应
     * @tparam Transport 支持异步读取的传输层类型
     * @tparam DynamicBuffer 动态缓冲区类型
     * @param socket 数据源套接字
     * @param http_response 用于接收解析结果的响应对象
     * @param buffer 用于存储读取数据的动态缓冲区
     * @param mr 内存资源指针
     * @return 协程等待对象，完成后返回读取结果状态码
     * @details 从网络套接字异步读取完整的 HTTP 响应报文并解析。使用 Boost.Beast
     * 的响应解析器处理分块传输编码和持久连接。解析器配置头部限制为 16KB，
     * 响应体限制为 10MB，防止恶意响应导致内存耗尽。
     * @note 函数必须在协程上下文中调用，使用 co_await 等待操作完成。
     * @note 当连接关闭时返回 fault::code::eof，其他错误返回 fault::code::generic_error。
     */
    template <class Transport, class DynamicBuffer>
    auto async_read(Transport &socket, response &http_response, DynamicBuffer &buffer, memory::resource_pointer mr)
        -> net::awaitable<fault::code>
    {
        if (!mr)
        {
            mr = memory::current_resource();
        }

        http_response.clear();
        using response_parser = beast::http::response_parser<http_body>;

        response_parser parser(std::piecewise_construct, std::make_tuple(network_allocator{mr}));
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
                co_return fault::code::eof;
            }
            co_return fault::code::generic_error;
        }

        auto beast_msg = parser.release();

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

        co_return fault::code::success;
    }

}
