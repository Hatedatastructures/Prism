/**
 * @file serialization.hpp
 * @brief HTTP 协议序列化
 * @details 提供将 HTTP 请求和响应对象序列化为二进制数据的函数。
 */
#pragma once

#include <forward-engine/memory/container.hpp>

#include <forward-engine/protocol/http/request.hpp>
#include <forward-engine/protocol/http/response.hpp>

/**
 * @namespace ngx::protocol::http
 * @brief HTTP 协议实现
 * @details 包含 HTTP/1.1 协议的完整实现，支持请求/响应的序列化与反序列化。
 */
namespace ngx::protocol::http
{
    /**
     * @brief 序列化 HTTP 请求
     * @param http_request 要序列化的 `HTTP` 请求对象
     * @param mr 序列化结果分配所使用的内存资源
     * @return `memory::string` 序列化后的 `HTTP` 请求报文
     */
    [[nodiscard]] auto serialize(const request &http_request, memory::resource_pointer mr = memory::current_resource())
        -> memory::string;

    /**
     * @brief 序列化 HTTP 响应
     * @param http_response 要序列化的 `HTTP` 响应对象
     * @param mr 序列化结果分配所使用的内存资源
     * @return `memory::string` 序列化后的 `HTTP` 响应报文
     */
    [[nodiscard]] auto serialize(const response &http_response, memory::resource_pointer mr = memory::current_resource())
        -> memory::string;
} // namespace ngx::protocol::http
