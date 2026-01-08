#pragma once

#include <string_view>
#include <memory/container.hpp>

#include "request.hpp"
#include "response.hpp"

namespace ngx::http
{
    /**
     * @brief 序列化 HTTP 请求
     * @param http_request 要序列化的 `HTTP` 请求对象
     * @param mr 序列化结果分配所使用的内存资源
     * @return `memory::string` 序列化后的 `HTTP` 请求报文
     */
    [[nodiscard]] memory::string serialize(const request &http_request, memory::resource_pointer mr = memory::current_resource());

    /**
     * @brief 序列化 HTTP 响应
     * @param http_response 要序列化的 `HTTP` 响应对象
     * @param mr 序列化结果分配所使用的内存资源
     * @return `memory::string` 序列化后的 `HTTP` 响应报文
     */
    [[nodiscard]] memory::string serialize(const response &http_response, memory::resource_pointer mr = memory::current_resource());
} // namespace ngx::http
