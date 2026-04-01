/**
 * @file serialization.hpp
 * @brief HTTP 协议序列化
 * @details 提供将 HTTP 请求和响应对象序列化为二进制数据的函数。支持将结构化的请求或响应对象
 * 转换为符合 HTTP 协议规范的字节流，可直接发送到网络连接。序列化过程包括生成请求行或状态行、
 * 格式化头部字段、拼接请求体或响应体。序列化结果使用 PMR 内存池分配，避免热路径堆分配。
 * @note 序列化后的报文使用 CRLF 作为行终止符。
 * @note 头部字段名保持原始大小写形式。
 * @warning 序列化大请求体或响应体时会产生内存拷贝，应考虑流式处理。
 */
#pragma once

#include <prism/memory/container.hpp>

#include <prism/protocol/http/request.hpp>
#include <prism/protocol/http/response.hpp>

/**
 * @namespace psm::protocol::http
 * @brief HTTP 协议实现命名空间
 * @details 包含 HTTP/1.1 和 HTTP/2 协议的完整实现，提供请求和响应的序列化与反序列化、
 * 协议状态机管理等功能。模块设计为无状态，仅负责数据报文的处理，不管理连接生命周期。
 */
namespace psm::protocol::http
{
    /**
     * @brief 序列化 HTTP 请求
     * @param http_request 要序列化的 HTTP 请求对象
     * @param mr 序列化结果分配所使用的内存资源
     * @return 序列化后的 HTTP 请求报文
     * @details 将 HTTP 请求对象序列化为符合 HTTP 协议规范的字节流。序列化过程包括生成请求行，
     * 格式化头部字段，拼接请求体。生成的报文使用 CRLF 作为行终止符，头部字段名保持原始大小写形式。
     */
    [[nodiscard]] auto serialize(const request &http_request, memory::resource_pointer mr = memory::current_resource())
        -> memory::string;

    /**
     * @brief 序列化 HTTP 响应
     * @param http_response 要序列化的 HTTP 响应对象
     * @param mr 序列化结果分配所使用的内存资源
     * @return 序列化后的 HTTP 响应报文
     * @details 将 HTTP 响应对象序列化为符合 HTTP 协议规范的字节流。序列化过程包括生成状态行，
     * 格式化头部字段，拼接响应体。生成的报文使用 CRLF 作为行终止符，头部字段名保持原始大小写形式。
     */
    [[nodiscard]] auto serialize(const response &http_response, memory::resource_pointer mr = memory::current_resource())
        -> memory::string;
}
