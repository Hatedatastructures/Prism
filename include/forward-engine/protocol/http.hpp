/**
 * @file http.hpp
 * @brief HTTP 协议支持库聚合头文件
 * @details 聚合了 HTTP 协议相关的头文件，提供完整的 HTTP/1.1 协议实现。支持请求/响应的序列化与反序列化，适用于高性能代理服务器场景。
 *
 * 模块组成：
 * @details - constants.hpp：HTTP 协议常量定义，包含状态码、请求方法和头部字段枚举；
 * @details - header.hpp：HTTP 头部字段容器，支持大小写不敏感的键值对存储；
 * @details - request.hpp：HTTP 请求对象，包含方法、目标、版本、头部和负载；
 * @details - response.hpp：HTTP 响应对象，包含状态码、原因短语、版本、头部和负载；
 * @details - serialization.hpp：HTTP 协议序列化，将请求/响应对象转换为二进制数据；
 * @details - deserialization.hpp：HTTP 协议反序列化，提供同步和异步的解析功能。
 *
 * 核心特性：
 * @details - 内存高效：使用 PMR 内存池管理所有字符串，避免热路径堆分配；
 * @details - 零拷贝设计：内部使用 std::string_view 和 memory::string 避免数据复制；
 * @details - 类型安全：提供枚举和字符串双重接口，确保协议兼容性；
 * @details - 头部优化：使用 headers 容器实现常量时间查找和大小写不敏感匹配。
 *
 * @note 该模块设计为无状态，仅负责数据报文的处理，不管理连接生命周期。
 * @warning 内存管理：协议处理器使用 PMR 内存池，确保零堆分配热路径。
 */
#pragma once

#include <forward-engine/protocol/http/constants.hpp>
#include <forward-engine/protocol/http/header.hpp>
#include <forward-engine/protocol/http/request.hpp>
#include <forward-engine/protocol/http/response.hpp>
#include <forward-engine/protocol/http/serialization.hpp>
#include <forward-engine/protocol/http/deserialization.hpp>

