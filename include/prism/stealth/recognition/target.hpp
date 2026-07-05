/**
 * @file target.hpp
 * @brief 目标地址解析
 * @details 提供从 HTTP 请求或 host:port 字符串中解析目标地址的工具函数。
 * 该模块从 protocol/analysis 迁移而来，职责下沉到 recognition 模块。
 * 支持 HTTP CONNECT 方法、绝对 URI、相对路径请求以及通用 host:port 格式。
 * @note 所有函数都是线程安全的，纯计算操作，不涉及 I/O。
 */
#pragma once

#include <prism/foundation/memory/container.hpp>
#include <prism/proto/protocol/common/target.hpp>
#include <prism/proto/protocol/http/parser.hpp>

#include <string_view>


namespace psm::recognition {

/**
 * @brief 从 HTTP 请求中解析目标地址
 * @details 解析 HTTP 请求，提取目标主机和端口信息。该方法支持
 * HTTP/1.1 的绝对 URI 格式和 Host 头字段。解析策略为首先检查
 * 请求行是否包含绝对 URI，如果存在则从中提取主机和端口，否则
 * 从 Host 头字段提取。如果 Host 头缺少端口，使用协议默认端口。
 * 支持 HTTP 代理请求的 CONNECT 方法，处理带端口的 Host 头格式，
 * 自动识别是否为正向代理请求。使用 std::string_view 避免数据
 * 拷贝，仅解析必要部分，内存分配通过 memory::resource_pointer
 * 控制。
 * @param req HTTP 请求对象，包含请求行和头部字段
 * @param mr 内存资源指针，用于分配结果字符串的内存，为空时使用
 * 默认资源
 * @return protocol::target 解析出的目标信息，包含主机、端口和正向代理标志
 * @note 如果解析失败，返回的目标对象可能包含空字符串。
 * @warning 请求对象必须包含有效的 HTTP 请求数据。
 */
[[nodiscard]] auto resolve(const protocol::http::proxy_request &req, memory::resource_pointer mr = nullptr)
    -> protocol::target;

/**
 * @brief 从字符串解析目标地址
 * @details 解析 "host:port" 格式的字符串，提取主机和端口信息。
 * 该方法用于解析 SOCKS5、TLS 等协议中的目标地址字段。支持基本
 * 格式如 example.com:8080，IPv4 地址如 192.168.1.1:80，IPv6
 * 地址如 [2001:db8::1]:443，省略端口时使用默认值 "80"。解析规则
 * 为查找最后一个冒号作为端口分隔符，处理 IPv6 地址的方括号语法，
 * 验证端口号有效性，主机名转换为小写。格式错误返回空主机和默认
 * 端口，无效端口返回默认端口 "80"。
 * @param host_port "host:port" 格式的字符串，可能包含 IPv6 地址
 * @param mr 内存资源指针，用于分配结果字符串的内存，为空时使用
 * 默认资源
 * @return protocol::target 解析出的目标信息，包含主机、端口和正向代理标志
 * @note 对于非 HTTP 协议，positive 标志通常为 true（正向代理）。
 * @warning IPv6 地址必须用方括号括起，否则解析可能失败。
 */
[[nodiscard]] auto resolve(std::string_view host_port, memory::resource_pointer mr = nullptr)
    -> protocol::target;

/**
 * @brief 解析主机端口字符串
 * @details 将 "host:port" 格式的字符串解析为独立的主机和端口组件。
 * 处理 IPv6 地址的方括号语法、端口分隔符查找、主机部分提取和
 * 端口部分验证。如果解析失败，host 和 port 可能被清空或设置为默认值，
 * 不抛出异常。
 * @param src 源字符串，格式为 "host:port" 或 "[ipv6]:port"
 * @param host 输出参数，存储解析出的主机名或 IP 地址
 * @param port 输出参数，存储解析出的端口号
 * @note 主机和端口字符串必须使用相同的内存资源分配器。
 */
void parse(std::string_view src, memory::string &host, memory::string &port);

} // namespace psm::recognition
