/**
 * @file socks5.hpp
 * @brief SOCKS5 协议支持库聚合头文件
 * @details 聚合了 SOCKS5 协议相关的头文件，提供完整的 SOCKS5 协议
 * RFC 1928 服务端实现。支持无认证模式，处理 CONNECT、BIND 和 UDP
 * ASSOCIATE 命令。模块组成包括 constants.hpp 定义 SOCKS5 协议常量，
 * 包含命令、地址类型、认证方法和响应码枚举。message.hpp 定义 SOCKS5
 * 消息结构，定义地址结构和请求消息结构。wire.hpp 提供 SOCKS5 协议线级
 * 解析，提供头部、地址和端口的解码函数。stream.hpp 提供 SOCKS5 协议流
 * 封装，提供协程友好的高级 API。核心特性包括协议完整，支持 SOCKS5 协议
 * 所有核心功能，包括 CONNECT、BIND、UDP ASSOCIATE 命令。地址类型全面，
 * 支持 IPv4、IPv6 和域名地址类型。认证灵活，支持无认证 0x00 和用户名
 * 密码认证 0x02。协程友好，所有操作基于 boost::asio::awaitable，支持
 * 异步无阻塞处理。协议流程为首先进行方法协商，客户端发送支持的方法列表，
 * 服务器选择并确认。然后进行请求处理，读取客户端请求，解析命令、地址
 * 类型和目标地址。接着进行响应发送，根据处理结果发送成功或错误响应。
 * 最后进行数据转发，握手成功后，提供透明的数据读写接口。
 * @note 参考文档 RFC 1928 SOCKS Protocol Version 5。
 * @warning 安全考虑方面，默认仅支持无认证，生产环境应启用用户名密码认证。
 */
#pragma once

#include <prism/protocol/socks5/constants.hpp>
#include <prism/protocol/socks5/message.hpp>
#include <prism/protocol/socks5/wire.hpp>
#include <prism/protocol/socks5/stream.hpp>
