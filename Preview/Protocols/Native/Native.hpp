/**
 * @file Native.hpp
 * @brief Native 伪装方案聚合头
 * @details 原生 TLS 兜底：服务端 TLS 握手 + 直通（传输透明）。
 * @note 先导出 Types 配置，再导出 Conn 工厂/连接实现；公共 API 由子头定义。
 */

#pragma once

#include <Preview/Protocols/Native/Types.hpp>
#include <Preview/Protocols/Native/Conn.hpp>
