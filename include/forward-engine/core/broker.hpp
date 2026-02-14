/**
 * @file broker.hpp
 * @brief 核心组件聚合
 * @details 聚合了 HTTP 协议和 Agent 相关的头文件，方便核心模块引用。
 * 该文件是核心模块的统一入口，简化了依赖管理。
 *
 * 包含组件：
 * - HTTP 协议 (`protocol/http.hpp`)：HTTP 协议解析和序列化；
 * - Agent 模块 (`agent.hpp`)：代理服务的核心业务逻辑。
 *
 * ```
 * // 使用示例：包含核心组件
 * #include <forward-engine/core/broker.hpp>
 *
 * // 现在可以使用 HTTP 协议和 Agent 模块的所有功能
 * ngx::protocol::http::request req;
 * ngx::agent::config cfg;
 * ```
 *
 * @note 该文件仅用于简化引用，不定义任何新的类型或函数。
 */
#pragma once

#include <forward-engine/protocol/http.hpp>
#include <forward-engine/agent.hpp>
