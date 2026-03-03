/**
 * @file agent.hpp
 * @brief Agent 模块聚合头文件
 * @details 包含 Agent 模块的所有核心组件，提供统一的代理服务入口。
 * 该模块是代理服务的核心业务层，负责会话管理、流量分发和协议处理。
 *
 * 包含组件：
 * - 配置管理 (`config.hpp`)：代理服务的配置结构定义；
 * - 流量分发 (`distributor.hpp`)：路由决策和连接管理；
 * - 会话管理 (`session.hpp`)：客户端连接的生命周期管理；
 * - 工作线程 (`worker.hpp`)：代理服务的运行时容器；
 * - 协议处理 (`handler.hpp`)：协议处理器接口和工厂；
 * - 验证器 (`validator.hpp`)：账户验证和连接数配额控制。
 *
 * 架构层次：
 * ```
 * ngx::agent::worker (运行时容器)
 * └── ngx::agent::session (会话管理)
 *     ├── ngx::agent::detection (协议检测)
 *     ├── ngx::agent::handler (协议处理器)
 *     │   ├── http_handler
 *     │   ├── socks5_handler
 *     │   └── tls_handler
 *     └── ngx::agent::distributor (路由分发)
 *         └── ngx::transport::source (连接池)
 * ```
 *
 * @note 所有组件使用 PMR 内存管理，支持自定义内存分配器。
 * @warning 组件应在正确的生命周期内使用，避免悬垂引用。
 */
#pragma once

#include <forward-engine/agent/config.hpp>
#include <forward-engine/agent/distributor.hpp>
#include <forward-engine/agent/distribute.hpp>
#include <forward-engine/agent/listener.hpp>
#include <forward-engine/agent/session.hpp>
#include <forward-engine/agent/worker.hpp>
#include <forward-engine/agent/handler.hpp>
#include <forward-engine/agent/validator.hpp>
