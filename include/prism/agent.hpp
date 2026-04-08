/**
 * @file agent.hpp
 * @brief Agent 模块聚合头文件
 * @details 包含代理服务的核心组件，提供完整的正向代理引擎实现。
 *
 * 模块组成：
 * @details - account/：账户管理模块，包含凭据验证和用户配额；
 * @details - dispatch/：协议分发模块，包含 handler 和 handlers；
 * @details - front/：前端监听模块，包含 balancer 和 listener；
 * @details - session/：会话管理模块，定义 session 类；
 * @details - worker/：工作线程模块，包含 worker、stats、tls、launch。
 *
 * 设计架构：
 * @details - Worker 隔离：每个 Worker 拥有独立 io_context，无锁设计；
 * @details - 负载均衡：Balancer 根据负载快照分发连接到最空闲 Worker；
 * @details - 协议栈：通过 pipeline 构建 HTTP/SOCKS5/Trojan 协议处理器；
 * @details - 连接复用：通过 connection_pool 管理上游连接缓存；
 * @details - 路由决策：router 整合 DNS 解析、反向路由表、连接池。
 *
 * 数据流向：
 * @details Listener → Balancer → Workers → Sessions → Handlers → Protocols
 * @details                                                    |
 * @details                                             Connection Pool → 目标服务
 *
 * @note 该模块是代理服务的核心，所有连接处理和数据转发在此完成。
 * @warning Worker 对象不可跨线程共享，所有成员访问必须在 Worker 线程内。
 */
#pragma once

#include <prism/agent/account/directory.hpp>
#include <prism/agent/account/entry.hpp>
#include <prism/agent/config.hpp>
#include <prism/agent/session/session.hpp>
#include <prism/agent/context.hpp>
#include <prism/agent/dispatch/handler.hpp>
#include <prism/agent/dispatch/handlers.hpp>
#include <prism/resolve/router.hpp>
#include <prism/resolve/transparent.hpp>
#include <prism/agent/front/balancer.hpp>
#include <prism/agent/front/listener.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/pipeline/protocols.hpp>
#include <prism/agent/worker/launch.hpp>
#include <prism/agent/worker/stats.hpp>
#include <prism/agent/worker/tls.hpp>
#include <prism/agent/worker/worker.hpp>
