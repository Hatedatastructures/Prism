/**
 * @file agent.hpp
 * @brief Agent 模块聚合头文件
 * @details 聚合引入代理服务的全部核心组件，涵盖账户
 * 管理、协议分发、前端监听、负载均衡、会话管理、
 * 工作线程等子模块。Agent 是 Prism 正向代理引擎的
 * 主体，所有连接处理和数据转发均在此模块内完成。
 * 每个 Worker 拥有独立 io_context，采用无锁设计，
 * 由 Balancer 分发连接。
 */
#pragma once

#include <prism/agent/account/directory.hpp>
#include <prism/agent/account/entry.hpp>
#include <prism/agent/config.hpp>
#include <prism/agent/session/session.hpp>
#include <prism/agent/context.hpp>
#include <prism/agent/dispatch/table.hpp>
#include <prism/resolve/router.hpp>
#include <prism/agent/front/balancer.hpp>
#include <prism/agent/front/listener.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/pipeline/protocols.hpp>
#include <prism/agent/worker/launch.hpp>
#include <prism/agent/worker/stats.hpp>
#include <prism/agent/worker/tls.hpp>
#include <prism/agent/worker/worker.hpp>
