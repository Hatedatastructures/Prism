/**
 * @file runtime.hpp
 * @brief Runtime 模块聚合头文件
 * @details 聚合引入代理服务的全部核心组件，涵盖账户
 * 管理、协议分发、前端监听、负载均衡、会话管理、
 * 工作线程等子模块。Instance 是 Prism 正向代理引擎的
 * 主体，所有连接处理和数据转发均在此模块内完成。
 * 每个 Worker 拥有独立 io_context，采用无锁设计，
 * 由 Balancer 分发连接。
 */
#pragma once

#include <prism/account/directory.hpp>
#include <prism/account/entry.hpp>
#include <prism/net/net.hpp>
#include <prism/net/connect/dial/router.hpp>
#include <prism/resource/session.hpp>
#include <prism/runtime/config.hpp>
#include <prism/runtime/front/balancer.hpp>
#include <prism/runtime/front/listener.hpp>
#include <prism/runtime/session/session.hpp>
#include <prism/runtime/worker/launch.hpp>
#include <prism/runtime/worker/tls.hpp>
#include <prism/runtime/worker/worker.hpp>
#include <prism/account/stats/runtime.hpp>
#include <prism/account/stats/traffic.hpp>

// Outbound 子模块（出站代理：直连 + 代理转发）
#include <prism/net/connect/outbound/direct.hpp>
#include <prism/net/connect/outbound/proxy.hpp>


