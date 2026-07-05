/**
 * @file trace.hpp
 * @brief Trace 模块聚合头文件
 * @details 聚合引入日志与可观测性系统的所有组件，包含
 * 日志配置（config）、会话前缀上下文（context）、token
 * awaitable 包装（token）和 spdlog 日志实现四个子模块。
 * 使用异步日志记录避免 I/O 阻塞业务线程，支持文件和
 * 控制台双输出、日志轮转和格式定制。
 * @warning 异步日志队列满时，根据 spdlog 策略可能阻塞
 * 或丢弃日志。
 */
#pragma once

#include <prism/trace/config.hpp>
#include <prism/trace/context.hpp>
#include <prism/trace/token.hpp>
#include <prism/trace/spdlog.hpp>


