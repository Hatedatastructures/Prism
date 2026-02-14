/**
 * @file trace.hpp
 * @brief Trace 模块聚合头文件
 * @details 包含日志与可观测性系统的所有组件，提供统一的日志记录接口。该模块是系统可观测性的核心，支持多级别、多目标的日志输出。
 *
 * 模块组成：
 * @details - config.hpp：日志系统配置，定义输出目标、格式、级别和性能调优选项；
 * @details - spdlog.hpp：高性能异步日志接口，封装 spdlog 库提供统一的日志记录 API；
 * @details - monitor.hpp：已弃用的协程日志系统，保留作为参考实现。
 *
 * 设计原理：
 * @details - 性能优先：使用异步日志记录，避免 I/O 操作阻塞业务线程；
 * @details - 配置驱动：通过配置结构灵活控制日志行为，支持热重载；
 * @details - 资源管理：控制日志文件大小和数量，避免磁盘空间耗尽；
 * @details - PMR 内存管理：使用 memory::string（PMR 分配器）减少堆碎片。
 *
 * 核心功能：
 * @details - 多目标输出：支持文件和控制台双输出，可独立启用/禁用；
 * @details - 日志轮转：基于文件大小和数量的自动轮转机制；
 * @details - 异步缓冲：后台线程刷盘，避免阻塞主业务逻辑；
 * @details - 格式定制：可自定义日志格式，支持时间戳、级别、线程 ID 等信息。
 *
 * @note 推荐使用 spdlog 接口，避免使用已弃用的 monitor 模块。
 * @warning 异步日志队列满时，根据 spdlog 策略可能阻塞或丢弃日志。
 */
#pragma once

#include <forward-engine/trace/config.hpp>
#include <forward-engine/trace/spdlog.hpp>
#include <forward-engine/trace/monitor.hpp>