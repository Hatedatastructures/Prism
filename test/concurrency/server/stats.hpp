/**
 * @file stats.hpp
 * @brief 统计模块主入口
 * @details 包含所有统计相关的头文件，提供统一的统计功能接口。
 *
 * 核心特性：
 * - 连接信息：记录客户端连接详情
 * - 统计指标：原子操作的高性能计数器
 * - 统计快照：支持 JSON 序列化的统计数据
 *
 * @note 使用方式：
 * @code
 * #include "server/stats.hpp"
 *
 * srv::stats::detailed_stats stats;
 * stats.increment_requests();
 * auto snapshot = srv::stats::create_snapshot(stats);
 * @endcode
 *
 */
#pragma once

#include "stats/connection.hpp"
#include "stats/metrics.hpp"
#include "stats/snapshot.hpp"
