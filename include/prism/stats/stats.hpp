/**
 * @file stats.hpp
 * @brief 统计模块聚合头文件
 * @details 引入统计模块的所有子头文件，提供一站式 include。
 * 模块结构：
 * - counter.hpp / gauge.hpp: 底层原子原语
 * - snapshot.hpp: 所有快照类型定义
 * - runtime.hpp: worker 负载 + 全局运行状态
 * - traffic.hpp: per-worker 流量统计 + 全局聚合
 * - account.hpp: 账户统计观察者
 * - memory.hpp: 内存分配统计追踪器
 */
#pragma once

#include <prism/stats/account.hpp>
#include <prism/stats/counter.hpp>
#include <prism/stats/gauge.hpp>
#include <prism/stats/memory.hpp>
#include <prism/stats/runtime.hpp>
#include <prism/stats/snapshot.hpp>
#include <prism/stats/traffic.hpp>


