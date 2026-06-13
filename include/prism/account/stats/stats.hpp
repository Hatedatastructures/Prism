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

#include <prism/account/stats/account.hpp>
#include <prism/account/stats/counter.hpp>
#include <prism/account/stats/gauge.hpp>
#include <prism/account/stats/memory.hpp>
#include <prism/account/stats/runtime.hpp>
#include <prism/account/stats/snapshot.hpp>
#include <prism/account/stats/traffic.hpp>


