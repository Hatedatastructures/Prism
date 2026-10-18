/**
 * @file Counters.hpp
 * @brief 统计计数面的聚合入口：稀疏计数表与 worker-local 流量增量。
 * @details 只做两条 include，不声明新类型：SparseCounters.hpp 拥有冷分配、值准入并按真实
 *          CounterScope（stream 必须携带父 session）退休的唯一计数表，只由控制 executor 使用，
 *          先核对完整键集合容量再一次准入（失败不留下部分计数事实），已准入键原地累加且溢出时
 *          保持旧值并独立计入 Overflow，scope 退休后归还全部节点；TrafficDelta.hpp 拥有按值持有
 *          最多 64 个范围字节增量的 worker-local 批次及其 exactly-once flush，拒绝不改变已有 batch。
 * @note 两个 owner 的容量、退休与溢出语义各自唯一，本头不引入第三个累加器或镜像计数表。
 *       模块聚合入口是 Statistics.hpp，它也直接 include 这两个头。
 */

#pragma once

#include <Prism/Statistics/SparseCounters.hpp>
#include <Prism/Statistics/TrafficDelta.hpp>
