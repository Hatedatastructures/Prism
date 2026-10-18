/**
 * @file Events.hpp
 * @brief 事件面契约的转发头：只 include Statistics/EventRing.hpp，不声明新类型。
 * @details EventRing.hpp 在那里拥有有界事件环及其契约：Append 状态（Accepted、Dropped、
 *          TerminalDropped）、终态保留配额、表示已淘汰序号闭区间的 EventLoss 缺口，以及按游标
 *          返回真实事件、最早保留序号和缺口的分页查询。事件环由控制 executor 独占，冷构造槽位，
 *          Append 移交事件值，Page 返回不保活业务的拥有快照；普通事件可复用最老普通槽，
 *          终态可淘汰旧事件但至少保留指定数量的最新终态。
 * @note 事件正文的所有权、清除与序号推进仍由 EventRing 唯一拥有，本头不构成第二份事件事实。
 *       模块聚合入口是 Statistics.hpp，它直接 include EventRing.hpp。
 */

#pragma once

#include <Prism/Statistics/EventRing.hpp>
