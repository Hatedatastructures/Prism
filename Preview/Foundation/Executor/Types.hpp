/**
 * @file Types.hpp
 * @brief Executor 子模块的值类型入口，转发 Affinity.hpp 的执行器亲和性枚举。
 * @details 唯一内容是指向 Preview/Foundation/Executor/Affinity.hpp 的 include，不声明新类型。
 *          Affinity.hpp 拥有 Preview::Executor::Affinity（Any、Caller、Process、Worker、Session、
 *          Stream、Control）及其 ExecutorAffinity 别名，并在 Preview 命名空间导出同名别名。
 *          亲和性只是回调被允许在哪个执行上下文运行的值约束；本头不选择、不持有也不调度 executor，
 *          context 与分配器的独立保留由 ContextOwner.hpp 承担，拥有型动作交付到唯一原 executor
 *          由 ExecutorReclaimer.hpp 承担。
 * @note 由 Foundation.hpp 聚合引入，供回调声明其执行上下文要求。
 */

#pragma once

#include <Preview/Foundation/Executor/Affinity.hpp>
