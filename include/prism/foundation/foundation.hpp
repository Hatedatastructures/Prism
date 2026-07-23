/**
 * @file foundation.hpp
 * @brief Core 模块聚合头文件
 * @details 聚合引入基础设施三子模块：
 *   - memory：基于 PMR 的高性能内存管理（容器别名、全局/线程局部内存池）
 *   - fault：错误码定义、std::error_code 兼容、错误检查适配
 *   - exception：异常层次（deviant 基类 + network/protocol/security）
 * 该模块为整个项目的基础层，所有上层模块都依赖此处定义的类型。
 * 遵循热路径零开销原则，所有函数 constexpr/noexcept，无动态分配。
 * @note 命名空间保留为原子形式：psm::memory、psm::fault、psm::exception
 * @warning 线程局部资源分配的内存严禁跨线程使用
 */
#pragma once

// Memory 子模块
#include <prism/foundation/memory/container.hpp>
#include <prism/foundation/memory/pool.hpp>

// Fault 子模块
#include <prism/foundation/fault/code.hpp>
#include <prism/foundation/fault/compatible.hpp>
#include <prism/foundation/fault/handling.hpp>

// Exception 子模块
#include <prism/foundation/exception/deviant.hpp>
#include <prism/foundation/exception/network.hpp>
#include <prism/foundation/exception/protocol.hpp>
#include <prism/foundation/exception/security.hpp>
#include <prism/foundation/coroutine/registry.hpp>

// Probe 子模块
#include <prism/foundation/rate/counter.hpp>
