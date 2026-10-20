/**
 * @file Foundation.hpp
 * @brief Core 模块聚合头文件
 * @details 聚合引入基础设施三子模块：
 *   - memory：基于 PMR 的高性能内存管理（容器别名、全局/线程局部内存池、帧竞技场）
 *   - fault：错误码定义、std::error_code 兼容、错误检查适配
 *   - exception：异常层次（Deviant 基类 + Network/Protocol/Security）
 * 该模块为整个项目的基础层，所有上层模块都依赖此处定义的类型。
 * 遵循热路径零开销原则，所有函数 constexpr/noexcept，无动态分配。
 * @note 命名空间保留为原子形式：Prism::Memory、Prism::Fault、Prism::Exception
 * @warning 线程局部资源分配的内存严禁跨线程使用
 * @note 本文件只负责聚合头，不在此处定义基础设施实现。
 */
#pragma once

// Identifier 子模块
#include <Prism/Foundation/Identifier/Id.hpp>

// Error 子模块
#include <Prism/Foundation/Error/Expected.hpp>

// Executor 子模块
#include <Prism/Foundation/Executor/Affinity.hpp>

// Cancellation 子模块
#include <Prism/Foundation/Cancellation/Mode.hpp>

// Memory 子模块
#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Foundation/Memory/Domain.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Foundation/Memory/Pool.hpp>
#include <Prism/Foundation/Memory/OwnedBytes.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>

// Coroutine 子模块

// Fault 子模块
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Fault/Compatible.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>

// Exception 子模块
#include <Prism/Foundation/Exception/Deviant.hpp>
#include <Prism/Foundation/Exception/Network.hpp>
#include <Prism/Foundation/Exception/Protocol.hpp>
#include <Prism/Foundation/Exception/Security.hpp>
