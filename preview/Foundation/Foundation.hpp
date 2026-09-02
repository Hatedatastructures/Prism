/**
 * @file Foundation.hpp
 * @brief Core 模块聚合头文件
 * @details 聚合引入基础设施三子模块：
 *   - memory：基于 PMR 的高性能内存管理（容器别名、全局/线程局部内存池、帧竞技场）
 *   - fault：错误码定义、std::error_code 兼容、错误检查适配
 *   - exception：异常层次（Deviant 基类 + Network/Protocol/Security）
 * 该模块为整个项目的基础层，所有上层模块都依赖此处定义的类型。
 * 遵循热路径零开销原则，所有函数 constexpr/noexcept，无动态分配。
 * @note 命名空间保留为原子形式：Preview::Memory、Preview::Fault、Preview::Exception
 * @warning 线程局部资源分配的内存严禁跨线程使用
 */
#pragma once

// Memory 子模块
#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Foundation/Memory/Pool.hpp>

// Coroutine 子模块
#include <preview/Foundation/Utility/Coroutine/Registry.hpp>

// Fault 子模块
#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Foundation/Fault/Compatible.hpp>
#include <preview/Foundation/Fault/Handling.hpp>

// Exception 子模块
#include <preview/Foundation/Exception/Deviant.hpp>
#include <preview/Foundation/Exception/Network.hpp>
#include <preview/Foundation/Exception/Protocol.hpp>
#include <preview/Foundation/Exception/Security.hpp>
