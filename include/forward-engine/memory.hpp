/**
 * @file memory.hpp
 * @brief Memory 模块聚合头文件
 * @details 包含内存管理系统的所有组件，提供基于 PMR（Polymorphic Memory Resource）的高性能内存管理基础设施。该模块是实现"性能军规"中内存管理要求的核心。
 *
 * 模块组成：
 * @details - container.hpp：内存容器别名，使用 std::pmr 多态内存资源的容器类型定义；
 * @details - pointer.hpp：智能指针定义（预留），支持自定义删除器的智能指针；
 * @details - pool.hpp：内存池系统，提供全局和线程局部的内存池管理。
 *
 * 设计哲学：
 * @details - 热路径无分配：网络 I/O、协议解析等热路径严禁 new/malloc；
 * @details - 线程封闭：通过线程局部池实现无锁并发（Thread Confinement）；
 * @details - 大小分类：小对象池化（≤16KB），大对象直通系统堆；
 * @details - 生命周期管理：全局池用于跨线程对象，线程局部池用于临时对象。
 *
 * @note 该模块是性能关键代码，修改时需确保不引入运行时开销。
 * @warning 线程局部资源分配的内存严禁跨线程使用。
 */
#pragma once

#include <forward-engine/memory/container.hpp>
#include <forward-engine/memory/pointer.hpp>
#include <forward-engine/memory/pool.hpp>