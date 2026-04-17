/**
 * @file memory.hpp
 * @brief Memory 模块聚合头文件
 * @details 聚合引入基于 PMR 的高性能内存管理基础设施，
 * 包含 PMR 容器别名（container）和全局/线程局部内存池
 * （pool）两个子模块。该模块遵循热路径无分配原则，
 * 通过线程封闭实现无锁并发，小对象池化、大对象直通
 * 系统堆。
 * @note 该模块是性能关键代码，修改时需确保不引入运行时
 * 开销。
 * @warning 线程局部资源分配的内存严禁跨线程使用。
 */
#pragma once

#include <prism/memory/container.hpp>
#include <prism/memory/pool.hpp>