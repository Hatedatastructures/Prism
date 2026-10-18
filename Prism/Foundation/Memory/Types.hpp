/**
 * @file Types.hpp
 * @brief Memory 子模块的值类型入口，转发 Domain.hpp 的内存域枚举。
 * @details 唯一内容是指向 Prism/Foundation/Memory/Domain.hpp 的 include，不声明新类型。
 *          Domain.hpp 拥有 Prism::Memory::Domain（Global、Process=Global、Worker、Session、
 *          Stream、Request、Snapshot）及 MemoryDomain 别名，并在 Prism 命名空间导出 MemoryDomain。
 *          该枚举只是标记资源所属层次的值语义标签，不携带资源所有权；分配与回收由同目录承担：
 *          Container.hpp 提供 PMR 容器别名与默认资源，Pool.hpp 定义内存池，BytePool.hpp 提供
 *          冷构造、有界准入、可回收的字节池 owner。
 * @note 由 Foundation.hpp 聚合引入，供调用者声明资源归属层次而不引入分配实现。
 */

#pragma once

#include <Prism/Foundation/Memory/Domain.hpp>
