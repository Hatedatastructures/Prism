/**
 * @file Builtin.hpp
 * @brief Composition Builtin 族的聚合头：能力位、描述项、注册表、冻结请求与只读快照。
 * @details 只做六条 include，不声明新类型：Capability.hpp 拥有 builtin 可声明或要求的能力位
 *          及自动补齐前置能力的不可变值集合；Descriptor.hpp 拥有单个静态 builtin 的元数据、
 *          无 I/O 回调和快照注册项；ProtocolBuiltins.hpp 拥有不含回调的编译期描述项以及
 *          协议与 carrier 所需的启动能力闭包；Registry.hpp 拥有显式注册并一次性冻结为
 *          不可变快照的行为，且只有它能为注册项分配 Id；Freeze.hpp 拥有注册表转快照时
 *          使用的值请求；Snapshot.hpp 拥有注册完成后只读的快照。
 * @note 能力校验、Id 分配与冻结约束仍归属被聚合的各头文件，本头不建立第二套注册表或快照事实。
 */

#pragma once

#include <Preview/Composition/Builtin/Capability.hpp>
#include <Preview/Composition/Builtin/Descriptor.hpp>
#include <Preview/Composition/Builtin/Freeze.hpp>
#include <Preview/Composition/Builtin/ProtocolBuiltins.hpp>
#include <Preview/Composition/Builtin/Registry.hpp>
#include <Preview/Composition/Builtin/Snapshot.hpp>
