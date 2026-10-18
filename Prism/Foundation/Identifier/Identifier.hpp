/**
 * @file Identifier.hpp
 * @brief Identifier 子模块的统一入口，转发 Types.hpp 及其带出的强类型标识符。
 * @details 唯一内容是指向 Prism/Foundation/Identifier/Types.hpp 的 include，不声明新类型。
 *          Types.hpp 再带 Id.hpp：Id<Tag, ValueType> 是按 Tag 区分、不可隐式互转的强类型数值标识，
 *          零值经 explicit operator bool 判为无效；TextId<Tag> 持有 std::string，用作 kind/name
 *          等稳定注册键，空值同样按显式 bool 判为无效。两者都默认生成相等与三路比较。
 *          标识符是纯值，不携带资源所有权、取消或生命周期含义。
 * @note 由 Foundation.hpp 聚合引入，builtin/snapshot/process/worker/session/stream/task/account
 *       等标识的正式定义位置是 Id.hpp。
 */

#pragma once

#include <Prism/Foundation/Identifier/Types.hpp>
