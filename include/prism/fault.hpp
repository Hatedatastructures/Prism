/**
 * @file fault.hpp
 * @brief Fault 模块聚合头文件
 * @details 聚合引入错误码定义、标准库兼容性支持和错误检查
 * 适配层，为上层组件提供统一的错误处理基础设施。
 * 包含 code（错误码枚举）、compatible（std::error_code
 * 兼容）和 handling（错误检查适配）三个子模块。
 * 该模块遵循热路径无异常原则，所有函数均为 constexpr
 * 和 noexcept，无动态分配和异常开销。
 * @note 该模块是性能关键代码，修改时需确保不引入运行时
 * 开销。
 * @warning describe() 返回静态字面量，保证零分配，可用于
 * 热路径日志。
 */
#pragma once

#include <prism/fault/code.hpp>
#include <prism/fault/compatible.hpp>
#include <prism/fault/handling.hpp>
