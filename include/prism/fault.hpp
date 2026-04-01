/**
 * @file fault.hpp
 * @brief Fault 模块聚合头文件
 * @details 包含项目基础类型和错误码定义，提供统一的错误处理基础设施。该模块是整个项目的"基石"，为上层组件提供稳定的基础设施支持。
 *
 * 模块组成：
 * @details - code.hpp：全局错误码枚举定义，遵循"热路径无异常"原则；
 * @details - compatible.hpp：错误码标准库兼容性支持，实现 std::error_code 和 boost::system::error_code 双向兼容；
 * @details - handling.hpp：极简错误码检查适配层，提供统一的错误检查接口。
 *
 * 设计原则：
 * @details - 热路径无异常：网络 I/O、协议解析、数据转发等热路径严禁抛异常，必须使用错误码返回值进行流控；
 * @details - 零开销：所有错误处理函数均为 constexpr 和 noexcept，无动态分配，无异常抛出；
 * @details - 双向兼容：同时支持 C++ 标准库和 Boost 生态系统，确保跨库互操作性。
 *
 * @note 该模块是性能关键代码，修改时需确保不引入运行时开销。
 * @warning 错误码描述函数 describe() 返回静态字面量，保证零分配，可用于热路径日志。
 */
#pragma once

#include <prism/fault/code.hpp>
#include <prism/fault/compatible.hpp>
#include <prism/fault/handling.hpp>
