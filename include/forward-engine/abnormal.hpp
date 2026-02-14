/**
 * @file abnormal.hpp
 * @brief Abnormal 模块聚合头文件
 * @details 包含异常处理体系的所有异常定义，提供统一的异常处理接口。
 * 该模块是项目异常处理系统的入口，聚合了所有异常类型的头文件。
 *
 * 包含组件：
 * - 异常基类 (`deviant.hpp`)：所有自定义异常的公共基类；
 * - 网络异常 (`network.hpp`)：网络相关的异常类型；
 * - 协议异常 (`protocol.hpp`)：协议解析相关的异常类型；
 * - 安全异常 (`security.hpp`)：安全验证相关的异常类型。
 *
 * 异常层次：
 * ```
 * std::runtime_error
 * └── ngx::abnormal::exception (抽象基类)
 *     ├── ngx::abnormal::network (网络错误)
 *     ├── ngx::abnormal::security (安全错误)
 *     └── ngx::abnormal::protocol (协议错误)
 * ```
 *
 * @note 所有自定义异常应继承自 `abnormal::exception` 并实现 `type_name()`。
 * @warning 异常不应作为正常的控制流机制，仅用于错误恢复。
 */
#pragma once

#include <forward-engine/abnormal/deviant.hpp>
#include <forward-engine/abnormal/protocol.hpp>
#include <forward-engine/abnormal/network.hpp>
#include <forward-engine/abnormal/security.hpp>
