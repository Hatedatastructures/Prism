/**
 * @file exception.hpp
 * @brief Exception 模块聚合头文件
 * @details 该模块是项目异常处理系统的入口，聚合了所有异常类型的头文件。
 * 包含异常基类 deviant.hpp、网络异常 network.hpp、协议异常 protocol.hpp
 * 和安全异常 security.hpp。所有自定义异常应继承自 exception::deviant
 * 并实现 type_name() 方法。异常层次以 std::runtime_error 为根，
 * exception::deviant 为抽象基类，派生出 network、security、protocol
 * 三类具体异常。异常不应作为正常的控制流机制，仅用于错误恢复。
 * @note 所有自定义异常应继承自 exception::deviant 并实现 type_name()。
 * @warning 异常不应作为正常的控制流机制，仅用于错误恢复。
 */
#pragma once

#include <prism/exception/deviant.hpp>
#include <prism/exception/protocol.hpp>
#include <prism/exception/network.hpp>
#include <prism/exception/security.hpp>
