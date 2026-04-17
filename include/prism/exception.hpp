/**
 * @file exception.hpp
 * @brief Exception 模块聚合头文件
 * @details 聚合引入所有异常类型定义，包含异常基类 deviant、
 * 网络异常 network、协议异常 protocol 和安全异常
 * security。异常层次以 std::runtime_error 为根，
 * exception::deviant 为抽象基类，派生出三类具体异常。
 * @note 所有自定义异常应继承自 exception::deviant 并
 * 实现 type_name()。
 * @warning 异常不应作为正常的控制流机制，仅用于错误恢复。
 */
#pragma once

#include <prism/exception/deviant.hpp>
#include <prism/exception/protocol.hpp>
#include <prism/exception/network.hpp>
#include <prism/exception/security.hpp>
