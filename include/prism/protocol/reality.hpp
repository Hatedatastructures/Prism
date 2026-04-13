/**
 * @file reality.hpp
 * @brief Reality 协议聚合头文件
 * @details 引入 Reality 协议的所有子模块，包括配置、常量、
 * ClientHello 解析、认证、密钥调度、ServerHello 生成、
 * 加密传输层和握手状态机。
 */

#pragma once

#include <prism/protocol/reality/config.hpp>
#include <prism/protocol/reality/constants.hpp>
#include <prism/protocol/reality/request.hpp>
#include <prism/protocol/reality/auth.hpp>
#include <prism/protocol/reality/keygen.hpp>
#include <prism/protocol/reality/response.hpp>
#include <prism/protocol/reality/session.hpp>
#include <prism/protocol/reality/handshake.hpp>

// TODO 零拷贝优化，代码风格优化，解析优化