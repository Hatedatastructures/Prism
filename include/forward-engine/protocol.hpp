/**
 * @file protocol.hpp
 * @brief Protocol 模块聚合头文件
 * @details 包含所有支持协议的实现（HTTP, SOCKS5, Trojan 等）。
 */
#pragma once

#include <forward-engine/protocol/frame.hpp>
#include <forward-engine/protocol/analysis.hpp>

#include <forward-engine/protocol/http.hpp>
#include <forward-engine/protocol/trojan.hpp>
#include <forward-engine/protocol/socks5.hpp>