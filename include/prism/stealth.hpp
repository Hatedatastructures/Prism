/**
 * @file stealth.hpp
 * @brief Stealth 模块聚合头文件
 * @details 聚合引入 Reality TLS 伪装层的所有组件，包含配置、
 * 常量、请求/响应处理、认证、密钥生成、封装和握手等
 * 子模块。stealth 是独立的 TLS 伪装层，实现 TLS 指纹
 * 伪装和 X25519 密钥交换，可叠加任意内层协议。
 */

#pragma once

#include <prism/stealth/scheme.hpp>
#include <prism/stealth/registry.hpp>
#include <prism/stealth/executor.hpp>
#include <prism/stealth/native.hpp>

#include <prism/stealth/reality/config.hpp>
#include <prism/stealth/reality/constants.hpp>
#include <prism/stealth/reality/request.hpp>
#include <prism/stealth/reality/auth.hpp>
#include <prism/stealth/reality/keygen.hpp>
#include <prism/stealth/reality/response.hpp>
#include <prism/stealth/reality/seal.hpp>
#include <prism/stealth/reality/handshake.hpp>
#include <prism/stealth/reality/scheme.hpp>

#include <prism/stealth/shadowtls/scheme.hpp>
#include <prism/stealth/restls/scheme.hpp>
