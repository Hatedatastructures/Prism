/**
 * @file stealth.hpp
 * @brief Stealth 模块聚合头文件
 * @details 聚合引入 Reality TLS 伪装层的所有组件，包含配置、
 * 常量、请求/响应处理、认证、密钥生成、封装和握手等
 * 子模块。stealth 是独立的 TLS 伪装层，实现 TLS 指纹
 * 伪装和 X25519 密钥交换，可叠加任意内层协议。
 */

#pragma once

#include <prism/stealth/common.hpp>
#include <prism/stealth/executor.hpp>
#include <prism/stealth/facade/native.hpp>
#include <prism/stealth/registry.hpp>
#include <prism/stealth/scheme.hpp>
#include <prism/stealth/seal/io.hpp>

#include <prism/stealth/stack/anytls/scheme.hpp>
#include <prism/stealth/ech/config.hpp>
#include <prism/stealth/ech/util/decrypt.hpp>
#include <prism/stealth/facade/reality/config.hpp>
#include <prism/stealth/facade/reality/handshake.hpp>
#include <prism/stealth/facade/reality/scheme.hpp>
#include <prism/stealth/facade/reality/seal.hpp>
#include <prism/stealth/facade/reality/util/auth.hpp>
#include <prism/stealth/facade/reality/util/keygen.hpp>
#include <prism/stealth/facade/reality/util/response.hpp>
#include <prism/stealth/facade/restls/scheme.hpp>
#include <prism/stealth/facade/shadowtls/scheme.hpp>
#include <prism/stealth/stack/trusttunnel/scheme.hpp>


