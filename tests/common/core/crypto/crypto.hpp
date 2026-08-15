/**
 * @file crypto.hpp
 * @brief Crypto 模块聚合头文件
 * @details 引入加密模块所有子头文件，提供统一的包含入口。
 */
#pragma once

#include <common/core/crypto/aead.hpp>
#include <common/core/crypto/base64.hpp>
#include <common/core/crypto/blake3.hpp>
#include <common/core/crypto/block.hpp>
#include <common/core/crypto/hkdf.hpp>
#include <common/core/crypto/sha224.hpp>
// #include <common/core/crypto/x25519.hpp>  // 依赖 BoringSSL curve25519，需要时另行引入
