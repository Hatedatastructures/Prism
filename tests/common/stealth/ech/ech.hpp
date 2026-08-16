/**
 * @file ech.hpp
 * @brief ECH 伪装方案聚合头
 * @details ECH（Encrypted Client Hello）：服务端注册 SSL_ECH_KEYS，
 *          检测 ClientHello 中的 ECH 扩展（0xfe0d），解密内层 SNI。
 * @note 密钥生成与 SSL_ECH_KEYS 构造见 keygen.hpp；检测见 scan.hpp
 */

#pragma once

#include <common/stealth/ech/keygen.hpp>
#include <common/stealth/ech/scan.hpp>
#include <common/stealth/ech/types.hpp>
