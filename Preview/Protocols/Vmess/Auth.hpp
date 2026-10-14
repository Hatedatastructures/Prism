/**
 * @file Auth.hpp
 * @brief VMess 认证 API 聚合入口
 * @details 保留现有公共入口；实现按密码学原语、KDF、AuthID 和认证头
 *          wire 所有权拆分到对应头文件。
 */

#pragma once

#include <Preview/Protocols/Vmess/AuthCrypto.hpp>
#include <Preview/Protocols/Vmess/AuthKdf.hpp>
#include <Preview/Protocols/Vmess/AuthId.hpp>
#include <Preview/Protocols/Vmess/AuthHeader.hpp>
