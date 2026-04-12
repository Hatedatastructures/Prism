/**
 * @file protocols.hpp
 * @brief 协议处理管道聚合头文件
 * @details 聚合所有协议处理管道的头文件，提供统一的包含入口。
 * 包括 HTTP、SOCKS5 和 Trojan 协议的会话处理函数声明。
 */
#pragma once

#include <prism/pipeline/protocols/http.hpp>
#include <prism/pipeline/protocols/socks5.hpp>
#include <prism/pipeline/protocols/trojan.hpp>
#include <prism/pipeline/protocols/vless.hpp>
#include <prism/pipeline/protocols/shadowsocks.hpp>
