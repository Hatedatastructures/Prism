/**
 * @file protocol.hpp
 * @brief Proto 模块聚合头文件
 * @details 聚合引入协议层两子模块：
 *   - protocol：协议实现（HTTP/SOCKS5/Trojan/VLESS/Shadowsocks + TLS 类型/通用工具）
 *   - multiplex：多路复用（bootstrap/core/duct/parcel + smux/yamux/h2mux）
 * 该模块负责协议级解析、转换、多路复用与子流管理。
 * @note 命名空间保留为原子形式：psm::protocol、psm::multiplex
 */
#pragma once

// Protocol 子模块
#include <prism/protocol/common/mux.hpp>
#include <prism/net/connect/target.hpp>
#include <prism/protocol/tls/types.hpp>
#include <prism/net/connect/types.hpp>
#include <prism/protocol/http/http.hpp>
#include <prism/protocol/shadowsocks/shadowsocks.hpp>
#include <prism/protocol/socks5/socks5.hpp>
#include <prism/protocol/trojan/trojan.hpp>
#include <prism/protocol/vless/vless.hpp>

// Multiplex 子模块
#include <prism/protocol/multiplex/bootstrap.hpp>
#include <prism/protocol/multiplex/config.hpp>
#include <prism/protocol/multiplex/core.hpp>
#include <prism/protocol/multiplex/duct.hpp>
#include <prism/protocol/multiplex/parcel.hpp>
#include <prism/protocol/multiplex/smux/config.hpp>
#include <prism/protocol/multiplex/smux/craft.hpp>
#include <prism/protocol/multiplex/smux/frame.hpp>
#include <prism/protocol/multiplex/yamux/config.hpp>
#include <prism/protocol/multiplex/yamux/craft.hpp>
#include <prism/protocol/multiplex/yamux/frame.hpp>
#include <prism/protocol/multiplex/h2mux/config.hpp>
#include <prism/protocol/multiplex/h2mux/craft.hpp>
