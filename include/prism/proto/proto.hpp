/**
 * @file proto.hpp
 * @brief Proto 模块聚合头文件
 * @details 聚合引入协议层两子模块：
 *   - protocol：协议实现（HTTP/SOCKS5/Trojan/VLESS/Shadowsocks + TLS 类型/通用工具）
 *   - multiplex：多路复用（bootstrap/core/duct/parcel + smux/yamux/h2mux）
 * 该模块负责协议级解析、转换、多路复用与子流管理。
 * @note 命名空间保留为原子形式：psm::protocol、psm::multiplex
 */
#pragma once

// Protocol 子模块
#include <prism/proto/protocol/common/mux.hpp>
#include <prism/proto/protocol/common/target.hpp>
#include <prism/proto/protocol/tls/types.hpp>
#include <prism/proto/protocol/types.hpp>
#include <prism/proto/protocol/http.hpp>
#include <prism/proto/protocol/shadowsocks.hpp>
#include <prism/proto/protocol/socks5.hpp>
#include <prism/proto/protocol/trojan.hpp>
#include <prism/proto/protocol/vless.hpp>

// Multiplex 子模块
#include <prism/proto/multiplex/bootstrap.hpp>
#include <prism/proto/multiplex/config.hpp>
#include <prism/proto/multiplex/core.hpp>
#include <prism/proto/multiplex/duct.hpp>
#include <prism/proto/multiplex/parcel.hpp>
#include <prism/proto/multiplex/smux/config.hpp>
#include <prism/proto/multiplex/smux/craft.hpp>
#include <prism/proto/multiplex/smux/frame.hpp>
#include <prism/proto/multiplex/yamux/config.hpp>
#include <prism/proto/multiplex/yamux/craft.hpp>
#include <prism/proto/multiplex/yamux/frame.hpp>
#include <prism/proto/multiplex/h2mux/config.hpp>
#include <prism/proto/multiplex/h2mux/craft.hpp>
