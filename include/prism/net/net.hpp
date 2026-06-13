/**
 * @file net.hpp
 * @brief Net 模块聚合头文件
 * @details 聚合引入网络层三子模块：
 *   - transport：传输层（TCP/TLS/UDP/预读重放/适配器）
 *   - connect：连接管理（dial 路由/连接池/tunnel 转发）
 *   - resolve：DNS 解析（七阶段管道/cache/rules/upstream）
 * 该模块为协议层提供统一的网络数据通道抽象。
 * @note 命名空间保留为原子形式：psm::transport、psm::connect、psm::resolve
 */
#pragma once

// Transport 子模块
#include <prism/net/transport/adapter/connector.hpp>
#include <prism/net/transport/encrypted.hpp>
#include <prism/net/transport/preview.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/net/transport/snapshot.hpp>
#include <prism/net/transport/transmission.hpp>
#include <prism/net/transport/unreliable.hpp>

// Connect 子模块
#include <prism/net/connect/dial/dial.hpp>
#include <prism/net/connect/dial/racer.hpp>
#include <prism/net/connect/dial/router.hpp>
#include <prism/net/connect/pool/config.hpp>
#include <prism/net/connect/pool/health.hpp>
#include <prism/net/connect/pool/pool.hpp>
#include <prism/net/connect/tunnel/forward.hpp>
#include <prism/net/connect/tunnel/tunnel.hpp>
#include <prism/net/connect/util.hpp>

// Resolve 子模块
#include <prism/net/resolve/dns/config.hpp>
#include <prism/net/resolve/dns/detail/cache.hpp>
#include <prism/net/resolve/dns/detail/coalescer.hpp>
#include <prism/net/resolve/dns/detail/format.hpp>
#include <prism/net/resolve/dns/detail/rules.hpp>
#include <prism/net/resolve/dns/detail/transparent.hpp>
#include <prism/net/resolve/dns/detail/utility.hpp>
#include <prism/net/resolve/dns/dns.hpp>
#include <prism/net/resolve/dns/upstream.hpp>
