/**
 * @file server.hpp
 * @brief 服务器模块主入口
 * @details 包含所有服务器相关的头文件，提供统一的服务器功能接口。
 *
 * 核心特性：
 * - 双端口服务器：主端口提供业务 API，统计端口提供统计信息
 * - 多线程 IO：支持多线程 IO 处理
 * - SSL/TLS 支持：可选的 SSL/TLS 加密
 * - WebSocket 支持：支持 WebSocket 实时统计推送
 *
 * @note 使用方式：
 * @code
 * #include "server/server.hpp"
 *
 * int main(int argc, char* argv[]) {
 *     return srv::server::entrance(argc, argv);
 * }
 * @endcode
 *
 */
#pragma once

#include "server/stats.hpp"
#include "server/router/route.hpp"
#include "server/router/main_router.hpp"
#include "server/router/stats_router.hpp"
#include "server/stream/tcp_wrapper.hpp"
#include "server/stream/ssl_wrapper.hpp"
#include "server/mime/types.hpp"
#include "server/handler/static_file.hpp"
#include "server/handler/main_api.hpp"
#include "server/handler/stats_api.hpp"
#include "server/websocket/handler.hpp"
#include "server/core/dual_port.hpp"
#include "server/session.hpp"
