/**
 * @file Conn.hpp
 * @brief XHTTP 公共连接工厂聚合入口。
 * @details 协议选项与 Connect/Accept 保留在模块根目录；私有 stream/split 状态、
 *          driver、writer 和 transport owner 位于 Detail 子目录。
 */
#pragma once

#include <Preview/Protocols/Xhttp/Entry.hpp>
#include <Preview/Protocols/Xhttp/Types.hpp>
