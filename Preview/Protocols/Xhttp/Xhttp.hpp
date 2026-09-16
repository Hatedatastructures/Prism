/**
 * @file Xhttp.hpp
 * @brief XHTTP 伪装方案聚合头
 * @details TLS + HTTP/2 + Stream-one（单 POST 双向流）。
 * @note 配置类型和连接实现分别由 Types.hpp、Conn.hpp 提供，本文件不重复定义协议逻辑。
 */

#pragma once

#include <Preview/Protocols/Xhttp/Types.hpp>
#include <Preview/Protocols/Xhttp/Conn.hpp>
