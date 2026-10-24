/**
 * @file Xhttp.hpp
 * @brief XHTTP 伪装方案的公开聚合头。
 * @details TLS + HTTP/2 + Stream-one（单 POST 双向流）。
 * @note 配置类型由 ConnectionTypes.hpp 提供，客户端和服务端入口由 Entry.hpp 提供。
 */

#pragma once

#include <Prism/Protocols/Xhttp/ConnectionTypes.hpp>
#include <Prism/Protocols/Xhttp/Entry.hpp>
