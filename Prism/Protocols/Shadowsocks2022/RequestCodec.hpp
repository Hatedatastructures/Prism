/**
 * @file RequestCodec.hpp
 * @brief Shadowsocks 2022 请求编解码兼容聚合入口。
 * @details 无状态固定/变长头 helper 由 RequestWire.hpp 拥有，增量
 *          Serializer/Parser 状态机由 RequestState.hpp 拥有；本文件
 *          保留原有 RequestCodec include 路径和公共符号。
 */

#pragma once

#include <Prism/Protocols/Shadowsocks2022/RequestState.hpp>
#include <Prism/Protocols/Shadowsocks2022/RequestWire.hpp>
