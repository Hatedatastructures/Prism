/**
 * @file form.hpp
 * @brief 传输形态枚举定义
 * @details 定义了传输层的数据传输形态，用于区分 TCP 流式传输和 UDP 数据报传输。
 * 该枚举在协议层用于标识请求的传输形态，指导 pipeline 进行正确的路由分发。
 *
 * 设计说明：
 * - stream: 可靠的有序字节流传输，对应 TCP 协议
 * - datagram: 不可靠的数据报传输，对应 UDP 协议
 *
 * 使用场景：
 * - SOCKS5 命令解析：CONNECT -> stream，UDP_ASSOCIATE -> datagram
 * - Trojan 命令解析：CONNECT -> stream，UDP_ASSOCIATE -> datagram
 * - Pipeline 路由：根据 form 选择 TCP tunnel 或 UDP relay
 *
 * @note 该枚举用于协议层，不应在传输层内部使用
 * @see ngx::protocol::socks5::request
 * @see ngx::protocol::trojan::request
 */

#pragma once

#include <cstdint>

namespace ngx::transport
{
    /**
     * @enum form
     * @brief 传输形态枚举
     * @details 标识数据传输的形态，用于协议层和 pipeline 层的路由决策。
     *
     * 形态说明：
     * - stream: TCP 流式传输，保证可靠性和顺序
     * - datagram: UDP 数据报传输，不保证可靠性
     *
     * 映射关系：
     * | 协议命令 | form 值 |
     * |---------|---------|
     * | CONNECT | stream |
     * | UDP_ASSOCIATE | datagram |
     * | BIND | stream (控制面) |
     */
    enum class form : std::uint8_t
    {
        stream,    ///< TCP 可靠流传输
        datagram   ///< UDP 数据报传输
    };
}
