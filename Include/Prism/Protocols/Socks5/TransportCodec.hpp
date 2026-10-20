/**
 * @file TransportCodec.hpp
 * @brief SOCKS5 消息与 Transmission 的异步组合操作
 * @details 该头拥有 partial read/write 的驱动循环；取消、关闭和底层
 *          所有权仍由 SharedTransmission/具体传输实现负责。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <system_error>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Socks5/BeastCodec.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Socks5
{

    namespace Net = boost::asio;

    /**
     * @brief 异步读取并解析一条消息
     * @param Transport 底层传输，共享所有权
     * @param ParserValue 已设置 Expect 的增量解析器
     * @return 解析结果；半帧由内部循环等待，EOF 返回 UnexpectedEof
     */
    [[nodiscard]] auto AsyncRead(
        SharedTransmission Transport,
        Parser &ParserValue) -> Net::awaitable<Error>;

    /**
     * @brief 异步发送一条消息
     * @param Transport 底层传输，共享所有权
     * @param SerializerValue 已 Reset 的增量序列化器
     * @return 写入结果；短写循环直到消息完成
     */
    [[nodiscard]] auto AsyncWrite(
        SharedTransmission Transport,
        Serializer &SerializerValue) -> Net::awaitable<Error>;

} // namespace Prism::Socks5
