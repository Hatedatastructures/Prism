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

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Socks5/BeastCodec.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Socks5
{

    namespace Net = boost::asio;

    /**
     * @brief 异步读取并解析一条消息
     * @param Transport 底层传输，共享所有权
     * @param ParserValue 已设置 Expect 的增量解析器
     * @return 解析结果；半帧由内部循环等待，EOF 返回 UnexpectedEof
     */
    [[nodiscard]] inline auto AsyncRead(
        SharedTransmission Transport,
        Parser &ParserValue) -> Net::awaitable<Error>
    {
        std::array<std::uint8_t, 512> Buffer{};
        while (!ParserValue.IsDone())
        {
            auto ByteBuffer = AsBytes(std::span<std::uint8_t>(Buffer));
            const auto Part = co_await Transport->ReadSome(ByteBuffer);
            if (Part.Failure.Failed())
            {
                co_return Error::IoError;
            }
            if (Part.Bytes == 0)
            {
                co_return Error::UnexpectedEof;
            }
            if (Part.Bytes > Buffer.size())
            {
                co_return Error::IoError;
            }
            std::error_code ParseError;
            ParserValue.Put(Net::buffer(Buffer.data(), Part.Bytes), ParseError);
            if (ParseError)
            {
                co_return static_cast<Error>(ParseError.value());
            }
        }
        co_return Error::None;
    }

    /**
     * @brief 异步发送一条消息
     * @param Transport 底层传输，共享所有权
     * @param SerializerValue 已 Reset 的增量序列化器
     * @return 写入结果；短写循环直到消息完成
     */
    [[nodiscard]] inline auto AsyncWrite(
        SharedTransmission Transport,
        Serializer &SerializerValue) -> Net::awaitable<Error>
    {
        std::array<std::uint8_t, 512> Buffer{};
        while (!SerializerValue.IsDone())
        {
            std::error_code ErrorCode;
            const auto N = SerializerValue.Get(
                Net::buffer(Buffer.data(), Buffer.size()), ErrorCode);
            if (ErrorCode)
            {
                co_return Error::IoError;
            }
            if (N == 0)
            {
                co_return Error::BadLength;
            }
            std::size_t Done = 0;
            while (Done < N)
            {
                auto View = AsBytes(
                    std::span<const std::uint8_t>(Buffer.data() + Done, N - Done));
                const auto Part = co_await Transport->WriteSome(View);
                if (Part.Failure.Failed())
                {
                    co_return Error::IoError;
                }
                if (Part.Bytes == 0 || Part.Bytes > N - Done)
                {
                    co_return Error::BrokenPipe;
                }
                Done += Part.Bytes;
            }
        }
        co_return Error::None;
    }

} // namespace Preview::Socks5
