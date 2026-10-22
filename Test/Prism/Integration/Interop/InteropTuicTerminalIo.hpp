/**
 * @file InteropTuicTerminalIo.hpp
 * @brief TUIC 互操作的 stream echo 和完整响应读取契约。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <expected>
#include <limits>
#include <span>

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Testing::TuicInterop::Detail
{
    namespace Net = boost::asio;

    /** @brief 记录已交付字节以及本次操作观察到的终止状态。 */
    struct EchoCompletion final
    {
        std::size_t Bytes{0};
        Prism::Fault::Failure Terminal{};
    };

    /**
     * @brief 回写所有读取字节，直到对端写半关闭。
     * @details 同次完成携带的 bytes 始终先回写；只有 EOF 是正常半关闭，
     *          其他终止状态按原失败返回。
     */
    [[nodiscard]] inline auto EchoPeerStream(
        Prism::Transmission &Carrier,
        std::span<std::byte> Buffer)
        -> Net::awaitable<std::expected<EchoCompletion, Prism::Fault::Failure>>
    {
        std::size_t EchoedBytes = 0;
        while (true)
        {
            const auto Read = co_await Carrier.ReadSome(Buffer);
            if (Read.Bytes > Buffer.size())
            {
                co_return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::InvalidArgument, Read.Failure.Native});
            }

            std::size_t Offset = 0;
            while (Offset < Read.Bytes)
            {
                const auto Remaining = Read.Bytes - Offset;
                const auto WriteWindow = std::span<const std::byte>(Buffer).subspan(
                    Offset, Remaining);
                const auto Written = co_await Carrier.WriteSome(WriteWindow);
                if (Written.Bytes > Remaining)
                {
                    co_return std::unexpected(Prism::Fault::Failure{
                        Prism::Fault::Code::InvalidArgument, Written.Failure.Native});
                }
                Offset += Written.Bytes;
                if (Written.Failure.Failed())
                {
                    co_return std::unexpected(Written.Failure);
                }
                if (Written.Bytes == 0)
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
                }
            }

            if (Read.Bytes > (std::numeric_limits<std::size_t>::max)() - EchoedBytes)
            {
                co_return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::InvalidArgument});
            }
            EchoedBytes += Read.Bytes;
            if (Read.Failure.Failed())
            {
                if (Read.Failure.Code == Prism::Fault::Code::Eof)
                {
                    co_return EchoCompletion{EchoedBytes, Read.Failure};
                }
                co_return std::unexpected(Read.Failure);
            }
            if (Read.Bytes == 0)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
            }
        }
    }

    /**
     * @brief 读取固定长度响应，完整 payload 与同次 EOF 一起返回时仍完整交付。
     * @details partial terminal 保留原失败；没有失败的零字节完成按无进展处理。
     */
    [[nodiscard]] inline auto ReadExpectedPayload(
        Prism::Transmission &Carrier,
        std::span<std::byte> Payload)
        -> Net::awaitable<std::expected<EchoCompletion, Prism::Fault::Failure>>
    {
        std::size_t Offset = 0;
        while (Offset < Payload.size())
        {
            const auto Window = Payload.subspan(Offset);
            const auto Read = co_await Carrier.ReadSome(Window);
            if (Read.Bytes > Window.size())
            {
                co_return std::unexpected(Prism::Fault::Failure{
                    Prism::Fault::Code::InvalidArgument, Read.Failure.Native});
            }
            Offset += Read.Bytes;
            if (Read.Failure.Failed())
            {
                if (Read.Failure.Code == Prism::Fault::Code::Eof &&
                    Offset == Payload.size())
                {
                    co_return EchoCompletion{Offset, Read.Failure};
                }
                co_return std::unexpected(Read.Failure);
            }
            if (Read.Bytes == 0)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
            }
        }
        co_return EchoCompletion{Offset, {}};
    }
}
