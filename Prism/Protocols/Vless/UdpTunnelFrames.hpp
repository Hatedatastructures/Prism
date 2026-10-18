/** @file UdpTunnelFrames.hpp @brief VLESS 普通 UDP 的长度帧流读写 owner。 */
#pragma once

#include <Prism/Protocols/Vless/Types.hpp>
#include <Prism/Protocols/Vless/UdpCodec.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Vless
{
    namespace Net = boost::asio;

    /** @brief 只读写普通 VLESS UDP `[uint16BE length][payload]` 的流帧 owner。 */
    class UdpTunnelFrames final
    {
    public:
        UdpTunnelFrames(std::shared_ptr<Conn<>> Stream, std::chrono::milliseconds Timeout)
            : Stream_(std::move(Stream)), Timeout_(Timeout), Timer_(Stream_->Executor()) {}

        /** @brief 读取且校验完整帧；返回值拥有帧字节，空载荷合法。 */
        [[nodiscard]] auto Read() -> Net::awaitable<std::expected<std::vector<std::uint8_t>, UdpFailure>>
        {
            std::array<std::byte, 2> Header{};
            const auto HeaderResult = co_await ReadExact(Header);
            if (!HeaderResult)
            {
                auto Failure = HeaderResult.error();
                if (Failure.Cause.Code == Prism::Fault::Code::Eof &&
                    Failure.Transferred != 0U)
                    Failure.Cause.Code = Prism::Fault::Code::BadMessage;
                co_return std::unexpected(std::move(Failure));
            }

            const auto Length =
                (static_cast<std::size_t>(std::to_integer<std::uint8_t>(Header[0])) << 8U) |
                std::to_integer<std::uint8_t>(Header[1]);
            std::vector<std::uint8_t> Frame(Length + Header.size());
            Frame[0] = std::to_integer<std::uint8_t>(Header[0]);
            Frame[1] = std::to_integer<std::uint8_t>(Header[1]);
            if (Length != 0U)
            {
                auto* Payload = reinterpret_cast<std::byte*>(Frame.data() + Header.size());
                const auto PayloadResult = co_await ReadExact(std::span<std::byte>(Payload, Length));
                if (!PayloadResult)
                {
                    auto Failure = PayloadResult.error();
                    if (Failure.Cause.Code == Prism::Fault::Code::Eof)
                        Failure.Cause.Code = Prism::Fault::Code::BadMessage;
                    co_return std::unexpected(std::move(Failure));
                }
            }
            co_return Frame;
        }

        /** @brief 完整写出单条长度帧；保留传输 Failure 的 native cause。 */
        [[nodiscard]] auto Write(std::span<const std::uint8_t> Frame)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            std::size_t Transferred = 0;
            while (Transferred < Frame.size())
            {
                const auto Remaining = Frame.size() - Transferred;
                const auto Result = co_await Stream_->WriteSome(
                    std::as_bytes(Frame.subspan(Transferred)));
                if (Result.Bytes > Remaining)
                    co_return std::unexpected(Prism::Fault::Failure{
                        Prism::Fault::Code::InvalidArgument, Result.Failure.Native});
                Transferred += Result.Bytes;
                if (Result.Failure.Failed())
                    co_return std::unexpected(Result.Failure);
                if (Result.Bytes == 0U)
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

    private:
        [[nodiscard]] auto ReadExact(std::span<std::byte> Buffer)
            -> Net::awaitable<UdpResult>
        {
            if (Timeout_.count() <= 0)
            {
                const auto Result = co_await ReadCarrierExact(Buffer);
                co_return Project(Result, Buffer.size());
            }

            using Net::experimental::awaitable_operators::operator||;
            Timer_.expires_after(Timeout_);
            boost::system::error_code TimerError;
            auto Read = ReadCarrierExact(Buffer);
            auto Timeout = Timer_.async_wait(
                Net::redirect_error(Net::use_awaitable, TimerError));
            const auto Result = co_await (std::move(Read) || std::move(Timeout));
            if (Result.index() == 1U)
                co_return std::unexpected(UdpFailure{
                    {Prism::Fault::Code::Timeout}, 0U});
            Timer_.cancel();
            co_return Project(std::get<0>(std::move(Result)), Buffer.size());
        }

        /** @brief 显式选择 Transmission byte-span 前门，保留完整 IoResult。 */
        [[nodiscard]] auto ReadCarrierExact(std::span<std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            auto &Carrier = static_cast<Prism::Transmission &>(*Stream_);
            co_return co_await Carrier.ReadExact(Buffer);
        }

        [[nodiscard]] static auto Project(const Prism::IoResult Result,
                                          const std::size_t Expected) -> UdpResult
        {
            if (Result.Bytes > Expected)
                return std::unexpected(UdpFailure{
                    {Prism::Fault::Code::InvalidArgument, Result.Failure.Native}, 0U});
            if (Result.Failure.Failed())
                return std::unexpected(UdpFailure{Result.Failure, Result.Bytes});
            if (Result.Bytes != Expected)
                return std::unexpected(UdpFailure{
                    {Prism::Fault::Code::BadMessage}, Result.Bytes});
            return {};
        }

        std::shared_ptr<Conn<>> Stream_;
        std::chrono::milliseconds Timeout_;
        Net::steady_timer Timer_;
    };
} // namespace Prism::Vless
