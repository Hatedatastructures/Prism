/** @file DohResponse.hpp @brief DoH 响应分块读取与 HTTP framing。 */
#pragma once

#include "TlsTransport.hpp"

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Utility/Http/ForwardResponseFraming.hpp>
#include <Prism/Net/Dns/AttemptDeadline.hpp>
#include <Prism/Net/Dns/Transport.hpp>

#include <boost/asio/error.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <vector>

namespace Prism::Network::Dns::Detail
{
    /** @brief 完整 HTTP 响应后到达的连接终态可退休连接；取消/超时始终失败。 */
    [[nodiscard]] inline auto IsDohCancellationOrTimeout(
        const boost::system::error_code &ErrorCode) noexcept -> bool
    {
        if (ErrorCode == Net::error::operation_aborted ||
            ErrorCode == Net::error::timed_out ||
            ErrorCode == Prism::make_error_code(Prism::Error::Canceled) ||
            ErrorCode == Prism::make_error_code(Prism::Error::Timeout))
        {
            return true;
        }
        const auto Condition = ErrorCode.default_error_condition();
        return Condition == boost::system::errc::make_error_condition(
                               boost::system::errc::operation_canceled) ||
               Condition == boost::system::errc::make_error_condition(
                               boost::system::errc::timed_out);
    }

    /** @brief 逐块读取并校验一个 DoH HTTP 响应。 */
    [[nodiscard]] inline auto ValidDohResponseHeaders(
        const Prism::Http11::ForwardResponseFraming &Framing) -> bool
    {
        constexpr std::size_t MaxBodyBytes = 65536U;
        const auto &Fields = Framing.ResponseFields();
        const bool HasSingleLength = Fields.HasContentLength &&
            !Fields.HasTransferEncoding && Fields.ContentLengthFieldCount == 1U &&
            Fields.ContentLength > 0U && Fields.ContentLength <= MaxBodyBytes;
        const bool HasSingleChunked = Fields.HasTransferEncoding &&
            !Fields.HasContentLength && Fields.TransferCodingCount == 1U &&
            Fields.FinalTransferCodingChunked;
        return Framing.StatusCode() == 200 &&
            (HasSingleLength || HasSingleChunked) &&
            Fields.ContentTypeFieldCount == 1U &&
            Fields.ContentTypeIs("application/dns-message");
    }

    /**
     * @brief 消费 TLS 读取字节后再处理同次完成的终态。
     * @tparam Owner 持有 TlsReadResult 接口的共享 DoH 状态 owner
     * @param OwnerValue owner 保活到响应 framing 与终态处理完成
     * @param Deadline 本次 DoH 尝试共享的绝对 deadline
     * @return 完整 DNS body，或 framing/原始传输终态
     * @details 完整响应与普通远端终态同次到达时返回完整 body 并关闭链路；
     *          取消/超时仍失败，未完成响应保留原终态，所有终态都关闭链路。
     */
    template <typename Owner>
    [[nodiscard]] inline auto ReceiveDohResponse(
        std::shared_ptr<Owner> OwnerValue,
        const AttemptDeadline Deadline)
        -> Net::awaitable<EcResult<std::vector<std::uint8_t>>>
    {
        constexpr std::size_t MaxHeaderBytes = 65536U;
        constexpr std::size_t MaxBodyBytes = 65536U;
        constexpr std::size_t MaxFramingBytes = 65536U;
        Prism::Http11::ForwardResponseFraming Framing({
            .CaptureBody = true,
            .MaxHeaderBytes = MaxHeaderBytes,
            .MaxDecodedBodyBytes = MaxBodyBytes,
            .MaxFramingBytes = MaxFramingBytes,
        });

        while (!Framing.IsComplete())
        {
            std::array<std::uint8_t, 2048> Buffer{};
            const auto Read = co_await OwnerValue->Tls.ReadSome(
                std::span<std::uint8_t>(Buffer.data(), Buffer.size()), Deadline);
            if (Read.Bytes > Buffer.size())
            {
                OwnerValue->Tls.Close();
                co_return std::unexpected(
                    Prism::make_error_code(Prism::Error::BadMessage));
            }
            if (Read.Bytes == 0U)
            {
                OwnerValue->Tls.Close();
                if (Read.Failure)
                {
                    co_return std::unexpected(Read.Failure);
                }
                co_return std::unexpected(
                    Prism::make_error_code(Prism::Error::UnexpectedEof));
            }

            const auto Input = std::as_bytes(std::span(Buffer.data(), Read.Bytes));
            const auto Framed = Framing.Consume(Input);
            if (Framed.ErrorCode != Prism::Error::None)
            {
                OwnerValue->Tls.Close();
                co_return std::unexpected(
                    Prism::make_error_code(Framed.ErrorCode));
            }
            if (Framed.Accepted != Input.size())
            {
                OwnerValue->Tls.Close();
                co_return std::unexpected(
                    Prism::make_error_code(Prism::Error::BadMessage));
            }
            if (Framing.HasFinalResponseHeaders() && !ValidDohResponseHeaders(Framing))
            {
                OwnerValue->Tls.Close();
                co_return std::unexpected(
                    Prism::make_error_code(Prism::Error::BadMessage));
            }
            if (Read.Failure)
            {
                OwnerValue->Tls.Close();
                if (!Framing.IsComplete() || IsDohCancellationOrTimeout(Read.Failure))
                {
                    co_return std::unexpected(Read.Failure);
                }
            }
        }
        co_return Framing.TakeDecodedBody();
    }
} // namespace Prism::Network::Dns::Detail
