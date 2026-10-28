/** @file RawIngressProbe.cpp @brief 单端口入口明文与 TLS 探测实现。 */
#include <Prism/Runtime/Recognition/RawIngressProbe.hpp>

#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <cstddef>
#include <chrono>
#include <memory>
#include <system_error>
#include <utility>

namespace Prism::Recognition
{
    auto RawIngressProbe::Run(RawIngressProbeRequest Request) -> Net::awaitable<RawIngressProbeResult>
    {
        if (!Request.Transport)
        {
            co_return Rejected(RejectedInput{
                {}, Prism::Fault::Code::InvalidArgument,
                std::make_error_code(std::errc::bad_file_descriptor)});
        }

        if (!Request.Bytes)
        {
            const auto Inbound = std::move(Request.Transport);
            if (Inbound)
            {
                (void)Inbound->Close();
            }
            co_return Rejected(RejectedInput{
                {}, Prism::Fault::Code::InvalidArgument,
                std::make_error_code(std::errc::invalid_argument)});
        }

        auto Buffer = std::make_shared<ProbeBuffer>(MaxTlsClientHelloBytes, std::move(Request.Bytes));
        if (Request.Timeout <= std::chrono::milliseconds::zero())
        {
            co_return co_await Inspect(Request.Transport, std::move(Buffer));
        }

        Net::steady_timer Timer(Request.Transport->Executor());
        Timer.expires_after(Request.Timeout);
        using Net::experimental::awaitable_operators::operator||;
        auto Race = co_await (Inspect(Request.Transport, Buffer) || Timer.async_wait(Net::use_awaitable));
        if (Race.index() == 0)
        {
            co_return std::get<0>(std::move(Race));
        }

        const auto Cancelled = Request.Transport->Cancel();
        if (!Cancelled)
        {
            const auto Failure = Cancelled.error();
            co_return Rejected(RejectedInput{{}, Failure.Code, Prism::Fault::ToNative(Failure)});
        }
        co_return Rejected(RejectedInput{
            Buffer->Replay(std::move(Request.Transport)), Prism::Fault::Code::Timeout,
            std::make_error_code(std::errc::timed_out)});
    }

    auto RawIngressProbe::Inspect(Prism::SharedTransmission Transport, std::shared_ptr<ProbeBuffer> Buffer)
        -> Net::awaitable<RawIngressProbeResult>
    {
        const auto Fill = co_await Buffer->ReadSomeWithTerminal(*Transport, 1U);
        const auto Data = Buffer->Data();
        if (Data.empty())
        {
            const auto Replayed = Buffer->Replay(Transport, Fill.Failure);
            if (!Replayed)
            {
                co_return Rejected(RejectedInput{{}, Replayed.error().Code,
                    Prism::Fault::ToNative(Replayed.error())});
            }
            co_return Rejected(RejectedInput{std::move(*Replayed),
                MapFill(Fill.Status, Fill.Failure), Prism::Fault::ToNative(Fill.Failure)});
        }

        if (std::to_integer<unsigned char>(Data.front()) != 0x16U)
        {
            const auto Replayed = Buffer->Replay(Transport, Fill.Failure);
            if (!Replayed)
            {
                co_return Rejected(RejectedInput{{}, Replayed.error().Code,
                    Prism::Fault::ToNative(Replayed.error())});
            }
            co_return RawIngressProbeResult{RawIngressKind::Cleartext, Prism::Fault::Code::Success,
                Prism::Fault::ToNative(Fill.Failure), Prism::Error::None, std::move(*Replayed), {}};
        }
        if (Fill.Status != RecognitionStatus::Accepted)
        {
            co_return Rejected(RejectedInput{
                Buffer->Replay(std::move(Transport)), MapFill(Fill.Status, Fill.Failure),
                Prism::Fault::ToNative(Fill.Failure)});
        }

        auto [Error, Features] = co_await ReadClientHello(*Transport, *Buffer);
        if (Error != Prism::Error::None)
        {
            co_return Rejected(RejectedInput{
                Buffer->Replay(std::move(Transport)),
                Prism::Fault::ToCode(Prism::make_error_code(Error)), {}, Error});
        }

        co_return RawIngressProbeResult{RawIngressKind::Tls, Prism::Fault::Code::Success, {},
            Prism::Error::None, Buffer->Replay(std::move(Transport)), std::move(Features)};
    }

    auto RawIngressProbe::Rejected(RejectedInput Input) -> RawIngressProbeResult
    {
        return RawIngressProbeResult{RawIngressKind::Rejected, Input.Code, std::move(Input.NativeError),
            Input.ProtocolError, std::move(Input.Transport), {}};
    }

    auto RawIngressProbe::MapFill(const RecognitionStatus Status,
        const Prism::Fault::Failure& Failure) noexcept -> Prism::Fault::Code
    {
        if (Status == RecognitionStatus::EndOfStream)
        {
            return Prism::Fault::Code::Eof;
        }
        if (Status == RecognitionStatus::BudgetExceeded)
        {
            return Prism::Fault::Code::ProtocolError;
        }
        if (Status == RecognitionStatus::TimedOut)
        {
            return Prism::Fault::Code::Timeout;
        }
        if (Status == RecognitionStatus::Polluted)
        {
            return Prism::Fault::Code::ProtocolError;
        }
        if (Failure.Failed())
        {
            const auto Code = Failure.Code == Prism::Fault::Code::Success
                ? Prism::Fault::ToCode(Failure.Native) : Failure.Code;
            return Code == Prism::Fault::Code::Success
                ? Prism::Fault::Code::IoError : Code;
        }
        return Prism::Fault::Code::IoError;
    }
}
