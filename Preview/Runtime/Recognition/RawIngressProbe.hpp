/**
 * @file RawIngressProbe.hpp
 * @brief 单端口入口的明文/TLS ClientHello 探测结果。
 */
#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <system_error>
#include <utility>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Runtime/Recognition/Tls.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Recognition
{

    namespace Net = boost::asio;

    enum class RawIngressKind : std::uint8_t
    {
        Cleartext,
        Tls,
        Rejected,
    };

    struct RawIngressProbeRequest final
    {
        Preview::SharedTransmission Transport;
        std::chrono::milliseconds Timeout{5000};
    };

    struct RawIngressProbeResult final
    {
        RawIngressKind Kind{RawIngressKind::Rejected};
        Preview::Fault::Code Code{Preview::Fault::Code::NotSupported};
        std::error_code NativeError{};
        Preview::Error ProtocolError{Preview::Error::None};
        Preview::SharedTransmission Transport{};
        ClientHelloFeatures ClientHello{};
    };

    class RawIngressProbe final
    {
    public:
        [[nodiscard]] static auto Run(RawIngressProbeRequest Request)
            -> Net::awaitable<RawIngressProbeResult>
        {
            if (!Request.Transport)
            {
                co_return Rejected({}, Preview::Fault::Code::InvalidArgument,
                                   std::make_error_code(std::errc::bad_file_descriptor));
            }

            auto Buffer = std::make_shared<ProbeBuffer>(MaxTlsClientHelloBytes);
            if (Request.Timeout <= std::chrono::milliseconds::zero())
            {
                co_return co_await Inspect(Request.Transport, std::move(Buffer));
            }

            Net::steady_timer Timer(Request.Transport->Executor());
            Timer.expires_after(Request.Timeout);
            using Net::experimental::awaitable_operators::operator||;
            auto Race = co_await (
                Inspect(Request.Transport, Buffer) || Timer.async_wait(Net::use_awaitable));
            if (Race.index() == 0)
            {
                co_return std::get<0>(std::move(Race));
            }

            Request.Transport->Cancel();
            co_return Rejected(
                Buffer->Replay(std::move(Request.Transport)),
                Preview::Fault::Code::Timeout,
                std::make_error_code(std::errc::timed_out));
        }

    private:
        [[nodiscard]] static auto Inspect(
            Preview::SharedTransmission Transport,
            std::shared_ptr<ProbeBuffer> Buffer) -> Net::awaitable<RawIngressProbeResult>
        {
            const auto Fill = co_await Buffer->ReadSome(*Transport, 1U);
            const auto Data = Buffer->Data();
            if (Data.empty())
            {
                co_return Rejected(Transport, MapFill(Fill.Status, Fill.Error), Fill.Error);
            }

            if (std::to_integer<unsigned char>(Data.front()) != 0x16U)
            {
                co_return RawIngressProbeResult{
                    RawIngressKind::Cleartext,
                    Preview::Fault::Code::Success,
                    Fill.Error,
                    Preview::Error::None,
                    Buffer->Replay(std::move(Transport)),
                    {}};
            }
            if (Fill.Status != RecognitionStatus::Accepted)
            {
                co_return Rejected(Buffer->Replay(std::move(Transport)),
                                   MapFill(Fill.Status, Fill.Error), Fill.Error);
            }

            auto [Error, Features] = co_await ReadClientHello(*Transport, *Buffer);
            if (Error != Preview::Error::None)
            {
                co_return Rejected(Buffer->Replay(std::move(Transport)),
                                   Preview::Fault::ToCode(Preview::make_error_code(Error)),
                                   {}, Error);
            }

            co_return RawIngressProbeResult{
                RawIngressKind::Tls,
                Preview::Fault::Code::Success,
                {},
                Preview::Error::None,
                Buffer->Replay(std::move(Transport)),
                std::move(Features)};
        }

        [[nodiscard]] static auto Rejected(
            Preview::SharedTransmission Transport,
            const Preview::Fault::Code Code,
            std::error_code NativeError,
            const Preview::Error ProtocolError = Preview::Error::None) -> RawIngressProbeResult
        {
            return RawIngressProbeResult{
                RawIngressKind::Rejected,
                Code,
                std::move(NativeError),
                ProtocolError,
                std::move(Transport),
                {}};
        }

        [[nodiscard]] static auto MapFill(
            const RecognitionStatus Status,
            const std::error_code &Error) noexcept -> Preview::Fault::Code
        {
            if (Status == RecognitionStatus::EndOfStream)
            {
                return Preview::Fault::Code::Eof;
            }
            if (Status == RecognitionStatus::BudgetExceeded)
            {
                return Preview::Fault::Code::ProtocolError;
            }
            if (Status == RecognitionStatus::TimedOut)
            {
                return Preview::Fault::Code::Timeout;
            }
            if (Status == RecognitionStatus::Polluted)
            {
                return Preview::Fault::Code::ProtocolError;
            }
            if (Error)
            {
                const auto Code = Preview::Fault::ToCode(Error);
                return Code == Preview::Fault::Code::Success
                           ? Preview::Fault::Code::IoError
                           : Code;
            }
            return Preview::Fault::Code::IoError;
        }
    };

} // namespace Preview::Recognition
