/** @file TlsRecognitionHelpers.cpp @brief TLS probe prepare 与 carrier commit 实现。 */

#include <Prism/Composition/Recognition/TlsRecognitionHelpers.hpp>

#include <boost/system/system_error.hpp>
#include <boost/asio/this_coro.hpp>

#include <cstdint>
#include <memory>
#include <span>
#include <system_error>
#include <utility>

namespace Prism::Composition::Recognition
{
    namespace detail
    {

        auto SchemeName(const TlsCarrier Carrier) noexcept -> std::string_view
        {
            return Prism::Composition::Protocol::ProtocolCatalog::CarrierName(Carrier);
        }

        auto ParseFeatures(const Core::ProbeSnapshot& Snapshot,
            Core::ClientHelloFeatures& Features) -> Core::MatchState
        {
            const auto Data = Snapshot.Data();
            const auto Bytes = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(Data.data()), Data.size());
            const auto [Error, Parsed] = Core::ParseClientHelloProgress(Bytes);
            if (Error == Prism::Error::NeedMore)
            {
                return Core::MatchState::NeedMore;
            }
            if (Error != Prism::Error::None)
            {
                return Core::MatchState::Rejected;
            }
            Features = Parsed;
            return Core::MatchState::Structural;
        }

        auto PrepareClientHello(Core::PrepareContext Context)
            -> Net::awaitable<Core::PrepareResult>
        {
            Core::PrepareResult Result;
            Result.Candidate = Context.Candidate;
            Core::ClientHelloFeatures Features;
            const auto Match = ParseFeatures(Context.Snapshot, Features);
            if (Match != Core::MatchState::Structural)
            {
                Result.Status = Core::RecognitionStatus::NoMatch;
                Result.NeedMore = Match == Core::MatchState::NeedMore;
                co_return Result;
            }
            Result.Status = Core::RecognitionStatus::Accepted;
            Result.PreparedState = std::make_shared<const Core::ClientHelloFeatures>(
                std::move(Features));
            co_return Result;
        }

        auto MetadataFor(const CommitSchemeRequest& RequestData) -> Core::CarrierMetadata
        {
            Core::CarrierMetadata Metadata;
            Metadata.Carrier = RequestData.Scheme;
            if (RequestData.Context.PreparedState)
            {
                const auto Features = std::static_pointer_cast<const Core::ClientHelloFeatures>(
                    RequestData.Context.PreparedState);
                Metadata.Sni = Features->ServerName;
            }
            return Metadata;
        }

        auto ExecuteCarrier(CommitSchemeRequest& RequestData,
            Prism::SharedTransmission Inbound) -> Net::awaitable<Core::CarrierAcceptResult>
        {
            if (RequestData.AcceptPrepared)
            {
                co_return co_await RequestData.AcceptPrepared(Core::CarrierAcceptPreparedInput{
                    std::move(Inbound), RequestData.Context.PreparedState, RequestData.Context.Bytes,
                    RequestData.Context.Trace});
            }
            if (RequestData.Accept)
            {
                co_return co_await RequestData.Accept(Core::CarrierAcceptInput{
                    std::move(Inbound), RequestData.Context.Bytes, RequestData.Context.Trace});
            }
            Core::CarrierAcceptResult Result;
            Result.Metadata.Carrier = RequestData.Scheme;
            Result.Code = Prism::Fault::Code::NotSupported;
            Result.Transport = std::move(Inbound);
            co_return Result;
        }

        auto CarrierRecognitionStatus(const Prism::Fault::Code Code) noexcept
            -> Core::RecognitionStatus
        {
            if (Code == Prism::Fault::Code::Timeout)
            {
                return Core::RecognitionStatus::TimedOut;
            }
            if (Code == Prism::Fault::Code::Canceled)
            {
                return Core::RecognitionStatus::IoError;
            }
            return Core::RecognitionStatus::NoMatch;
        }

        auto CarrierRecognitionError(const Prism::Fault::Code Code) noexcept -> std::error_code
        {
            if (Code == Prism::Fault::Code::Timeout)
            {
                return std::make_error_code(std::errc::timed_out);
            }
            if (Code == Prism::Fault::Code::Canceled)
            {
                return std::make_error_code(std::errc::operation_canceled);
            }
            return std::make_error_code(std::errc::protocol_error);
        }

        auto CloseAndDrainOriginal(Prism::SharedTransmission Inbound)
            -> Net::awaitable<Prism::Fault::Failure>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());

            const auto Closed = Inbound->Close();
            if (!Closed)
            {
                co_return Closed.error();
            }
            const auto Drained = co_await Inbound->Activity()->Drain();
            if (!Drained)
            {
                co_return Drained.error();
            }
            co_return Prism::Fault::Failure{};
        }

        auto CommitScheme(CommitSchemeRequest RequestData)
            -> Net::awaitable<Core::CommitResult>
        {
            Core::CommitResult Result;
            Result.Candidate = RequestData.Context.Candidate;
            const auto Original = RequestData.Context.Inbound;
            Result.Metadata = MetadataFor(RequestData);
            if (RequestData.Context.Polluted || !Original)
            {
                Result.FaultCode = Prism::Fault::Code::IoError;
                if (RequestData.Context.Polluted)
                {
                    Result.FaultCode = Prism::Fault::Code::ProtocolError;
                }
                if (RequestData.Context.Polluted)
                {
                    Result.Status = Core::RecognitionStatus::Polluted;
                }
                else
                {
                    Result.Status = Core::RecognitionStatus::IoError;
                }
                Result.Error = std::make_error_code(std::errc::operation_not_permitted);
                Result.Polluted = RequestData.Context.Polluted;
                Result.Transport = Original;
                co_return Result;
            }
            if (!RequestData.Accept && !RequestData.AcceptPrepared)
            {
                Result.FaultCode = Prism::Fault::Code::NotSupported;
                Result.Status = Core::RecognitionStatus::NoMatch;
                Result.Error = Prism::make_error_code(Prism::Error::Unsupported);
                Result.Transport = Original;
                co_return Result;
            }
            Core::CarrierAcceptResult Accepted;
            bool SchemeThrew = false;
            Prism::Fault::Failure CloseFailure;
            try
            {
                Accepted = co_await ExecuteCarrier(RequestData, Original);
            }
            catch (const boost::system::system_error& Error)
            {
                SchemeThrew = true;
                Accepted.Code = Prism::Fault::Code::TlsHsfail;
                Accepted.NativeError = static_cast<std::error_code>(Error.code());
            }
            catch (const std::system_error& Error)
            {
                SchemeThrew = true;
                Accepted.Code = Prism::Fault::Code::TlsHsfail;
                Accepted.NativeError = Error.code();
            }
            catch (...)
            {
                SchemeThrew = true;
                Accepted.Code = Prism::Fault::Code::TlsHsfail;
            }
            if (SchemeThrew)
            {
                CloseFailure = co_await CloseAndDrainOriginal(Original);
                Accepted.Transport.reset();
            }
            if (Accepted.Metadata.Carrier.empty())
            {
                Accepted.Metadata.Carrier = Result.Metadata.Carrier;
            }
            if (Accepted.Metadata.Sni.empty() && !Accepted.Metadata.EchAccepted)
            {
                Accepted.Metadata.Sni = Result.Metadata.Sni;
            }
            if (Accepted.Metadata.Alpn.empty())
            {
                Accepted.Metadata.Alpn = Result.Metadata.Alpn;
            }
            Result.Metadata = std::move(Accepted.Metadata);
            Result.FaultCode = Accepted.Code;
            Result.NativeError = Accepted.NativeError;
            if (Prism::Fault::Failed(Accepted.Code) || Accepted.NativeError || !Accepted.Transport)
            {
                if (Result.FaultCode == Prism::Fault::Code::Success)
                {
                    Result.FaultCode = Accepted.NativeError
                        ? Prism::Fault::ToCode(Accepted.NativeError)
                        : Prism::Fault::Code::ProtocolError;
                }
                Result.Status = CarrierRecognitionStatus(Result.FaultCode);
                Result.Error = CarrierRecognitionError(Result.FaultCode);
                if (CloseFailure.Failed())
                {
                    Result.Error = Prism::Fault::ToNative(CloseFailure);
                }
                if (Accepted.Transport)
                {
                    Result.Transport = std::move(Accepted.Transport);
                }
                else if (!SchemeThrew)
                {
                    Result.Transport = Original;
                }
                co_return Result;
            }
            Result.Status = Core::RecognitionStatus::Accepted;
            Result.Transport = std::move(Accepted.Transport);
            co_return Result;
        }

    } // namespace detail

} // namespace Prism::Composition::Recognition
