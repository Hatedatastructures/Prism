/**
 * @file TlsRecognitionHelpers.hpp
 * @brief TLS ClientHello 解析、prepare 与 carrier commit 辅助函数。
 * @details policy 与 binding Inspect 由 TlsCandidateModel 拥有；本头只处理
 *          probe 解析、prepared state 和 commit 阶段，并保留原始 inbound
 *          以便错误合同向 Runtime 传递。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <cstddef>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Composition/Recognition/TlsCandidateModel.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Runtime/Recognition/Tls.hpp>

namespace Preview::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;

    namespace detail
    {

        [[nodiscard]] inline auto SchemeName(TlsCarrier Carrier) noexcept -> std::string_view
        {
            return Preview::Composition::Protocol::ProtocolCatalog::CarrierName(Carrier);
        }

        [[nodiscard]] inline auto ParseFeatures(const Core::ProbeSnapshot &Snapshot,
                                                Core::ClientHelloFeatures &Features) -> Core::MatchState
        {
            const auto Data = Snapshot.Data();
            const auto Bytes = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Data.data()), Data.size());
            const auto [Error, Parsed] = Core::ParseClientHelloProgress(Bytes);
            if (Error == Preview::Error::NeedMore)
            {
                return Core::MatchState::NeedMore;
            }
            if (Error != Preview::Error::None)
            {
                return Core::MatchState::Rejected;
            }
            Features = Parsed;
            return Core::MatchState::Structural;
        }

        [[nodiscard]] inline auto PrepareClientHello(Core::PrepareContext Context)
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

        /**
         * @brief TLS commit 的 owning request。
         * @details CommitScheme 按值接收整个 request；typed callback、prepared state
         *          和原始 Inbound 因而都由 coroutine frame 保持。这里不借用
         *          SchemeExecutor、registry 或外层 configuration；取消、half-close
         *          与最终关闭由 carrier callback 的协议 owner 承担。
         */
        struct CommitSchemeRequest
        {
            Core::CommitContext Context;
            CarrierAcceptFn Accept;
            CarrierAcceptPreparedFn AcceptPrepared;
            std::string Scheme;
        };

        [[nodiscard]] inline auto MetadataFor(const CommitSchemeRequest &RequestData)
            -> Core::CarrierMetadata
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

        [[nodiscard]] inline auto ExecuteCarrier(CommitSchemeRequest &RequestData,
                                                 Preview::SharedTransmission Inbound)
            -> Net::awaitable<Core::CarrierAcceptResult>
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
            Result.Code = Preview::Fault::Code::NotSupported;
            Result.Transport = std::move(Inbound);
            co_return Result;
        }

        [[nodiscard]] inline auto CarrierRecognitionStatus(Preview::Fault::Code Code) noexcept
            -> Core::RecognitionStatus
        {
            if (Code == Preview::Fault::Code::Timeout)
            {
                return Core::RecognitionStatus::TimedOut;
            }
            if (Code == Preview::Fault::Code::Canceled)
            {
                return Core::RecognitionStatus::IoError;
            }
            return Core::RecognitionStatus::NoMatch;
        }

        [[nodiscard]] inline auto CarrierRecognitionError(Preview::Fault::Code Code) noexcept
            -> std::error_code
        {
            if (Code == Preview::Fault::Code::Timeout)
            {
                return std::make_error_code(std::errc::timed_out);
            }
            if (Code == Preview::Fault::Code::Canceled)
            {
                return std::make_error_code(std::errc::operation_canceled);
            }
            return std::make_error_code(std::errc::protocol_error);
        }

        [[nodiscard]] inline auto CommitScheme(CommitSchemeRequest RequestData)
            -> Net::awaitable<Core::CommitResult>
        {
            Core::CommitResult Result;
            Result.Candidate = RequestData.Context.Candidate;
            const auto Original = RequestData.Context.Inbound;
            Result.Metadata = MetadataFor(RequestData);
            if (RequestData.Context.Polluted || !Original)
            {
                Result.FaultCode = Preview::Fault::Code::IoError;
                if (RequestData.Context.Polluted)
                {
                    Result.FaultCode = Preview::Fault::Code::ProtocolError;
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
                Result.FaultCode = Preview::Fault::Code::NotSupported;
                Result.Status = Core::RecognitionStatus::NoMatch;
                Result.Error = Preview::make_error_code(Preview::Error::Unsupported);
                Result.Transport = Original;
                co_return Result;
            }
            Core::CarrierAcceptResult Accepted;
            try
            {
                Accepted = co_await ExecuteCarrier(RequestData, Original);
            }
            catch (const boost::system::system_error& Error)
            {
                Accepted.Code = Preview::Fault::Code::TlsHsfail;
                Accepted.NativeError = Error.code();
                Accepted.Transport = Original;
            }
            catch (const std::system_error& Error)
            {
                Accepted.Code = Preview::Fault::Code::TlsHsfail;
                Accepted.NativeError = boost::system::error_code(Error.code());
                Accepted.Transport = Original;
            }
            catch (...)
            {
                Accepted.Code = Preview::Fault::Code::TlsHsfail;
                Accepted.Transport = Original;
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
            if (Preview::Fault::Failed(Accepted.Code) || Accepted.NativeError || !Accepted.Transport)
            {
                if (Result.FaultCode == Preview::Fault::Code::Success)
                {
                    Result.FaultCode = Accepted.NativeError
                                           ? Preview::Fault::ToCode(Accepted.NativeError)
                                           : Preview::Fault::Code::ProtocolError;
                }
                Result.Status = CarrierRecognitionStatus(Result.FaultCode);
                Result.Error = CarrierRecognitionError(Result.FaultCode);
                if (Accepted.Transport)
                {
                    Result.Transport = std::move(Accepted.Transport);
                }
                else
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

} // namespace Preview::Composition::Recognition
