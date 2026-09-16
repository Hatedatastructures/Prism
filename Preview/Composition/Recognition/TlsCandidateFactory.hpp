/**
 * @file TlsCandidateFactory.hpp
 * @brief TLS carrier 候选与 scheme executor 适配
 * @details 只在候选提交阶段调用已注册的 Preview scheme executor；
 *          ClientHello 的 SNI/ALPN 检查保持纯函数，不启动握手或写入传输。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Protocols/Shadowtls/Server.hpp>
#include <Preview/Runtime/Recognition/Profile.hpp>
#include <Preview/Runtime/Recognition/SchemeExecutor.hpp>
#include <Preview/Runtime/Recognition/Tls.hpp>

namespace Preview::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;

    /// 具体 carrier 的服务端接入回调
    using CarrierAcceptFn = std::function<Net::awaitable<Core::CarrierAcceptResult>(
        Preview::SharedTransmission)>;

    /**
     * @brief 创建 ShadowTLS v3 服务端 carrier 接入回调
     * @param Options relay 目标拨号选项
     * @param Config ShadowTLS 认证配置
     * @return 可长期捕获的服务端接入回调
     * @details 回调按值持有 relay session 与配置；失败返回 typed fault，成功返回
     *          已完成首包认证和 record 状态接管的 Conn。
     */
    [[nodiscard]] inline auto MakeShadowtlsServerAccept(Preview::Shadowtls::ServerOptions Options,
                                                        Preview::Shadowtls::ServerConfig Config)
        -> CarrierAcceptFn
    {
        auto Session = std::make_shared<Preview::Shadowtls::ServerSession>(std::move(Options));
        return [Session, Config = std::move(Config)](Preview::SharedTransmission Inbound)
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            auto ServerResult = co_await Session->Run(std::move(Inbound), Config);
            Core::CarrierAcceptResult Result;
            Result.Metadata.Carrier = "shadowtls";
            if (ServerResult.Status != Preview::Error::None || !ServerResult.Connection)
            {
                Result.Code = ServerResult.Status == Preview::Error::None
                                  ? Preview::Fault::Code::ProtocolError
                                  : Preview::Fault::ToCode(Preview::make_error_code(ServerResult.Status));
                co_return Result;
            }
            Result.Transport = std::move(ServerResult.Connection);
            co_return Result;
        };
    }

    /**
     * @enum TlsCarrier
     * @brief 已有 Preview TLS carrier 方案名
     */
    enum class TlsCarrier : std::uint8_t
    {
        Native,
        Reality,
        Shadowtls,
        Restls,
        Ws,
        Xhttp,
        Gun,
    };

    /**
     * @struct TlsCandidateOptions
     * @brief TLS carrier 候选筛选与提交参数
     */
    struct TlsCandidateOptions
    {
        Core::CandidateId Id{Core::InvalidCandidate};
        std::string Name;
        std::string Scheme;
        std::vector<std::string> ServerNames;
        std::vector<std::string> Alpn;
        bool Fallback{false};
        TlsCarrier Carrier{TlsCarrier::Native};
    };

    /**
     * @struct TlsCandidateBinding
     * @brief TLS carrier Runtime 候选
     */
    struct TlsCandidateBinding
    {
        Core::CandidateSpec Spec;
        std::string Scheme;
        std::vector<std::string> ServerNames;
        std::vector<std::string> Alpn;
        bool Fallback{false};

        [[nodiscard]] auto Inspect(const Core::ClientHelloFeatures &Features) const -> Core::MatchState;
    };

    namespace detail
    {

        [[nodiscard]] inline auto SchemeName(TlsCarrier Carrier) noexcept -> std::string_view
        {
            switch (Carrier)
            {
            case TlsCarrier::Native: return "native";
            case TlsCarrier::Reality: return "reality";
            case TlsCarrier::Shadowtls: return "shadowtls";
            case TlsCarrier::Restls: return "restls";
            case TlsCarrier::Ws: return "ws";
            case TlsCarrier::Xhttp: return "xhttp";
            case TlsCarrier::Gun: return "gun";
            }
            return {};
        }

        [[nodiscard]] inline auto Normalize(std::string_view Value) -> std::string
        {
            std::string Result;
            Result.reserve(Value.size());
            for (const auto Character : Value)
            {
                const auto Byte = static_cast<unsigned char>(Character);
                unsigned char Lower = Byte;
                if (Byte >= 'A' && Byte <= 'Z')
                {
                    Lower = static_cast<unsigned char>(Byte + ('a' - 'A'));
                }
                Result.push_back(static_cast<char>(Lower));
            }
            while (!Result.empty() && Result.back() == '.')
            {
                Result.pop_back();
            }
            return Result;
        }

        [[nodiscard]] inline auto MatchesServerName(std::string_view ServerName,
                                                    const std::vector<std::string> &Patterns) -> bool
        {
            const auto Normalized = Normalize(ServerName);
            if (Normalized.empty())
            {
                return false;
            }
            for (const auto &RawPattern : Patterns)
            {
                const auto Pattern = Normalize(RawPattern);
                if (Pattern == Normalized)
                {
                    return true;
                }
                if (Pattern.starts_with("*.") && Normalized.ends_with(Pattern.substr(1)))
                {
                    const auto Prefix = std::string_view(Normalized).substr(
                        0, Normalized.size() - Pattern.size() + 1);
                    if (!Prefix.empty() && Prefix.find('.') == std::string_view::npos)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        [[nodiscard]] inline auto MatchesAlpn(const std::vector<std::string> &Offered,
                                              const std::vector<std::string> &Expected) -> bool
        {
            if (Expected.empty())
            {
                return true;
            }
            return std::any_of(Expected.begin(), Expected.end(), [&Offered](const auto &Need)
                               { return std::find(Offered.begin(), Offered.end(), Need) != Offered.end(); });
        }

        [[nodiscard]] inline auto InspectFeatures(const Core::ClientHelloFeatures &Features,
                                                  const std::vector<std::string> &ServerNames,
                                                  const std::vector<std::string> &Alpn,
                                                  bool Fallback) -> Core::MatchState
        {
            // 当前 Preview 没有 ECH inner ClientHello 解密能力，不能把 outer SNI
            // 当作真实路由输入；显式 fallback 也不能绕过这一安全边界。
            if (Features.HasEch)
            {
                return Core::MatchState::Rejected;
            }
            if (Fallback)
            {
                return Core::MatchState::Structural;
            }
            if (!MatchesServerName(Features.ServerName, ServerNames) ||
                !MatchesAlpn(Features.AlpnProtocols, Alpn))
            {
                return Core::MatchState::Rejected;
            }
            return Core::MatchState::Structural;
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

        struct CommitSchemeRequest
        {
            Core::CommitContext Context;
            Preview::Recognition::SchemeExecutor *Executor{nullptr};
            CarrierAcceptFn Accept;
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
            if (RequestData.Accept)
            {
                co_return co_await RequestData.Accept(std::move(Inbound));
            }
            Core::CarrierAcceptResult Result;
            Result.Metadata.Carrier = RequestData.Scheme;
            Result.Transport = co_await RequestData.Executor->Execute(
                RequestData.Scheme, std::move(Inbound));
            if (!Result.Transport)
            {
                Result.Code = Preview::Fault::Code::TlsHsfail;
            }
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
                Result.FaultCode = RequestData.Context.Polluted
                                       ? Preview::Fault::Code::ProtocolError
                                       : Preview::Fault::Code::IoError;
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
            if (!RequestData.Accept &&
                (!RequestData.Executor || RequestData.Scheme.empty() ||
                 !RequestData.Executor->Has(RequestData.Scheme)))
            {
                Result.FaultCode = Preview::Fault::Code::NotSupported;
                Result.Status = Core::RecognitionStatus::NoMatch;
                Result.Error = Preview::make_error_code(Preview::Error::NotSupported);
                Result.Transport = Original;
                co_return Result;
            }
            Core::CarrierAcceptResult Accepted;
            try
            {
                Accepted = co_await ExecuteCarrier(RequestData, Original);
            }
            catch (...)
            {
                Result.FaultCode = Preview::Fault::Code::TlsHsfail;
                Result.Status = Core::RecognitionStatus::NoMatch;
                Result.Error = CarrierRecognitionError(Result.FaultCode);
                Result.Transport = Original;
                co_return Result;
            }
            if (Accepted.Metadata.Carrier.empty())
            {
                Accepted.Metadata.Carrier = Result.Metadata.Carrier;
            }
            if (Accepted.Metadata.Sni.empty())
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
            if (Preview::Fault::Failed(Accepted.Code) || !Accepted.Transport)
            {
                if (Result.FaultCode == Preview::Fault::Code::Success)
                {
                    Result.FaultCode = Preview::Fault::Code::TlsHsfail;
                }
                Result.Status = CarrierRecognitionStatus(Result.FaultCode);
                Result.Error = CarrierRecognitionError(Result.FaultCode);
                Result.Transport = Accepted.Transport ? std::move(Accepted.Transport) : Original;
                co_return Result;
            }
            Result.Status = Core::RecognitionStatus::Accepted;
            Result.Transport = std::move(Accepted.Transport);
            co_return Result;
        }

    } // namespace detail

    inline auto TlsCandidateBinding::Inspect(const Core::ClientHelloFeatures &Features) const
        -> Core::MatchState
    {
        return detail::InspectFeatures(Features, ServerNames, Alpn, Fallback);
    }

    /**
     * @class TlsCandidateFactory
     * @brief 构造 TLS carrier Runtime 候选
     */
    class TlsCandidateFactory
    {
    public:
        [[nodiscard]] static auto Make(TlsCandidateOptions Options,
                                       Preview::Recognition::SchemeExecutor *Executor,
                                       CarrierAcceptFn Accept)
            -> TlsCandidateBinding
        {
            const auto DefaultScheme = detail::SchemeName(Options.Carrier);
            if (Options.Scheme.empty())
            {
                Options.Scheme = std::string(DefaultScheme);
            }
            else
            {
                Options.Scheme = detail::Normalize(Options.Scheme);
            }
            if (Options.Name.empty())
            {
                Options.Name = Options.Scheme;
            }
            const auto Fallback = Options.Fallback && Options.Carrier == TlsCarrier::Native &&
                                  Options.Scheme == DefaultScheme;
            Core::CandidateSpec Spec;
            Spec.Id = Options.Id;
            if (Spec.Id == Core::InvalidCandidate)
            {
                Spec.Id = 0;
            }
            Spec.Name = Options.Name;
            Spec.Scheme = Options.Scheme;
            Spec.Protocol = Core::ProtocolType::Tls;
            Spec.Kind = Core::CandidateKind::TlsCarrier;
            Spec.Fallback = Fallback;
            Spec.MinimumBytes = Preview::Recognition::TlsRecordHeaderSize;
            TlsCandidateBinding Binding;
            Binding.Scheme = Options.Scheme;
            Binding.ServerNames = Options.ServerNames;
            Binding.Alpn = Options.Alpn;
            Binding.Fallback = Fallback;
            Spec.Inspect = [Names = Binding.ServerNames, Alpn = Binding.Alpn, Fallback](
                               const Core::ProbeSnapshot &Snapshot)
            {
                Core::ClientHelloFeatures Features;
                const auto Parsed = detail::ParseFeatures(Snapshot, Features);
                if (Parsed == Core::MatchState::Structural)
                {
                    return detail::InspectFeatures(Features, Names, Alpn, Fallback);
                }
                return Parsed;
            };
            Spec.Prepare = detail::PrepareClientHello;
            Spec.Commit = [Executor, Accept = std::move(Accept), Scheme = Options.Scheme](Core::CommitContext Context)
                -> Net::awaitable<Core::CommitResult>
            {
                co_return co_await detail::CommitScheme(
                    detail::CommitSchemeRequest{std::move(Context), Executor, Accept, Scheme});
            };
            Binding.Spec = std::move(Spec);
            return Binding;
        }

        [[nodiscard]] static auto Make(TlsCandidateOptions Options,
                                       Preview::Recognition::SchemeExecutor *Executor)
            -> TlsCandidateBinding
        {
            return Make(std::move(Options), Executor, {});
        }

        [[nodiscard]] static auto Make(TlsCandidateOptions Options, CarrierAcceptFn Accept)
            -> TlsCandidateBinding
        {
            return Make(std::move(Options), nullptr, std::move(Accept));
        }

        [[nodiscard]] static auto MakeNative(TlsCandidateOptions Options,
                                              Preview::Recognition::SchemeExecutor *Executor)
            -> TlsCandidateBinding
        {
            Options.Carrier = TlsCarrier::Native;
            Options.Scheme.clear();
            return Make(std::move(Options), Executor);
        }

        [[nodiscard]] static auto MakeReality(TlsCandidateOptions Options,
                                               Preview::Recognition::SchemeExecutor *Executor)
            -> TlsCandidateBinding
        {
            Options.Carrier = TlsCarrier::Reality;
            Options.Scheme.clear();
            return Make(std::move(Options), Executor);
        }

        [[nodiscard]] static auto MakeShadowtls(TlsCandidateOptions Options,
                                                Preview::Recognition::SchemeExecutor *Executor)
            -> TlsCandidateBinding
        {
            Options.Carrier = TlsCarrier::Shadowtls;
            Options.Scheme.clear();
            return Make(std::move(Options), Executor);
        }

        [[nodiscard]] static auto MakeRestls(TlsCandidateOptions Options,
                                             Preview::Recognition::SchemeExecutor *Executor)
            -> TlsCandidateBinding
        {
            Options.Carrier = TlsCarrier::Restls;
            Options.Scheme.clear();
            return Make(std::move(Options), Executor);
        }

        [[nodiscard]] static auto MakeWs(TlsCandidateOptions Options,
                                          Preview::Recognition::SchemeExecutor *Executor)
            -> TlsCandidateBinding
        {
            Options.Carrier = TlsCarrier::Ws;
            Options.Scheme.clear();
            return Make(std::move(Options), Executor);
        }

        [[nodiscard]] static auto MakeXhttp(TlsCandidateOptions Options,
                                            Preview::Recognition::SchemeExecutor *Executor)
            -> TlsCandidateBinding
        {
            Options.Carrier = TlsCarrier::Xhttp;
            Options.Scheme.clear();
            return Make(std::move(Options), Executor);
        }

        [[nodiscard]] static auto MakeGun(TlsCandidateOptions Options,
                                          Preview::Recognition::SchemeExecutor *Executor)
            -> TlsCandidateBinding
        {
            Options.Carrier = TlsCarrier::Gun;
            Options.Scheme.clear();
            return Make(std::move(Options), Executor);
        }

    };

} // namespace Preview::Composition::Recognition
