/**
 * @file CandidateFactoryHelpers.hpp
 * @brief cleartext/opaque 候选的 probe、认证准备和 replay 提交辅助函数。
 * @details 所有函数只操作 ProbeSnapshot 或按值捕获的配置。CommitReplay
 *          只在 winner 确认后转移 inbound，避免失败试探污染连接状态。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <Preview/Composition/Recognition/CandidateModel.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Anytls/Anytls.hpp>
#include <Preview/Protocols/Http1/Parser.hpp>
#include <Preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Preview/Protocols/Socks5/Codec.hpp>
#include <Preview/Protocols/Trojan/Codec.hpp>
#include <Preview/Protocols/Vless/Codec.hpp>
#include <Preview/Protocols/Vmess/Credentials.hpp>
#include <Preview/Protocols/Vmess/Codec.hpp>

namespace Preview::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;

    namespace detail
    {

        [[nodiscard]] inline auto SnapshotBytes(const Core::ProbeSnapshot &Snapshot)
            -> std::span<const std::uint8_t>
        {
            const auto Bytes = Snapshot.Data();
            return {reinterpret_cast<const std::uint8_t *>(Bytes.data()), Bytes.size()};
        }

        [[nodiscard]] inline auto SnapshotText(const Core::ProbeSnapshot &Snapshot) -> std::string_view
        {
            const auto Bytes = Snapshot.Data();
            return {reinterpret_cast<const char *>(Bytes.data()), Bytes.size()};
        }

        [[nodiscard]] inline auto IsNeedMore(std::error_code Error) noexcept -> bool
        {
            return Error == static_cast<std::error_code>(Preview::make_error_code(Preview::Error::NeedMore));
        }

        [[nodiscard]] inline auto Accepted(Core::CandidateId Id) -> Core::PrepareResult
        {
            Core::PrepareResult Result;
            Result.Candidate = Id;
            Result.Status = Core::RecognitionStatus::Accepted;
            return Result;
        }

        [[nodiscard]] inline auto NoMatch(Core::CandidateId Id) -> Core::PrepareResult
        {
            Core::PrepareResult Result;
            Result.Candidate = Id;
            Result.Status = Core::RecognitionStatus::NoMatch;
            return Result;
        }

        [[nodiscard]] inline auto NeedMore(Core::CandidateId Id) -> Core::PrepareResult
        {
            Core::PrepareResult Result;
            Result.Candidate = Id;
            Result.Status = Core::RecognitionStatus::NoMatch;
            Result.NeedMore = true;
            return Result;
        }

        [[nodiscard]] inline auto CommitReplay(Core::CommitContext Context)
            -> Net::awaitable<Core::CommitResult>
        {
            Core::CommitResult Result;
            Result.Candidate = Context.Candidate;
            if (Context.Polluted || !Context.Inbound)
            {
                if (Context.Polluted)
                {
                    Result.Status = Core::RecognitionStatus::Polluted;
                    Result.Error = std::make_error_code(std::errc::operation_not_permitted);
                }
                else
                {
                    Result.Status = Core::RecognitionStatus::IoError;
                    Result.Error = std::make_error_code(std::errc::bad_message);
                }
                Result.Polluted = Context.Polluted;
                co_return Result;
            }
            Result.Status = Core::RecognitionStatus::Accepted;
            Result.Transport = std::move(Context.Inbound);
            co_return Result;
        }

        [[nodiscard]] inline auto InspectHttp(const Core::ProbeSnapshot &Snapshot) -> Core::MatchState
        {
            const auto Text = SnapshotText(Snapshot);
            if (Text.empty())
            {
                return Core::MatchState::NeedMore;
            }
            if (Text.size() > Preview::Http11::MaxHdrSize)
            {
                return Core::MatchState::Rejected;
            }
            if (Text.find("\r\n\r\n") == std::string_view::npos)
            {
                return Core::MatchState::NeedMore;
            }
            Preview::Http11::HttpRequest Request;
            // 识别层只确认 HTTP/1.1 请求结构；目标语义由 Http1 ingress owner 返回 400。
            if (Preview::Http11::ParseRequest(Text, Request) != Preview::Fault::Code::Success)
            {
                return Core::MatchState::Rejected;
            }
            return Core::MatchState::Structural;
        }

        [[nodiscard]] inline auto InspectSocks5(const Core::ProbeSnapshot &Snapshot) -> Core::MatchState
        {
            const auto Data = SnapshotBytes(Snapshot);
            Preview::Socks5::Greeting Greeting;
            std::size_t Consumed = 0;
            const auto Error = Preview::Socks5::ParseGreeting(Data, Greeting, Consumed);
            if (Error == Preview::Error::NeedMore)
            {
                return Core::MatchState::NeedMore;
            }
            if (Error != Preview::Error::None || Greeting.Methods.empty())
            {
                return Core::MatchState::Rejected;
            }
            return Core::MatchState::Structural;
        }

        [[nodiscard]] inline auto InspectVless(const Core::ProbeSnapshot &Snapshot) -> Core::MatchState
        {
            Preview::Vless::RequestHeader Request;
            std::size_t Consumed = 0;
            const auto Error = Preview::Vless::ParseRequest(SnapshotBytes(Snapshot), Request, Consumed);
            if (Error == Preview::Error::NeedMore)
            {
                return Core::MatchState::NeedMore;
            }
            if (Error != Preview::Error::None ||
                (Request.Cmd != Preview::Vless::Command::Tcp && Request.Cmd != Preview::Vless::Command::Udp &&
                 Request.Cmd != Preview::Vless::Command::Mux))
            {
                return Core::MatchState::Rejected;
            }
            return Core::MatchState::Structural;
        }

        [[nodiscard]] inline auto InspectTrojan(const Core::ProbeSnapshot &Snapshot) -> Core::MatchState
        {
            Preview::Trojan::RequestHeader Request;
            std::size_t Consumed = 0;
            const auto Error = Preview::Trojan::ParseRequest(SnapshotBytes(Snapshot), Request, Consumed);
            if (Error == Preview::Error::NeedMore)
            {
                return Core::MatchState::NeedMore;
            }
            if (Error != Preview::Error::None || (Request.Cmd != Preview::Trojan::Command::Connect &&
                                                  Request.Cmd != Preview::Trojan::Command::UdpAssociate &&
                                                  Request.Cmd != Preview::Trojan::Command::Mux))
            {
                return Core::MatchState::Rejected;
            }
            return Core::MatchState::Structural;
        }

        [[nodiscard]] inline auto InspectOpaqueLength(const Core::ProbeSnapshot &Snapshot,
                                                      std::size_t MinimumBytes) -> Core::MatchState
        {
            if (Snapshot.Size() < MinimumBytes)
            {
                return Core::MatchState::NeedMore;
            }
            return Core::MatchState::Structural;
        }

        struct VlessPrepareRequest
        {
            Core::CandidateId Id{Core::InvalidCandidate};
            std::array<std::uint8_t, Preview::Vless::UuidLen> Uuid{};
            Preview::SharedAuthenticator AuthenticatorOwner{};
            Core::ProbeSnapshot Snapshot{};
        };

        struct TrojanPrepareRequest
        {
            Core::CandidateId Id{Core::InvalidCandidate};
            std::string Password;
            bool EnableTcp{true};
            bool EnableUdp{false};
            Preview::SharedAuthenticator AuthenticatorOwner{};
            Core::ProbeSnapshot Snapshot{};
        };

        struct Ss2022PrepareRequest
        {
            Core::CandidateId Id{Core::InvalidCandidate};
            std::array<std::uint8_t, 16> Psk{};
            std::uint64_t TimeWindow{90};
            Core::ProbeSnapshot Snapshot{};
        };

        struct AnytlsPrepareRequest
        {
            Core::CandidateId Id{Core::InvalidCandidate};
            std::string Password;
            Core::ProbeSnapshot Snapshot{};
        };

        [[nodiscard]] inline auto PrepareVless(VlessPrepareRequest RequestData) -> Core::PrepareResult
        {
            Preview::Vless::RequestHeader Request;
            std::size_t Consumed = 0;
            if (Preview::Vless::ParseRequest(SnapshotBytes(RequestData.Snapshot), Request, Consumed) !=
                Preview::Error::None)
            {
                return NoMatch(RequestData.Id);
            }
            const std::string_view Got(reinterpret_cast<const char *>(Request.Uuid.data()),
                                       Request.Uuid.size());
            const std::string_view Expected(reinterpret_cast<const char *>(RequestData.Uuid.data()),
                                            RequestData.Uuid.size());
            bool Authenticated = false;
            if (RequestData.AuthenticatorOwner)
            {
                const auto Credential = Preview::Account::CredentialView{
                    Preview::Account::CredentialKind::Uuid,
                    std::as_bytes(std::span<const std::uint8_t>(Request.Uuid))};
                const auto Inspected = RequestData.AuthenticatorOwner->InspectCredential(Credential);
                Authenticated = Inspected && *Inspected;
            }
            else
            {
                Authenticated = Preview::ConstantTimeEqual(Got, Expected);
            }
            if (!Authenticated)
            {
                return NoMatch(RequestData.Id);
            }
            return Accepted(RequestData.Id);
        }

        [[nodiscard]] inline auto PrepareTrojan(TrojanPrepareRequest RequestData) -> Core::PrepareResult
        {
            const auto Data = SnapshotBytes(RequestData.Snapshot);
            if (Data.size() < Preview::Trojan::CredentialLen + 2)
            {
                return NoMatch(RequestData.Id);
            }
            const auto Credential = Preview::Trojan::Credential(RequestData.Password);
            const std::string_view Got(reinterpret_cast<const char *>(Data.data()),
                                       Preview::Trojan::CredentialLen);
            bool Authenticated = false;
            if (RequestData.AuthenticatorOwner)
            {
                const auto Inspected = RequestData.AuthenticatorOwner->InspectCredential(
                    Preview::Account::CredentialView::Token(Got));
                Authenticated = Inspected && *Inspected;
            }
            else
            {
                Authenticated = Preview::ConstantTimeEqual(Got, Credential);
            }
            if (!Authenticated)
            {
                return NoMatch(RequestData.Id);
            }
            Preview::Trojan::RequestHeader Request;
            std::size_t Consumed = 0;
            if (Preview::Trojan::ParseRequest(Data, Request, Consumed) != Preview::Error::None)
            {
                return NoMatch(RequestData.Id);
            }
            if ((Request.Cmd == Preview::Trojan::Command::Connect && !RequestData.EnableTcp) ||
                (Request.Cmd == Preview::Trojan::Command::UdpAssociate && !RequestData.EnableUdp))
            {
                return NoMatch(RequestData.Id);
            }
            return Accepted(RequestData.Id);
        }

        [[nodiscard]] inline auto InspectVmessUuid(
            const std::array<std::uint8_t, 16> &Uuid,
            const Core::ProbeSnapshot &Snapshot) -> Core::MatchState
        {
            Preview::Vmess::Parser Parser(Uuid);
            std::error_code Error;
            const auto Data = SnapshotBytes(Snapshot);
            Parser.Put(Net::const_buffer(Data.data(), Data.size()), Error);
            if (IsNeedMore(Error))
            {
                return Core::MatchState::NeedMore;
            }
            if (Error || !Parser.IsDone())
            {
                return Core::MatchState::Rejected;
            }
            const auto Command = static_cast<Preview::Vmess::Command>(Parser.Get().Cmd);
            if (Command != Preview::Vmess::Command::Tcp && Command != Preview::Vmess::Command::Udp &&
                Command != Preview::Vmess::Command::Mux)
            {
                return Core::MatchState::Rejected;
            }
            return Core::MatchState::Authenticated;
        }

        struct VmessPrepareRequest final
        {
            Core::CandidateId Id{Core::InvalidCandidate};
            std::array<std::uint8_t, 16> Uuid{};
            Preview::Account::CredentialIndexView Credentials;
            Core::ProbeSnapshot Snapshot{};
        };

        inline auto UpdateVmessTrial(
            Core::MatchState &State,
            const std::array<std::uint8_t, 16> &Uuid,
            const Core::ProbeSnapshot &Snapshot) -> void
        {
            const auto Trial = InspectVmessUuid(Uuid, Snapshot);
            if (Trial == Core::MatchState::Authenticated)
            {
                State = Trial;
            }
            else if (State != Core::MatchState::Authenticated &&
                     Trial == Core::MatchState::NeedMore)
            {
                State = Trial;
            }
        }

        /** @brief 同步借用本次 probe 状态和快照；ForEachCredential 返回后不保存任何材料引用。 */
        struct VmessCredentialTrial final
        {
            Core::MatchState &State;
            const Core::ProbeSnapshot &Snapshot;

            auto operator()(const std::shared_ptr<const Preview::Account::AccountBinding> &,
                            const Preview::Account::CredentialMaterial &Material) const -> void
            {
                if (const auto Uuid = Preview::Vmess::Credentials::CopyUuid(Material.Credential.View()))
                    UpdateVmessTrial(State, *Uuid, Snapshot);
            }
        };

        [[nodiscard]] inline auto PrepareVmess(VmessPrepareRequest RequestData)
            -> Core::PrepareResult
        {
            auto State = Core::MatchState::Rejected;
            if (RequestData.Credentials)
            {
                (void)RequestData.Credentials.ForEachCredential(
                    Preview::Account::CredentialKind::Uuid, VmessCredentialTrial{State, RequestData.Snapshot});
            }
            else
            {
                UpdateVmessTrial(State, RequestData.Uuid, RequestData.Snapshot);
            }
            if (State == Core::MatchState::Authenticated)
            {
                return Accepted(RequestData.Id);
            }
            if (State == Core::MatchState::NeedMore)
            {
                return NeedMore(RequestData.Id);
            }
            return NoMatch(RequestData.Id);
        }

        [[nodiscard]] inline auto PrepareSs2022(Ss2022PrepareRequest RequestData) -> Core::PrepareResult
        {
            Preview::Shadowsocks2022::Parser Parser(RequestData.Psk);
            std::error_code Error;
            const auto Data = SnapshotBytes(RequestData.Snapshot);
            Parser.Put(Net::const_buffer(Data.data(), Data.size()), Error);
            if (IsNeedMore(Error))
            {
                return NeedMore(RequestData.Id);
            }
            if (Error || !Parser.IsDone() || !Parser.IsTimestampFresh(RequestData.TimeWindow))
            {
                return NoMatch(RequestData.Id);
            }
            return Accepted(RequestData.Id);
        }

        [[nodiscard]] inline auto InspectAnytls(const Core::ProbeSnapshot &Snapshot,
                                                std::string_view Password) -> Core::MatchState
        {
            std::array<std::uint8_t, Preview::Anytls::PasswordHashLen> Hash{};
            const auto Data = SnapshotBytes(Snapshot);
            if (Data.size() < Hash.size())
            {
                return Core::MatchState::NeedMore;
            }
            std::copy_n(Data.begin(), Hash.size(), Hash.begin());
            if (!Preview::Anytls::VerifyAuth(Password, Hash))
            {
                return Core::MatchState::Rejected;
            }
            return Core::MatchState::Authenticated;
        }

        [[nodiscard]] inline auto PrepareAnytls(AnytlsPrepareRequest RequestData) -> Core::PrepareResult
        {
            std::array<std::uint8_t, Preview::Anytls::PasswordHashLen> Hash{};
            const auto Data = SnapshotBytes(RequestData.Snapshot);
            if (Data.size() < Hash.size())
            {
                return NeedMore(RequestData.Id);
            }
            std::copy_n(Data.begin(), Hash.size(), Hash.begin());
            if (!Preview::Anytls::VerifyAuth(RequestData.Password, Hash))
            {
                return NoMatch(RequestData.Id);
            }
            return Accepted(RequestData.Id);
        }

        [[nodiscard]] inline auto CommitFor() -> Core::CommitFn
        {
            return [](Core::CommitContext Context) -> Net::awaitable<Core::CommitResult>
            { co_return co_await CommitReplay(std::move(Context)); };
        }

        [[nodiscard]] inline auto NormalizeOptions(CandidateOptions Options, std::string_view Name)
            -> CandidateOptions
        {
            if (Options.Id == Core::InvalidCandidate)
            {
                Options.Id = 0;
            }
            if (Options.Name.empty())
            {
                Options.Name = std::string(Name);
            }
            return Options;
        }

        [[nodiscard]] inline auto BaseSpec(CandidateOptions Options, std::string_view Name,
                                           Preview::Contract::ProtocolType Protocol) -> Core::CandidateSpec
        {
            Options = NormalizeOptions(std::move(Options), Name);
            Core::CandidateSpec Spec;
            Spec.Id = Options.Id;
            Spec.Name = std::move(Options.Name);
            Spec.Protocol = Protocol;
            Spec.Priority = Options.Priority;
            Spec.Tier = Options.Tier;
            Spec.Fallback = Options.Fallback;
            Spec.Commit = CommitFor();
            return Spec;
        }

    } // namespace detail

} // namespace Preview::Composition::Recognition
