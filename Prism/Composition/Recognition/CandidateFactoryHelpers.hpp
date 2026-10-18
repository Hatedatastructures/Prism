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

#include <Prism/Composition/Recognition/CandidateModel.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Anytls/Anytls.hpp>
#include <Prism/Protocols/Http1/Parser.hpp>
#include <Prism/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Prism/Protocols/Socks5/Codec.hpp>
#include <Prism/Protocols/Trojan/Codec.hpp>
#include <Prism/Protocols/Vless/Codec.hpp>
#include <Prism/Protocols/Vmess/Credentials.hpp>
#include <Prism/Protocols/Vmess/Codec.hpp>

namespace Prism::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Prism::Recognition;

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
            return Error == static_cast<std::error_code>(Prism::make_error_code(Prism::Error::NeedMore));
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
            if (Text.size() > Prism::Http11::MaxHdrSize)
            {
                return Core::MatchState::Rejected;
            }
            if (Text.find("\r\n\r\n") == std::string_view::npos)
            {
                return Core::MatchState::NeedMore;
            }
            Prism::Http11::HttpRequest Request;
            // 识别层只确认 HTTP/1.1 请求结构；目标语义由 Http1 ingress owner 返回 400。
            if (Prism::Http11::ParseRequest(Text, Request) != Prism::Fault::Code::Success)
            {
                return Core::MatchState::Rejected;
            }
            return Core::MatchState::Structural;
        }

        [[nodiscard]] inline auto InspectSocks5(const Core::ProbeSnapshot &Snapshot) -> Core::MatchState
        {
            const auto Data = SnapshotBytes(Snapshot);
            Prism::Socks5::Greeting Greeting;
            std::size_t Consumed = 0;
            const auto Error = Prism::Socks5::ParseGreeting(Data, Greeting, Consumed);
            if (Error == Prism::Error::NeedMore)
            {
                return Core::MatchState::NeedMore;
            }
            if (Error != Prism::Error::None || Greeting.Methods.empty())
            {
                return Core::MatchState::Rejected;
            }
            return Core::MatchState::Structural;
        }

        [[nodiscard]] inline auto InspectVless(const Core::ProbeSnapshot &Snapshot) -> Core::MatchState
        {
            Prism::Vless::RequestHeader Request;
            std::size_t Consumed = 0;
            const auto Error = Prism::Vless::ParseRequest(SnapshotBytes(Snapshot), Request, Consumed);
            if (Error == Prism::Error::NeedMore)
            {
                return Core::MatchState::NeedMore;
            }
            if (Error != Prism::Error::None ||
                (Request.Cmd != Prism::Vless::Command::Tcp && Request.Cmd != Prism::Vless::Command::Udp &&
                 Request.Cmd != Prism::Vless::Command::Mux))
            {
                return Core::MatchState::Rejected;
            }
            return Core::MatchState::Structural;
        }

        [[nodiscard]] inline auto InspectTrojan(const Core::ProbeSnapshot &Snapshot) -> Core::MatchState
        {
            Prism::Trojan::RequestHeader Request;
            std::size_t Consumed = 0;
            const auto Error = Prism::Trojan::ParseRequest(SnapshotBytes(Snapshot), Request, Consumed);
            if (Error == Prism::Error::NeedMore)
            {
                return Core::MatchState::NeedMore;
            }
            if (Error != Prism::Error::None || (Request.Cmd != Prism::Trojan::Command::Connect &&
                                                  Request.Cmd != Prism::Trojan::Command::UdpAssociate &&
                                                  Request.Cmd != Prism::Trojan::Command::Mux))
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
            std::array<std::uint8_t, Prism::Vless::UuidLen> Uuid{};
            Prism::SharedAuthenticator AuthenticatorOwner{};
            Core::ProbeSnapshot Snapshot{};
            bool UdpEnabled{true};
        };

        struct TrojanPrepareRequest
        {
            Core::CandidateId Id{Core::InvalidCandidate};
            std::string Password;
            bool EnableTcp{true};
            bool EnableUdp{false};
            Prism::SharedAuthenticator AuthenticatorOwner{};
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
            Prism::Vless::RequestHeader Request;
            std::size_t Consumed = 0;
            if (Prism::Vless::ParseRequest(SnapshotBytes(RequestData.Snapshot), Request, Consumed) !=
                Prism::Error::None)
            {
                return NoMatch(RequestData.Id);
            }
            if (Request.Cmd == Prism::Vless::Command::Udp && !RequestData.UdpEnabled)
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
                const auto Credential = Prism::Account::CredentialView{
                    Prism::Account::CredentialKind::Uuid,
                    std::as_bytes(std::span<const std::uint8_t>(Request.Uuid))};
                const auto Inspected = RequestData.AuthenticatorOwner->InspectCredential(Credential);
                Authenticated = Inspected && *Inspected;
            }
            else
            {
                Authenticated = Prism::ConstantTimeEqual(Got, Expected);
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
            if (Data.size() < Prism::Trojan::CredentialLen + 2)
            {
                return NoMatch(RequestData.Id);
            }
            const auto Credential = Prism::Trojan::Credential(RequestData.Password);
            const std::string_view Got(reinterpret_cast<const char *>(Data.data()),
                                       Prism::Trojan::CredentialLen);
            bool Authenticated = false;
            if (RequestData.AuthenticatorOwner)
            {
                const auto Inspected = RequestData.AuthenticatorOwner->InspectCredential(
                    Prism::Account::CredentialView::Token(Got));
                Authenticated = Inspected && *Inspected;
            }
            else
            {
                Authenticated = Prism::ConstantTimeEqual(Got, Credential);
            }
            if (!Authenticated)
            {
                return NoMatch(RequestData.Id);
            }
            Prism::Trojan::RequestHeader Request;
            std::size_t Consumed = 0;
            if (Prism::Trojan::ParseRequest(Data, Request, Consumed) != Prism::Error::None)
            {
                return NoMatch(RequestData.Id);
            }
            if ((Request.Cmd == Prism::Trojan::Command::Connect && !RequestData.EnableTcp) ||
                (Request.Cmd == Prism::Trojan::Command::UdpAssociate && !RequestData.EnableUdp))
            {
                return NoMatch(RequestData.Id);
            }
            return Accepted(RequestData.Id);
        }

        struct VmessRequestInspection final
        {
            Core::MatchState State{Core::MatchState::Rejected};
            std::optional<Prism::Vmess::Command> Command;
        };

        [[nodiscard]] inline auto InspectVmessUuid(
            const std::array<std::uint8_t, 16> &Uuid,
            const Core::ProbeSnapshot &Snapshot) -> VmessRequestInspection
        {
            Prism::Vmess::Parser Parser(Uuid);
            std::error_code Error;
            const auto Data = SnapshotBytes(Snapshot);
            Parser.Put(Net::const_buffer(Data.data(), Data.size()), Error);
            if (IsNeedMore(Error))
            {
                return {Core::MatchState::NeedMore, std::nullopt};
            }
            if (Error || !Parser.IsDone())
            {
                return {};
            }
            const auto Command = static_cast<Prism::Vmess::Command>(Parser.Get().Cmd);
            if (Command != Prism::Vmess::Command::Tcp && Command != Prism::Vmess::Command::Udp &&
                Command != Prism::Vmess::Command::Mux)
            {
                return {};
            }
            return {Core::MatchState::Authenticated, Command};
        }

        struct VmessPrepareRequest final
        {
            Core::CandidateId Id{Core::InvalidCandidate};
            std::array<std::uint8_t, 16> Uuid{};
            Prism::Account::CredentialIndexView Credentials;
            Core::ProbeSnapshot Snapshot{};
            bool UdpEnabled{true};
        };

        inline auto UpdateVmessTrial(
            VmessRequestInspection &State,
            const VmessRequestInspection &Trial) -> void
        {
            if (Trial.State == Core::MatchState::Authenticated)
            {
                State = Trial;
            }
            else if (State.State != Core::MatchState::Authenticated &&
                     Trial.State == Core::MatchState::NeedMore)
            {
                State = Trial;
            }
        }

        /** @brief 同步借用本次 probe 状态和快照；ForEachCredential 返回后不保存任何材料引用。 */
        struct VmessCredentialTrial final
        {
            VmessRequestInspection &State;
            const Core::ProbeSnapshot &Snapshot;

            auto operator()(const std::shared_ptr<const Prism::Account::AccountBinding> &,
                            const Prism::Account::CredentialMaterial &Material) const -> void
            {
                if (const auto Uuid = Prism::Vmess::Credentials::CopyUuid(Material.Credential.View()))
                    UpdateVmessTrial(State, InspectVmessUuid(*Uuid, Snapshot));
            }
        };

        [[nodiscard]] inline auto PrepareVmess(VmessPrepareRequest RequestData)
            -> Core::PrepareResult
        {
            VmessRequestInspection State;
            if (RequestData.Credentials)
            {
                (void)RequestData.Credentials.ForEachCredential(
                    Prism::Account::CredentialKind::Uuid, VmessCredentialTrial{State, RequestData.Snapshot});
            }
            else
            {
                UpdateVmessTrial(State, InspectVmessUuid(RequestData.Uuid, RequestData.Snapshot));
            }
            if (State.State == Core::MatchState::Authenticated && State.Command)
            {
                if (*State.Command == Prism::Vmess::Command::Udp && !RequestData.UdpEnabled)
                {
                    return NoMatch(RequestData.Id);
                }
                return Accepted(RequestData.Id);
            }
            if (State.State == Core::MatchState::NeedMore)
            {
                return NeedMore(RequestData.Id);
            }
            return NoMatch(RequestData.Id);
        }

        [[nodiscard]] inline auto PrepareSs2022(Ss2022PrepareRequest RequestData) -> Core::PrepareResult
        {
            Prism::Shadowsocks2022::Parser Parser(RequestData.Psk);
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
            std::array<std::uint8_t, Prism::Anytls::PasswordHashLen> Hash{};
            const auto Data = SnapshotBytes(Snapshot);
            if (Data.size() < Hash.size())
            {
                return Core::MatchState::NeedMore;
            }
            std::copy_n(Data.begin(), Hash.size(), Hash.begin());
            if (!Prism::Anytls::VerifyAuth(Password, Hash))
            {
                return Core::MatchState::Rejected;
            }
            return Core::MatchState::Authenticated;
        }

        [[nodiscard]] inline auto PrepareAnytls(AnytlsPrepareRequest RequestData) -> Core::PrepareResult
        {
            std::array<std::uint8_t, Prism::Anytls::PasswordHashLen> Hash{};
            const auto Data = SnapshotBytes(RequestData.Snapshot);
            if (Data.size() < Hash.size())
            {
                return NeedMore(RequestData.Id);
            }
            std::copy_n(Data.begin(), Hash.size(), Hash.begin());
            if (!Prism::Anytls::VerifyAuth(RequestData.Password, Hash))
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
                                           Prism::Contract::ProtocolType Protocol) -> Core::CandidateSpec
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

} // namespace Prism::Composition::Recognition
