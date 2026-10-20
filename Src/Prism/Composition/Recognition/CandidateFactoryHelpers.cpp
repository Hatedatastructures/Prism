/** @file CandidateFactoryHelpers.cpp @brief protocol recognition 与认证准备辅助实现。 */

#include <Prism/Composition/Recognition/CandidateFactoryHelpers.hpp>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Anytls/Anytls.hpp>
#include <Prism/Protocols/Http1/Parser.hpp>
#include <Prism/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Prism/Protocols/Socks5/MessageCodec.hpp>
#include <Prism/Protocols/Trojan/CredentialCodec.hpp>
#include <Prism/Protocols/Trojan/RequestCodec.hpp>
#include <Prism/Protocols/Vless/RequestCodec.hpp>
#include <Prism/Protocols/Vmess/Credentials.hpp>
#include <Prism/Protocols/Vmess/RequestCodec.hpp>

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

namespace Prism::Composition::Recognition
{
    namespace detail
    {

        auto SnapshotBytes(const Core::ProbeSnapshot& Snapshot)
            -> std::span<const std::uint8_t>
        {
            const auto Bytes = Snapshot.Data();
            return {reinterpret_cast<const std::uint8_t*>(Bytes.data()), Bytes.size()};
        }

        auto SnapshotText(const Core::ProbeSnapshot& Snapshot) -> std::string_view
        {
            const auto Bytes = Snapshot.Data();
            return {reinterpret_cast<const char*>(Bytes.data()), Bytes.size()};
        }

        auto IsNeedMore(const std::error_code Error) noexcept -> bool
        {
            return Error == static_cast<std::error_code>(
                Prism::make_error_code(Prism::Error::NeedMore));
        }

        auto Accepted(const Core::CandidateId Id) -> Core::PrepareResult
        {
            Core::PrepareResult Result;
            Result.Candidate = Id;
            Result.Status = Core::RecognitionStatus::Accepted;
            return Result;
        }

        auto NoMatch(const Core::CandidateId Id) -> Core::PrepareResult
        {
            Core::PrepareResult Result;
            Result.Candidate = Id;
            Result.Status = Core::RecognitionStatus::NoMatch;
            return Result;
        }

        auto NeedMore(const Core::CandidateId Id) -> Core::PrepareResult
        {
            Core::PrepareResult Result;
            Result.Candidate = Id;
            Result.Status = Core::RecognitionStatus::NoMatch;
            Result.NeedMore = true;
            return Result;
        }

        auto CommitReplay(Core::CommitContext Context) -> Net::awaitable<Core::CommitResult>
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

        auto InspectHttp(const Core::ProbeSnapshot& Snapshot) -> Core::MatchState
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

        auto InspectSocks5(const Core::ProbeSnapshot& Snapshot) -> Core::MatchState
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

        auto InspectVless(const Core::ProbeSnapshot& Snapshot) -> Core::MatchState
        {
            Prism::Vless::RequestHeader Request;
            std::size_t Consumed = 0;
            const auto Error = Prism::Vless::ParseRequest(SnapshotBytes(Snapshot), Request, Consumed);
            if (Error == Prism::Error::NeedMore)
            {
                return Core::MatchState::NeedMore;
            }
            if (Error != Prism::Error::None ||
                (Request.Cmd != Prism::Vless::Command::Tcp &&
                 Request.Cmd != Prism::Vless::Command::Udp && Request.Cmd != Prism::Vless::Command::Mux))
            {
                return Core::MatchState::Rejected;
            }
            return Core::MatchState::Structural;
        }

        auto InspectTrojan(const Core::ProbeSnapshot& Snapshot) -> Core::MatchState
        {
            Prism::Trojan::RequestHeader Request;
            std::size_t Consumed = 0;
            const auto Error = Prism::Trojan::ParseRequest(SnapshotBytes(Snapshot), Request, Consumed);
            if (Error == Prism::Error::NeedMore)
            {
                return Core::MatchState::NeedMore;
            }
            if (Error != Prism::Error::None ||
                (Request.Cmd != Prism::Trojan::Command::Connect &&
                 Request.Cmd != Prism::Trojan::Command::UdpAssociate &&
                 Request.Cmd != Prism::Trojan::Command::Mux))
            {
                return Core::MatchState::Rejected;
            }
            return Core::MatchState::Structural;
        }

        auto InspectOpaqueLength(const Core::ProbeSnapshot& Snapshot,
            const std::size_t MinimumBytes) -> Core::MatchState
        {
            if (Snapshot.Size() < MinimumBytes)
            {
                return Core::MatchState::NeedMore;
            }
            return Core::MatchState::Structural;
        }

        auto PrepareVless(VlessPrepareRequest RequestData) -> Core::PrepareResult
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
            const std::string_view Got(reinterpret_cast<const char*>(Request.Uuid.data()),
                Request.Uuid.size());
            const std::string_view Expected(reinterpret_cast<const char*>(RequestData.Uuid.data()),
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

        auto PrepareTrojan(TrojanPrepareRequest RequestData) -> Core::PrepareResult
        {
            const auto Data = SnapshotBytes(RequestData.Snapshot);
            if (Data.size() < Prism::Trojan::CredentialLen + 2)
            {
                return NoMatch(RequestData.Id);
            }
            const auto Credential = Prism::Trojan::Credential(RequestData.Password);
            const std::string_view Got(reinterpret_cast<const char*>(Data.data()),
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

        auto InspectVmessUuid(const std::array<std::uint8_t, 16>& Uuid,
            const Core::ProbeSnapshot& Snapshot) -> VmessRequestInspection
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

        auto UpdateVmessTrial(VmessRequestInspection& State,
            const VmessRequestInspection& Trial) -> void
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

        auto VmessCredentialTrial::operator()(
            const std::shared_ptr<const Prism::Account::AccountBinding>&,
            const Prism::Account::CredentialMaterial& Material) const -> void
        {
            if (const auto Uuid = Prism::Vmess::Credentials::CopyUuid(Material.Credential.View()))
            {
                UpdateVmessTrial(State, InspectVmessUuid(*Uuid, Snapshot));
            }
        }

        auto PrepareVmess(VmessPrepareRequest RequestData) -> Core::PrepareResult
        {
            VmessRequestInspection State;
            if (RequestData.Credentials)
            {
                (void)RequestData.Credentials.ForEachCredential(
                    Prism::Account::CredentialKind::Uuid,
                    VmessCredentialTrial{State, RequestData.Snapshot});
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

        auto PrepareSs2022(Ss2022PrepareRequest RequestData) -> Core::PrepareResult
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

        auto InspectAnytls(const Core::ProbeSnapshot& Snapshot,
            const std::string_view Password) -> Core::MatchState
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

        auto PrepareAnytls(AnytlsPrepareRequest RequestData) -> Core::PrepareResult
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

        auto CommitFor() -> Core::CommitFn
        {
            return [](Core::CommitContext Context) -> Net::awaitable<Core::CommitResult>
            {
                co_return co_await CommitReplay(std::move(Context));
            };
        }

        auto NormalizeOptions(CandidateOptions Options, const std::string_view Name)
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

        auto BaseSpec(CandidateOptions Options, const std::string_view Name,
            const Prism::Contract::ProtocolType Protocol) -> Core::CandidateSpec
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
