/**
 * @file CandidateFactory.hpp
 * @brief Composition 层协议候选与 handler resolver 工厂
 * @details CandidateSpec 只保存 Runtime 可理解的结构检查、认证准备和
 *          replay 提交回调；具体 ProtocolHandler 由返回的 Accept 回调持有，
 *          只有 Session 在 winner 确定后才会调用它。
 */

#pragma once

#include <boost/asio/buffer.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/address_v6.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <preview/Composition/Adapters/ProtocolAdapter.hpp>
#include <preview/Foundation/Authenticator.hpp>
#include <preview/Protocols/Http1/Conn.hpp>
#include <preview/Protocols/Http1/Parser.hpp>
#include <preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <preview/Protocols/Socks5/Codec.hpp>
#include <preview/Protocols/Trojan/Codec.hpp>
#include <preview/Protocols/Vless/Codec.hpp>
#include <preview/Protocols/Vmess/Codec.hpp>
#include <preview/Runtime/Recognition/Profile.hpp>

namespace Preview::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Runtime = Preview::Runtime;
    namespace Core = Preview::Recognition;

    /**
     * @struct CandidateOptions
     * @brief 候选的稳定元数据
     */
    struct CandidateOptions
    {
        Core::CandidateId Id{Core::InvalidCandidate};
        std::string Name;
        std::uint16_t Priority{0};
        std::uint8_t Tier{0};
        bool Fallback{false};
    };

    /**
     * @struct HttpConfig
     * @brief HTTP CONNECT 候选的认证配置
     */
    struct HttpConfig
    {
        bool RequireAuth{false};
        Preview::SharedAuthenticator Authenticator{};
    };

    /**
     * @struct CandidateBinding
     * @brief Runtime 候选与其 winner-only 接入器
     */
    struct CandidateBinding
    {
        Core::CandidateSpec Spec;
        Runtime::SessionOptions::ProtocolAcceptFn Accept;
    };

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

        [[nodiscard]] inline auto IsSuccessful(Core::MatchState State) noexcept -> bool
        {
            return State == Core::MatchState::Structural || State == Core::MatchState::Authenticated;
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

        [[nodiscard]] inline auto ParsePort(std::string_view Text, std::uint16_t &Port) noexcept -> bool
        {
            if (Text.empty())
            {
                return false;
            }
            unsigned Value = 0;
            const auto *Begin = Text.data();
            const auto *End = Begin + Text.size();
            const auto [Next, Error] = std::from_chars(Begin, End, Value);
            if (Error != std::errc{} || Next != End || Value == 0 || Value > 65535)
            {
                return false;
            }
            Port = static_cast<std::uint16_t>(Value);
            return true;
        }

        [[nodiscard]] inline auto ParseHttpTarget(std::string_view Target, std::string &Host,
                                                  std::string &Port) -> bool
        {
            std::string_view HostPart;
            std::string_view PortPart;
            if (Target.starts_with('['))
            {
                const auto Close = Target.find(']');
                if (Close == std::string_view::npos || Close + 1 >= Target.size() ||
                    Target[Close + 1] != ':')
                {
                    return false;
                }
                HostPart = Target.substr(1, Close - 1);
                PortPart = Target.substr(Close + 2);
                boost::system::error_code AddressError;
                (void)Net::ip::make_address_v6(HostPart, AddressError);
                if (AddressError)
                {
                    return false;
                }
            }
            else
            {
                const auto Colon = Target.rfind(':');
                if (Colon == std::string_view::npos)
                {
                    return false;
                }
                HostPart = Target.substr(0, Colon);
                PortPart = Target.substr(Colon + 1);
                // 未加方括号的 IPv6 authority 无法区分地址分隔冒号与端口冒号。
                if (HostPart.find(':') != std::string_view::npos)
                {
                    return false;
                }
            }
            std::uint16_t ParsedPort = 0;
            if (HostPart.empty() || !ParsePort(PortPart, ParsedPort))
            {
                return false;
            }
            Host.assign(HostPart);
            Port = std::to_string(ParsedPort);
            return true;
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
            if (Preview::Http11::ParseRequest(Text, Request) != Preview::Fault::Code::Success ||
                Request.Method != "CONNECT" || Request.version != "HTTP/1.1")
            {
                return Core::MatchState::Rejected;
            }
            std::string Host;
            std::string Port;
            if (ParseHttpTarget(Request.Target, Host, Port))
            {
                return Core::MatchState::Structural;
            }
            return Core::MatchState::Rejected;
        }

        [[nodiscard]] inline auto InspectSocks5(const Core::ProbeSnapshot &Snapshot)
            -> Core::MatchState
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

        [[nodiscard]] inline auto InspectVless(const Core::ProbeSnapshot &Snapshot)
            -> Core::MatchState
        {
            Preview::Vless::RequestHeader Request;
            std::size_t Consumed = 0;
            const auto Error = Preview::Vless::ParseRequest(SnapshotBytes(Snapshot), Request, Consumed);
            if (Error == Preview::Error::NeedMore)
            {
                return Core::MatchState::NeedMore;
            }
            if (Error != Preview::Error::None ||
                (Request.Cmd != Preview::Vless::Command::Tcp &&
                 Request.Cmd != Preview::Vless::Command::Udp &&
                 Request.Cmd != Preview::Vless::Command::Mux))
            {
                return Core::MatchState::Rejected;
            }
            return Core::MatchState::Structural;
        }

        [[nodiscard]] inline auto InspectTrojan(const Core::ProbeSnapshot &Snapshot)
            -> Core::MatchState
        {
            Preview::Trojan::RequestHeader Request;
            std::size_t Consumed = 0;
            const auto Error = Preview::Trojan::ParseRequest(SnapshotBytes(Snapshot), Request, Consumed);
            if (Error == Preview::Error::NeedMore)
            {
                return Core::MatchState::NeedMore;
            }
            if (Error != Preview::Error::None ||
                (Request.Cmd != Preview::Trojan::Command::Connect &&
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
            const Preview::Authenticator *Authenticator{nullptr};
            Core::ProbeSnapshot Snapshot{};
        };

        struct TrojanPrepareRequest
        {
            Core::CandidateId Id{Core::InvalidCandidate};
            std::string Password;
            bool EnableTcp{true};
            bool EnableUdp{false};
            const Preview::Authenticator *Authenticator{nullptr};
            Core::ProbeSnapshot Snapshot{};
        };

        struct Ss2022PrepareRequest
        {
            Core::CandidateId Id{Core::InvalidCandidate};
            std::array<std::uint8_t, 16> Psk{};
            std::uint64_t TimeWindow{90};
            Core::ProbeSnapshot Snapshot{};
        };

        [[nodiscard]] inline auto SsPsk(const Preview::Shadowsocks2022::ServerConfig &Config)
            -> std::optional<std::array<std::uint8_t, 16>>
        {
            if (Config.UsePsk)
            {
                return std::optional{Config.Psk};
            }
            return Preview::Shadowsocks2022::DecodePsk(Config.password);
        }

        [[nodiscard]] inline auto PrepareVless(VlessPrepareRequest RequestData)
            -> Core::PrepareResult
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
            if (RequestData.Authenticator)
            {
                Authenticated = RequestData.Authenticator->Check("", Got).Ok;
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

        [[nodiscard]] inline auto PrepareTrojan(TrojanPrepareRequest RequestData)
            -> Core::PrepareResult
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
            if (RequestData.Authenticator)
            {
                Authenticated = RequestData.Authenticator->Check("", Got).Ok;
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

        [[nodiscard]] inline auto PrepareVmess(Core::CandidateId Id,
                                               std::array<std::uint8_t, 16> Uuid,
                                               const Core::ProbeSnapshot &Snapshot) -> Core::PrepareResult
        {
            Preview::Vmess::Parser Parser(Uuid);
            std::error_code Error;
            const auto Data = SnapshotBytes(Snapshot);
            Parser.Put(Net::const_buffer(Data.data(), Data.size()), Error);
            if (IsNeedMore(Error))
            {
                return NeedMore(Id);
            }
            if (Error || !Parser.IsDone())
            {
                return NoMatch(Id);
            }
            const auto Command = static_cast<Preview::Vmess::Command>(Parser.Get().Cmd);
            if (Command != Preview::Vmess::Command::Tcp &&
                Command != Preview::Vmess::Command::Udp &&
                Command != Preview::Vmess::Command::Mux)
            {
                return NoMatch(Id);
            }
            return Accepted(Id);
        }

        [[nodiscard]] inline auto PrepareSs2022(Ss2022PrepareRequest RequestData)
            -> Core::PrepareResult
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

        [[nodiscard]] inline auto CommitFor() -> Core::CommitFn
        {
            return [](Core::CommitContext Context) -> Net::awaitable<Core::CommitResult>
            {
                co_return co_await CommitReplay(std::move(Context));
            };
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
                                           Core::ProtocolType Protocol) -> Core::CandidateSpec
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

    /**
     * @class HttpHandler
     * @brief HTTP CONNECT 协议 handler
     */
    class HttpHandler final : public Runtime::Handler::ProtocolHandler
    {
    public:
        explicit HttpHandler(HttpConfig Config) : Config_(std::move(Config)) {}

        auto Accept(Preview::SharedTransmission Inbound)
            -> Net::awaitable<Runtime::Handler::AcceptResult> override
        {
            Runtime::Handler::AcceptResult Result;
            if (!Inbound)
            {
                Result.err = Preview::Error::IoError;
                co_return Result;
            }
            auto Raw = Inbound;
            Preview::Http11::ServerConn Server(std::move(Inbound));
            Preview::Http11::HttpRequest Request;
            const auto ReadError = co_await Server.ReadRequest(Request);
            if (ReadError != Preview::Fault::Code::Success || Request.Method != "CONNECT")
            {
                co_await Server.SendResponse(Preview::Http11::Status::BadRequest);
                if (Raw)
                {
                    Raw->Close();
                }
                Result.err = Preview::Error::BadMessage;
                co_return Result;
            }

            std::string Host;
            std::string Port;
            if (!detail::ParseHttpTarget(Request.Target, Host, Port))
            {
                co_await Server.SendResponse(Preview::Http11::Status::BadRequest);
                if (Raw)
                {
                    Raw->Close();
                }
                Result.err = Preview::Error::BadAddress;
                co_return Result;
            }

            Preview::AuthResult AuthResult;
            if (Config_.RequireAuth)
            {
                if (!Config_.Authenticator)
                {
                    co_await Server.SendResponse(Preview::Http11::Status::ProxyAuthRequired);
                    if (Raw)
                    {
                        Raw->Close();
                    }
                    Result.err = Preview::Error::BadAuth;
                    co_return Result;
                }
                AuthResult = Preview::Http11::CheckBasic(Request.authorization, *Config_.Authenticator);
                if (!AuthResult.Ok)
                {
                    co_await Server.SendResponse(Preview::Http11::Status::ProxyAuthRequired);
                    if (Raw)
                    {
                        Raw->Close();
                    }
                    Result.err = Preview::Error::BadAuth;
                    co_return Result;
                }
            }

            if (co_await Server.SendResponse(Preview::Http11::Status::Ok) != Preview::Fault::Code::Success)
            {
                Result.err = Preview::Error::IoError;
                co_return Result;
            }
            Result.Target.Host = Host;
            Result.Target.Port = Port;
            Result.identity = std::move(AuthResult.Identity);
            Result.ProtocolAuthenticated = Config_.RequireAuth;
            Result.AccountLease = std::move(AuthResult.Lease);
            Result.Transmission = Server.Release();
            if (Result.Transmission)
            {
                Result.err = Preview::Error::None;
            }
            else
            {
                Result.err = Preview::Error::IoError;
            }
            co_return Result;
        }

        [[nodiscard]] auto Name() const -> std::string_view override { return "http"; }

    private:
        HttpConfig Config_;
    };

    /**
     * @class CandidateFactory
     * @brief 创建标准协议候选及 winner-only handler resolver
     */
    class CandidateFactory
    {
    public:
        [[nodiscard]] static auto MakeHttp(CandidateOptions Options = {}, HttpConfig Config = {})
            -> CandidateBinding
        {
            auto Spec = detail::BaseSpec(std::move(Options), "http", Core::ProtocolType::Http);
            Spec.Kind = Core::CandidateKind::Cleartext;
            Spec.MinimumBytes = 1;
            Spec.FirstBytes = {'C'};
            if (Config.RequireAuth)
            {
                Spec.RequiresAuthentication = true;
                Spec.Prepare = [Config](Core::PrepareContext Context) -> Net::awaitable<Core::PrepareResult>
                {
                    const auto State = detail::InspectHttp(Context.Snapshot);
                    if (!detail::IsSuccessful(State))
                    {
                        co_return detail::NoMatch(Context.Candidate);
                    }
                    const auto Text = detail::SnapshotText(Context.Snapshot);
                    Preview::Http11::HttpRequest Request;
                    if (Preview::Http11::ParseRequest(Text, Request) != Preview::Fault::Code::Success ||
                        !Config.Authenticator)
                    {
                        co_return detail::NoMatch(Context.Candidate);
                    }
                    const auto Auth = Preview::Http11::CheckBasic(Request.authorization,
                                                                   *Config.Authenticator);
                    if (Auth.Ok)
                    {
                        co_return detail::Accepted(Context.Candidate);
                    }
                    co_return detail::NoMatch(Context.Candidate);
                };
            }
            Spec.Inspect = detail::InspectHttp;
            auto Handler = std::make_shared<HttpHandler>(std::move(Config));
            return CandidateBinding{std::move(Spec), Runtime::MakeProtocolAccept(std::move(Handler))};
        }

        [[nodiscard]] static auto MakeHttp(Core::CandidateId Id, HttpConfig Config = {})
            -> CandidateBinding
        {
            return MakeHttp(CandidateOptions{Id, {}, 0, 0, false}, std::move(Config));
        }

        [[nodiscard]] static auto MakeSocks5(CandidateOptions Options,
                                             Preview::Socks5::ServerConfig Config = {})
            -> CandidateBinding
        {
            auto Spec = detail::BaseSpec(std::move(Options), "socks5", Core::ProtocolType::Socks5);
            Spec.Kind = Core::CandidateKind::EarlyResponse;
            Spec.MinimumBytes = 2;
            Spec.FirstBytes = {Preview::Socks5::Version};
            Spec.Inspect = detail::InspectSocks5;
            auto Handler = std::make_shared<Runtime::Handler::Socks5>(std::move(Config));
            return CandidateBinding{std::move(Spec), Runtime::MakeProtocolAccept(std::move(Handler))};
        }

        [[nodiscard]] static auto MakeSocks5(Core::CandidateId Id,
                                             Preview::Socks5::ServerConfig Config = {})
            -> CandidateBinding
        {
            return MakeSocks5(CandidateOptions{Id, {}, 0, 0, false}, std::move(Config));
        }

        [[nodiscard]] static auto MakeVless(CandidateOptions Options,
                                            Preview::Vless::ServerConfig Config = {})
            -> CandidateBinding
        {
            const auto Uuid = Config.uuid;
            const auto AuthenticatorOwner = Config.AuthenticatorOwner;
            const auto *Authenticator = Config.ResolveAuthenticator();
            auto Spec = detail::BaseSpec(std::move(Options), "vless", Core::ProtocolType::Vless);
            Spec.Kind = Core::CandidateKind::Cleartext;
            Spec.RequiresAuthentication = true;
            Spec.MinimumBytes = 22;
            Spec.FirstBytes = {Preview::Vless::ProtocolVersion};
            Spec.Inspect = detail::InspectVless;
            Spec.Prepare = [Uuid, AuthenticatorOwner, Authenticator](Core::PrepareContext Context)
                -> Net::awaitable<Core::PrepareResult>
            {
                co_return detail::PrepareVless(
                    detail::VlessPrepareRequest{Context.Candidate, Uuid, Authenticator, Context.Snapshot});
            };
            auto Handler = std::make_shared<Runtime::Handler::Vless>(std::move(Config));
            return CandidateBinding{std::move(Spec), Runtime::MakeProtocolAccept(std::move(Handler))};
        }

        [[nodiscard]] static auto MakeVless(Core::CandidateId Id,
                                            Preview::Vless::ServerConfig Config = {})
            -> CandidateBinding
        {
            return MakeVless(CandidateOptions{Id, {}, 0, 0, false}, std::move(Config));
        }

        [[nodiscard]] static auto MakeTrojan(CandidateOptions Options,
                                             Preview::Trojan::ServerConfig Config = {})
            -> CandidateBinding
        {
            const auto Password = Config.password;
            const auto EnableTcp = Config.EnableTcp;
            const auto EnableUdp = Config.EnableUdp;
            const auto AuthenticatorOwner = Config.AuthenticatorOwner;
            const auto *Authenticator = Config.ResolveAuthenticator();
            const auto Credential = Preview::Trojan::Credential(Password);
            auto Spec = detail::BaseSpec(std::move(Options), "trojan", Core::ProtocolType::Trojan);
            Spec.Kind = Core::CandidateKind::Opaque;
            Spec.RequiresAuthentication = true;
            Spec.MinimumBytes = Preview::Trojan::CredentialLen + 2;
            if (Authenticator)
            {
                Spec.Fallback = true;
            }
            else
            {
                Spec.FirstBytes = {static_cast<std::uint8_t>(Credential.front())};
            }
            Spec.Inspect = detail::InspectTrojan;
            Spec.Prepare = [Password, EnableTcp, EnableUdp, AuthenticatorOwner, Authenticator](Core::PrepareContext Context)
                -> Net::awaitable<Core::PrepareResult>
            {
                co_return detail::PrepareTrojan(detail::TrojanPrepareRequest{
                    Context.Candidate, Password, EnableTcp, EnableUdp, Authenticator, Context.Snapshot});
            };
            auto Handler = std::make_shared<Runtime::Handler::Trojan>(std::move(Config));
            return CandidateBinding{std::move(Spec), Runtime::MakeProtocolAccept(std::move(Handler))};
        }

        [[nodiscard]] static auto MakeTrojan(Core::CandidateId Id,
                                             Preview::Trojan::ServerConfig Config = {})
            -> CandidateBinding
        {
            return MakeTrojan(CandidateOptions{Id, {}, 0, 0, false}, std::move(Config));
        }

        [[nodiscard]] static auto MakeVmess(CandidateOptions Options,
                                            Preview::Vmess::ServerConfig Config = {})
            -> CandidateBinding
        {
            const auto Uuid = Config.uuid;
            auto Spec = detail::BaseSpec(std::move(Options), "vmess", Core::ProtocolType::Vmess);
            Spec.Kind = Core::CandidateKind::Opaque;
            Spec.RequiresAuthentication = true;
            Spec.Fallback = true;
            Spec.MinimumBytes = 60;
            Spec.Inspect = [](const Core::ProbeSnapshot &Snapshot)
            {
                return detail::InspectOpaqueLength(Snapshot, 60);
            };
            Spec.Prepare = [Uuid](Core::PrepareContext Context) -> Net::awaitable<Core::PrepareResult>
            {
                co_return detail::PrepareVmess(Context.Candidate, Uuid, Context.Snapshot);
            };
            auto Handler = std::make_shared<Runtime::Handler::Vmess>(std::move(Config));
            return CandidateBinding{std::move(Spec), Runtime::MakeProtocolAccept(std::move(Handler))};
        }

        [[nodiscard]] static auto MakeVmess(Core::CandidateId Id,
                                            Preview::Vmess::ServerConfig Config = {})
            -> CandidateBinding
        {
            return MakeVmess(CandidateOptions{Id, {}, 0, 0, false}, std::move(Config));
        }

        [[nodiscard]] static auto MakeSs2022(CandidateOptions Options,
                                             Preview::Shadowsocks2022::ServerConfig Config = {})
            -> CandidateBinding
        {
            const auto Psk = detail::SsPsk(Config);
            const auto TimeWindow = Config.TimeWindow;
            auto Spec = detail::BaseSpec(std::move(Options), "ss2022",
                                         Core::ProtocolType::Shadowsocks);
            Spec.Kind = Core::CandidateKind::Opaque;
            Spec.RequiresAuthentication = true;
            Spec.Fallback = true;
            Spec.MinimumBytes = 43;
            Spec.Inspect = [Psk](const Core::ProbeSnapshot &Snapshot)
            {
                if (Psk)
                {
                    return detail::InspectOpaqueLength(Snapshot, 43);
                }
                return Core::MatchState::Rejected;
            };
            Spec.Prepare = [Psk, TimeWindow](Core::PrepareContext Context)
                -> Net::awaitable<Core::PrepareResult>
            {
                if (Psk)
                {
                    co_return detail::PrepareSs2022(detail::Ss2022PrepareRequest{
                        Context.Candidate, *Psk, TimeWindow, Context.Snapshot});
                }
                co_return detail::NoMatch(Context.Candidate);
            };
            if (Psk && !Config.UsePsk)
            {
                Config.UsePsk = true;
                Config.Psk = *Psk;
                Config.password.clear();
            }
            auto Handler = std::make_shared<Runtime::Handler::Ss2022>(std::move(Config));
            return CandidateBinding{std::move(Spec), Runtime::MakeProtocolAccept(std::move(Handler))};
        }

        [[nodiscard]] static auto MakeSs2022(Core::CandidateId Id,
                                             Preview::Shadowsocks2022::ServerConfig Config = {})
            -> CandidateBinding
        {
            return MakeSs2022(CandidateOptions{Id, {}, 0, 0, false}, std::move(Config));
        }

        [[nodiscard]] static auto MakeShadowsocks2022(CandidateOptions Options,
                                                       Preview::Shadowsocks2022::ServerConfig Config = {})
            -> CandidateBinding
        {
            return MakeSs2022(std::move(Options), std::move(Config));
        }

        [[nodiscard]] static auto MakeShadowsocks2022(Core::CandidateId Id,
                                                       Preview::Shadowsocks2022::ServerConfig Config = {})
            -> CandidateBinding
        {
            return MakeSs2022(Id, std::move(Config));
        }
    };

    inline auto MakeHttpCandidate(CandidateOptions Options = {}, HttpConfig Config = {})
        -> CandidateBinding
    {
        return CandidateFactory::MakeHttp(std::move(Options), std::move(Config));
    }

    inline auto MakeSocks5Candidate(CandidateOptions Options,
                                    Preview::Socks5::ServerConfig Config = {}) -> CandidateBinding
    {
        return CandidateFactory::MakeSocks5(std::move(Options), std::move(Config));
    }

    inline auto MakeVlessCandidate(CandidateOptions Options,
                                   Preview::Vless::ServerConfig Config = {}) -> CandidateBinding
    {
        return CandidateFactory::MakeVless(std::move(Options), std::move(Config));
    }

    inline auto MakeTrojanCandidate(CandidateOptions Options,
                                    Preview::Trojan::ServerConfig Config = {}) -> CandidateBinding
    {
        return CandidateFactory::MakeTrojan(std::move(Options), std::move(Config));
    }

    inline auto MakeVmessCandidate(CandidateOptions Options,
                                   Preview::Vmess::ServerConfig Config = {}) -> CandidateBinding
    {
        return CandidateFactory::MakeVmess(std::move(Options), std::move(Config));
    }

    inline auto MakeSs2022Candidate(
        CandidateOptions Options,
        Preview::Shadowsocks2022::ServerConfig Config = {}) -> CandidateBinding
    {
        return CandidateFactory::MakeSs2022(std::move(Options), std::move(Config));
    }

} // namespace Preview::Composition::Recognition
