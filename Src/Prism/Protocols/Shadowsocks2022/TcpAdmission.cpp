/** @file TcpAdmission.cpp @brief SS2022 TCP admission 与目标投影实现。 */
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Protocols/Shadowsocks2022/TcpAdmission.hpp>
#include <Prism/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Prism/Transport/Replay.hpp>

#include "Detail/Target.hpp"

#include <boost/asio/buffer.hpp>
#include <string>
#include <system_error>
#include <utility>

namespace Prism::Shadowsocks2022
{

    namespace Detail
    {
        [[nodiscard]] static auto FailureForWireError(const Prism::Error Value)
            -> Prism::Fault::Failure
        {
            return {Prism::Fault::Detail::MapProtocolCategoryValue(static_cast<int>(Value)), {}};
        }
        [[nodiscard]] static auto IsRetryableAuthenticationFailure(
            const Prism::Fault::Failure &Failure) noexcept -> bool
        {
            if (Failure.Code != Prism::Fault::Code::AuthFailed) return false;
            if (!Failure.Native) return true;
            static const auto &ProtocolCategory =
                static_cast<const std::error_category &>(Prism::ErrorCategory());
            return &Failure.Native.category() == &ProtocolCategory &&
                Failure.Native.value() == static_cast<int>(Prism::Error::BadAuth);
        }
    }

    [[nodiscard]] auto InspectTcp(const Prepared& Value, std::span<const std::byte> Bytes)
        -> Prism::Error
    {
        bool More = false;
        for (const auto& Credential : Value.Credentials)
        {
            Parser Candidate(WireKey(Credential));
            std::error_code ErrorValue;
            Candidate.Put(Net::const_buffer(Bytes.data(), Bytes.size()), ErrorValue);
            More |= ErrorValue == Prism::make_error_code(Prism::Error::NeedMore);
            if (!ErrorValue && Candidate.IsDone() &&
                Candidate.IsTimestampFresh(Value.Input.Config.TimeWindow))
                return Prism::Error::None;
        }
        return More ? Prism::Error::NeedMore : Prism::Error::BadAuth;
    }

    auto AcceptTcp(TcpIngress Input, const Prepared& Value)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        if (!Input.Bytes)
        {
            co_return co_await Input.Admission.Reject(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto Created = Prism::Transport::ReplayTransmission::Create(Input.Inbound,
            Prism::Transport::ReplayOptions{64U * 1024U,
                Prism::Transport::ReplayMode::Candidate, std::move(Input.Bytes)});
        if (!Created)
        {
            co_return co_await Input.Admission.Reject(Created.error());
        }
        auto Replay = std::move(*Created);
        if (const auto Tracked = Input.Admission.Track(Replay); !Tracked)
        {
            co_return co_await Input.Admission.Reject(Tracked.error());
        }
        Replay->EnableWrites();
        for (const auto& Credential : Value.Credentials)
        {
            ServerConfig Config;
            Config.Psk = WireKey(Credential);
            Config.TimeWindow = Value.Input.Config.TimeWindow;
            Config.Authenticator = Value.Services.Authentication.Authenticator;
            auto Accepted = co_await Prism::Shadowsocks2022::Accept(Replay, Config);
            if (!Accepted)
            {
                const auto Failure = Accepted.error();
                if (Detail::IsRetryableAuthenticationFailure(Failure))
                {
                    const auto Rewound = Replay->Rewind();
                    if (Rewound)
                    {
                        continue;
                    }
                    co_return co_await Input.Admission.Reject(Rewound.error());
                }
                co_return co_await Input.Admission.Reject(Failure);
            }

            auto Request = std::move(Accepted->Request);
            auto Connection = std::move(Accepted->Connection);
            if (!Connection)
            {
                co_return co_await Input.Admission.Reject(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            if (const auto TrackedConnection = Input.Admission.Track(Connection);
                !TrackedConnection)
            {
                co_return co_await Input.Admission.Reject(TrackedConnection.error());
            }
            Replay->Commit();
            Prism::Contract::ProtocolDataPlane Plane;
            Plane.Protocol = Prism::Contract::ProtocolType::Shadowsocks;
            auto Target = Detail::ToNetworkTarget(Request.dst);
            if (!Target)
            {
                co_return co_await Input.Admission.Reject(std::move(Plane), Target.error());
            }
            Plane.Target = std::move(*Target);
            Plane.ProtocolAuthenticated = true;
            Plane.AccountId = Connection->AccountId();
            Plane.Identity = std::string(Connection->Identity());
            Plane.AccountLease = Connection->TakeAuthLease();
            if (Input.Mux)
            {
                Plane.Root = Prism::Contract::MuxRootDataPlane{Connection, {}};
                const auto UseState = Input.Mux->GenerationUseState();
                if (!UseState)
                {
                    co_return co_await Input.Admission.Reject(std::move(Plane),
                        Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
                }
                auto CreateRequest = Prism::Contract::MuxRootCreateRequest::Prepare(
                    Input.Admission.RootCreateOwner(), UseState, std::move(Plane));
                if (!CreateRequest)
                {
                    if (Plane.HasTransport())
                    {
                        co_return co_await Input.Admission.Reject(
                            std::move(Plane), CreateRequest.error());
                    }
                    co_return std::unexpected(CreateRequest.error());
                }
                auto CreatedRoot = Input.Mux->Create(std::move(*CreateRequest));
                if (!CreatedRoot)
                {
                    co_return std::unexpected(CreatedRoot.error());
                }
                Plane = std::move(CreatedRoot->Plane);
            }
            else
            {
                Plane.Root = Prism::Contract::StreamDataPlane{std::move(Connection)};
            }
            co_return co_await Input.Admission.Admit(std::move(Plane));
        }
        co_return co_await Input.Admission.Reject(
            Detail::FailureForWireError(Prism::Error::BadAuth));
    }

} // namespace Prism::Shadowsocks2022
