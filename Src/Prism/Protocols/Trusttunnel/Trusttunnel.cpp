/**
 * @file Trusttunnel.cpp
 * @brief TrustTunnel 流与数据报工厂实现。
 */
#include <Prism/Protocols/Trusttunnel/Trusttunnel.hpp>

#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Utility/Crypto/Base64.hpp>
#include <Prism/Protocols/Trusttunnel/Codec.hpp>
#include <Prism/Protocols/Trusttunnel/Binding.hpp>
#include <Prism/Protocols/Trusttunnel/Types.hpp>
#include <Prism/Protocols/Trusttunnel/TransportTypes.hpp>
#include <Prism/Protocols/Trusttunnel/Transport/Activity.hpp>

#include <boost/asio/this_coro.hpp>

#include <exception>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace Prism::Trusttunnel::Detail
{
    ForwardedActivity::ForwardedActivity(
        std::shared_ptr<Prism::Contract::CarrierActivity> Front,
        std::shared_ptr<Prism::Contract::CarrierActivity> Child,
        std::shared_ptr<Prism::Contract::CarrierCloseReceipt> Receipt)
        : State_(std::make_shared<State>(
              std::move(Front), std::move(Child), std::move(Receipt)))
    {
    }

    auto ForwardedActivity::ReleaseChild() noexcept -> void
    {
        State_->Child.reset();
    }

    auto ForwardedActivity::Seal() noexcept -> void
    {
        State_->Front->Seal();
    }

    auto ForwardedActivity::Drain()
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        return DrainState(State_);
    }

    auto ForwardedActivity::DrainState(std::shared_ptr<State> Value)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await boost::asio::this_coro::throw_if_cancelled(false);
        co_await boost::asio::this_coro::reset_cancellation_state(
            boost::asio::disable_cancellation());
        Value->Front->Seal();

        const auto CloseDispatch = co_await Value->Receipt->AwaitCloseDispatch();
        if (!CloseDispatch)
        {
            co_return std::unexpected(CloseDispatch.error());
        }

        auto FirstFailure = Prism::Fault::Failure{};
        if (Value->Child)
        {
            // 子层由其自身 Close 在提交关闭预约后封止；此处直接 Drain，
            // 避免在子层 close handler 转交更深层之前递归抢先封止。
            const auto Child = co_await Value->Child->Drain();
            if (!Child) FirstFailure = Child.error();
            if (!Value->Child->IsRetired())
            {
                if (FirstFailure.Succeeded())
                    FirstFailure = {Prism::Fault::Code::Blocked};
                co_return std::unexpected(FirstFailure);
            }
        }

        Value->Receipt->ConfirmExternalClose();
        const auto Receipt = co_await Value->Receipt->Drain();
        if (!Receipt && FirstFailure.Succeeded()) FirstFailure = Receipt.error();
        const auto Front = co_await Value->Front->Drain();
        if (!Front && FirstFailure.Succeeded()) FirstFailure = Front.error();
        if (!Value->Front->IsRetired() && FirstFailure.Succeeded())
            FirstFailure = {Prism::Fault::Code::Blocked};
        if (FirstFailure.Failed()) co_return std::unexpected(FirstFailure);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }
}

namespace Prism::Trusttunnel
{
    Binding::Binding(PreparedBinding Prepared)
        : Instance(std::move(Prepared.Instance)),
          NativeTls(std::move(Prepared.NativeTls)),
          Wire(std::move(Prepared.Wire))
    {
    }

    auto Binding::Close() const noexcept -> void
    {
        Closed_.store(true, std::memory_order_release);
    }

    auto Binding::IsRetired() const noexcept -> bool
    {
        return Closed_.load(std::memory_order_acquire);
    }

    [[nodiscard]] auto PrepareAccountCredential(std::string_view Value)
        -> Prism::Account::Credential
    {
        return Prism::Account::Credential::Password(Value);
    }

    [[nodiscard]] auto BindProvider(PreparedBinding Prepared)
        -> std::shared_ptr<const Binding>
    {
        return std::make_shared<const Binding>(std::move(Prepared));
    }

    auto ParseServerCredential(std::string_view Credential)
        -> std::expected<ServerConfig, Prism::Contract::ProviderFailure>
    {
        const auto Separator = Credential.find(':');
        if (Separator == std::string_view::npos || Separator == 0U || Separator + 1U >= Credential.size())
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::InvalidCredential, {}, "Authentication.Credential"});
        }
        return ServerConfig{std::string(Credential.substr(0, Separator)),
            std::string(Credential.substr(Separator + 1U))};
    }

    auto PrepareProviderBinding(
        std::string Instance,
        Prism::Contract::AuthenticationServices Authentication,
        std::shared_ptr<boost::asio::ssl::context> NativeTls)
        -> std::expected<PreparedBinding, Prism::Contract::ProviderFailure>
    {
        if (!NativeTls)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::MissingTls, {}, "NativeTls"});
        }
        if (!Authentication.Generation || !Authentication.Authenticator || !Authentication.Credentials)
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::MissingAuthentication, {}, "Authentication"});
        }
        std::string Credential;
        const auto Enumerated = Authentication.Credentials.ForEachCredential(
            Prism::Account::CredentialKind::Password,
            [&Credential](const std::shared_ptr<const Prism::Account::AccountBinding>&,
                          const Prism::Account::CredentialMaterial& Material)
            {
                if (!Credential.empty()) return;
                const auto Bytes = Material.Credential.View().Bytes();
                Credential.assign(reinterpret_cast<const char*>(Bytes.data()), Bytes.size());
            });
        if (!Enumerated || Credential.empty())
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::InvalidCredential, {}, "Authentication.Credential"});
        }
        auto Configuration = ParseServerCredential(Credential);
        if (!Configuration) return std::unexpected(Configuration.error());
        auto Wire = MakeWireAuthBinding(std::move(*Configuration), std::move(Authentication.Authenticator));
        return PreparedBinding{std::move(Instance), std::move(NativeTls), std::move(Wire)};
    }

    auto BasicAuth(std::string_view Username, std::string_view Password) -> std::string
    {
        const std::string Raw = std::string(Username) + ":" + std::string(Password);
        std::string Encoded;
        Encoded.reserve((Raw.size() + 2) / 3 * 4);
        std::size_t Index = 0;
        for (; Index + 2 < Raw.size(); Index += 3)
        {
            const auto Value = static_cast<std::uint32_t>(static_cast<std::uint8_t>(Raw[Index])) << 16 |
                               static_cast<std::uint32_t>(static_cast<std::uint8_t>(Raw[Index + 1])) << 8 |
                               static_cast<std::uint8_t>(Raw[Index + 2]);
            Encoded.push_back(base64_table[(Value >> 18) & 0x3F]);
            Encoded.push_back(base64_table[(Value >> 12) & 0x3F]);
            Encoded.push_back(base64_table[(Value >> 6) & 0x3F]);
            Encoded.push_back(base64_table[Value & 0x3F]);
        }
        if (Index + 1 == Raw.size())
        {
            const auto Value = static_cast<std::uint32_t>(static_cast<std::uint8_t>(Raw[Index])) << 16;
            Encoded.push_back(base64_table[(Value >> 18) & 0x3F]);
            Encoded.push_back(base64_table[(Value >> 12) & 0x3F]);
            Encoded.push_back('=');
            Encoded.push_back('=');
        }
        else if (Index + 2 == Raw.size())
        {
            const auto Value = static_cast<std::uint32_t>(static_cast<std::uint8_t>(Raw[Index])) << 16 |
                               static_cast<std::uint32_t>(static_cast<std::uint8_t>(Raw[Index + 1])) << 8;
            Encoded.push_back(base64_table[(Value >> 18) & 0x3F]);
            Encoded.push_back(base64_table[(Value >> 12) & 0x3F]);
            Encoded.push_back(base64_table[(Value >> 6) & 0x3F]);
            Encoded.push_back('=');
        }
        return std::string(BasicPrefix) + Encoded;
    }

    auto ParseBasicAuth(
        std::string_view Authorization,
        std::string &Username,
        std::string &Password) -> bool
    {
        if (Authorization.size() < BasicPrefix.size() ||
            Authorization.substr(0, BasicPrefix.size()) != BasicPrefix)
        {
            return false;
        }
        const auto Encoded = Authorization.substr(BasicPrefix.size());
        if (Encoded.empty())
        {
            return false;
        }

        const auto Raw = Prism::Crypto::Base64Decode(Encoded);
        if (Raw.empty())
        {
            return false;
        }
        const auto Canonical = Prism::Crypto::Base64Encode(
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Raw.data()),
                Raw.size()));
        if (Canonical != Encoded)
        {
            return false;
        }
        const auto Colon = Raw.find(':');
        if (Colon == std::string::npos)
        {
            return false;
        }
        Username = Raw.substr(0, Colon);
        Password = Raw.substr(Colon + 1);
        return true;
    }

    auto VerifyBasicAuth(
        std::string_view Authorization,
        std::string_view ExpectUser,
        std::string_view ExpectPass) -> bool
    {
        std::string Username;
        std::string Password;
        if (!ParseBasicAuth(Authorization, Username, Password))
        {
            return false;
        }
        const auto UserMatches = Prism::ConstantTimeEqual(Username, ExpectUser);
        const auto PasswordMatches = Prism::ConstantTimeEqual(Password, ExpectPass);
        return UserMatches && PasswordMatches;
    }

    auto Connect(ConnectParameters Parameters)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>
    {
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Parameters.Upstream);
        if (!Prepared)
        {
            co_return std::unexpected(Prepared.error());
        }
        auto Admission = std::move(*Prepared);
        std::exception_ptr Fatal;
        try
        {
            auto Created = Detail::Conn<>::Create(ConnRequest{
                std::move(Parameters.Upstream),
                Parameters.Configuration.username,
                Parameters.Configuration.password});
            if (!Created)
            {
                co_return std::unexpected(co_await Admission.Retire(Created.error()));
            }
            auto Connection = std::move(*Created);
            auto Tracked = Admission.Track(
                std::static_pointer_cast<Prism::Transmission>(Connection));
            if (!Tracked)
            {
                co_return std::unexpected(co_await Admission.Retire(Tracked.error()));
            }
            const auto Handshake = co_await Connection->WriteHandshake(
                Parameters.Target, Parameters.Port);
            if (!Handshake)
            {
                co_return std::unexpected(co_await Admission.Retire(Handshake.error()));
            }
            Admission.Release();
            co_return Connection;
        }
        catch (const std::bad_alloc &)
        {
            Fatal = std::current_exception();
        }
        co_return std::unexpected(co_await Admission.Retire(
            Prism::Contract::InboundAdmission::ExceptionFailure(std::move(Fatal))));
    }

    auto ConnectPacket(ConnectParameters Parameters)
        -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>
    {
        auto Connected = co_await Connect(std::move(Parameters));
        if (!Connected)
        {
            co_return std::unexpected(Connected.error());
        }
        auto Connection = std::move(*Connected);
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(
            std::static_pointer_cast<Prism::Transmission>(Connection));
        if (!Prepared)
        {
            co_return std::unexpected(Prepared.error());
        }
        auto Admission = std::move(*Prepared);
        std::exception_ptr Fatal;
        try
        {
            auto Created = Dgram::Create(
                DgramRequest{std::static_pointer_cast<Prism::Transmission>(Connection)});
            if (!Created)
            {
                co_return std::unexpected(co_await Admission.Retire(Created.error()));
            }
            auto Tracked = Admission.Track(
                std::static_pointer_cast<Prism::Transmission>(*Created));
            if (!Tracked)
            {
                co_return std::unexpected(co_await Admission.Retire(Tracked.error()));
            }
            Connection.reset();
            Admission.Release();
            co_return SharedDgram(std::move(*Created));
        }
        catch (const std::bad_alloc &)
        {
            Fatal = std::current_exception();
        }
        co_return std::unexpected(co_await Admission.Retire(
            Prism::Contract::InboundAdmission::ExceptionFailure(std::move(Fatal))));
    }

    auto Accept(SharedTransmission Upstream, ServerConfig Configuration)
        -> Net::awaitable<std::expected<AcceptedConnection, Prism::Fault::Failure>>
    {
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Upstream);
        if (!Prepared)
        {
            co_return std::unexpected(Prepared.error());
        }
        auto Admission = std::move(*Prepared);
        std::exception_ptr Fatal;
        try
        {
            auto Created = Detail::Conn<>::Create(ConnRequest{
                std::move(Upstream), Configuration.username, Configuration.password});
            if (!Created)
            {
                co_return std::unexpected(co_await Admission.Retire(Created.error()));
            }
            auto Connection = std::move(*Created);
            auto Tracked = Admission.Track(
                std::static_pointer_cast<Prism::Transmission>(Connection));
            if (!Tracked)
            {
                co_return std::unexpected(co_await Admission.Retire(Tracked.error()));
            }
            std::string Target;
            const auto Handshake = co_await Connection->ReadHandshake(Target);
            if (!Handshake)
            {
                co_return std::unexpected(co_await Admission.Retire(Handshake.error()));
            }
            Admission.Release();
            co_return AcceptedConnection{std::move(Target), std::move(Connection)};
        }
        catch (const std::bad_alloc &)
        {
            Fatal = std::current_exception();
        }
        co_return std::unexpected(co_await Admission.Retire(
            Prism::Contract::InboundAdmission::ExceptionFailure(std::move(Fatal))));
    }

    auto AcceptPacket(SharedTransmission Upstream, ServerConfig Configuration)
        -> Net::awaitable<std::expected<AcceptedDatagram, Prism::Fault::Failure>>
    {
        auto Accepted = co_await Accept(std::move(Upstream), std::move(Configuration));
        if (!Accepted)
        {
            co_return std::unexpected(Accepted.error());
        }
        auto Result = std::move(*Accepted);
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(
            std::static_pointer_cast<Prism::Transmission>(Result.Connection));
        if (!Prepared)
        {
            co_return std::unexpected(Prepared.error());
        }
        auto Admission = std::move(*Prepared);
        std::exception_ptr Fatal;
        try
        {
            auto Created = Dgram::Create(
                DgramRequest{std::static_pointer_cast<Prism::Transmission>(Result.Connection)});
            if (!Created)
            {
                co_return std::unexpected(co_await Admission.Retire(Created.error()));
            }
            auto Tracked = Admission.Track(
                std::static_pointer_cast<Prism::Transmission>(*Created));
            if (!Tracked)
            {
                co_return std::unexpected(co_await Admission.Retire(Tracked.error()));
            }
            Result.Connection.reset();
            Admission.Release();
            co_return AcceptedDatagram{
                std::move(Result.Target), SharedDgram(std::move(*Created))};
        }
        catch (const std::bad_alloc &)
        {
            Fatal = std::current_exception();
        }
        co_return std::unexpected(co_await Admission.Retire(
            Prism::Contract::InboundAdmission::ExceptionFailure(std::move(Fatal))));
    }
}
