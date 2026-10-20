/** @file Anytls.cpp @brief AnyTLS 握手工厂与失败退休实现。 */
#include <Prism/Protocols/Anytls/Anytls.hpp>

#include <Prism/Protocols/Anytls/Detail/Session/Retirement.hpp>
#include <Prism/Protocols/Anytls/Detail/Session/Session.hpp>
#include <Prism/Protocols/Anytls/Detail/Session/State.hpp>

#include <boost/system/system_error.hpp>

#include <exception>
#include <memory>
#include <new>
#include <system_error>
#include <utility>

namespace Prism::Anytls::Detail
{

    auto PreserveNative(Prism::Fault::Failure& Primary,
        const Prism::Fault::Failure& Cleanup) noexcept -> void
    {
        if (!Primary.Native && Cleanup.Native)
        {
            Primary.Native = Cleanup.Native;
        }
    }

    auto RetireConstructionFailure(
        const std::shared_ptr<TransportRetirement>& Retirement,
        const SharedTransmission& Upstream,
        Prism::Fault::Failure Primary) -> Net::awaitable<Prism::Fault::Failure>
    {
        auto Transport = Upstream;
        const auto Attached = Retirement->Attach(
            std::move(Transport), Prism::Account::StreamLease{});
        if (!Attached)
        {
            PreserveNative(Primary, Attached.error());
            co_return Primary;
        }

        Retirement->RetainForRetry();
        try
        {
            const auto Retired = co_await Retirement->RetireAndDrain();
            if (!Retired)
            {
                PreserveNative(Primary, Retired.error());
            }
        }
        catch (...)
        {
            Retirement->RequestRetirement();
            PreserveNative(Primary, FailureFromException(std::current_exception()));
        }
        co_return Primary;
    }

    auto AcceptWithRetirement(SharedTransmission Upstream,
        const ServerConfig& Config,
        const std::shared_ptr<TransportRetirement>& Retirement)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>
    {
        if (!Upstream || !Retirement)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }

        SharedConn Connection;
        std::exception_ptr ConstructionFailure;
        try
        {
            Connection = std::make_shared<Conn<>>(Upstream, Config.Password);
        }
        catch (...)
        {
            ConstructionFailure = std::current_exception();
        }
        if (ConstructionFailure)
        {
            const auto Failure = co_await RetireConstructionFailure(
                Retirement, Upstream, FailureFromException(ConstructionFailure));
            co_return std::unexpected(Failure);
        }

        auto Attached = Retirement->Attach(
            std::static_pointer_cast<Prism::Transmission>(Connection),
            Prism::Account::StreamLease{});
        if (!Attached)
        {
            co_return std::unexpected(Attached.error());
        }
        Upstream.reset();

        std::expected<void, Prism::Fault::Failure> Handshake;
        try
        {
            Handshake = co_await Connection->ReadHandshake();
        }
        catch (...)
        {
            Handshake = std::unexpected(FailureFromException(std::current_exception()));
        }
        if (!Handshake)
        {
            auto Failure = Handshake.error();
            Retirement->RetainForRetry();
            try
            {
                const auto Retired = co_await Retirement->RetireAndDrain();
                if (!Retired)
                {
                    PreserveNative(Failure, Retired.error());
                }
            }
            catch (...)
            {
                Retirement->RequestRetirement();
                PreserveNative(Failure, FailureFromException(std::current_exception()));
            }
            co_return std::unexpected(Failure);
        }
        co_return Connection;
    }

} // namespace Prism::Anytls::Detail

namespace Prism::Anytls
{

    auto Connect(SharedTransmission Upstream, const ClientConfig& Config)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>
    {
        if (!Upstream)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto Prepared = Detail::TransportRetirement::Prepare();
        if (!Prepared)
        {
            co_return std::unexpected(Prepared.error());
        }
        auto Retirement = std::move(*Prepared);
        SharedConn Connection;
        std::exception_ptr ConstructionFailure;
        try
        {
            Connection = std::make_shared<Conn<>>(Upstream, Config.Password);
        }
        catch (...)
        {
            ConstructionFailure = std::current_exception();
        }
        if (ConstructionFailure)
        {
            auto Failure = co_await Detail::RetireConstructionFailure(
                Retirement, Upstream, Detail::FailureFromException(ConstructionFailure));
            co_return std::unexpected(Failure);
        }

        auto Attached = Retirement->Attach(
            std::static_pointer_cast<Prism::Transmission>(Connection),
            Prism::Account::StreamLease{});
        if (!Attached)
        {
            co_return std::unexpected(Attached.error());
        }
        Upstream.reset();

        std::expected<void, Prism::Fault::Failure> Handshake;
        try
        {
            Handshake = co_await Connection->WriteHandshake();
        }
        catch (...)
        {
            Handshake = std::unexpected(
                Detail::FailureFromException(std::current_exception()));
        }
        if (!Handshake)
        {
            auto Failure = Handshake.error();
            Retirement->RetainForRetry();
            try
            {
                const auto Retired = co_await Retirement->RetireAndDrain();
                if (!Retired)
                {
                    Detail::PreserveNative(Failure, Retired.error());
                }
            }
            catch (...)
            {
                Retirement->RequestRetirement();
                Detail::PreserveNative(Failure,
                    Detail::FailureFromException(std::current_exception()));
            }
            co_return std::unexpected(Failure);
        }
        co_return Connection;
    }

    auto Accept(SharedTransmission Upstream, const ServerConfig& Config)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>
    {
        if (!Upstream)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto Prepared = Detail::TransportRetirement::Prepare();
        if (!Prepared)
        {
            co_return std::unexpected(Prepared.error());
        }
        co_return co_await Detail::AcceptWithRetirement(
            std::move(Upstream), Config, *Prepared);
    }

} // namespace Prism::Anytls
