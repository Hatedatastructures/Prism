/** @file Egress.cpp @brief 一次拥有型 UDP 解析、交换与回包实现。 */
#include <Prism/Net/Datagram/Egress.hpp>
#include <Prism/Net/Dns/Resolver.hpp>
#include <Prism/Net/DomainName.hpp>
#include <Prism/Net/Host.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <atomic>
#include <cstddef>
#include <memory>
#include <optional>
#include <system_error>
#include <tuple>
#include <utility>
#include <variant>

namespace Prism::Network
{
    struct DatagramEgress::ExchangeProgress final
    {
        std::atomic<std::size_t> Uploaded{0};
    };

    DatagramEgress::DatagramEgress(std::shared_ptr<Prism::Network::Dns::Resolver> Resolver)
        : Resolver_(std::move(Resolver))
    {
    }

    auto DatagramEgress::Exchange(Prism::Contract::DatagramExchangeRequest Request)
        -> Net::awaitable<Prism::Contract::DatagramExchangeResult>
    {
        return ExchangeOwned(Resolver_, std::move(Request));
    }

    auto DatagramEgress::ExchangeOwned(
        std::shared_ptr<Prism::Network::Dns::Resolver> ResolverOwner,
        Prism::Contract::DatagramExchangeRequest Request)
        -> Net::awaitable<Prism::Contract::DatagramExchangeResult>
    {
        const auto Executor = co_await Net::this_coro::executor;
        auto Progress = std::make_shared<ExchangeProgress>();
        Net::steady_timer Deadline(Executor);
        Deadline.expires_after(Request.Timeout);

        try
        {
            using Net::experimental::awaitable_operators::operator||;
            auto Outcome = co_await (
                ExchangeCore(std::move(ResolverOwner), std::move(Request), Progress) ||
                Deadline.async_wait(Net::use_awaitable));
            if (Outcome.index() == 1U)
            {
                Prism::Contract::DatagramExchangeResult Result;
                Result.Failure = Prism::Fault::Failure{Prism::Fault::Code::Timeout, {}};
                Result.Uploaded = Progress->Uploaded.load(std::memory_order_acquire);
                co_return Result;
            }
            co_return std::move(std::get<0>(Outcome));
        }
        catch (const boost::system::system_error &Error)
        {
            Prism::Contract::DatagramExchangeResult Result;
            Result.Failure = Prism::Fault::FromNative(static_cast<std::error_code>(Error.code()));
            Result.Uploaded = Progress->Uploaded.load(std::memory_order_acquire);
            co_return Result;
        }
        catch (const std::system_error &Error)
        {
            Prism::Contract::DatagramExchangeResult Result;
            Result.Failure = Prism::Fault::FromNative(Error.code());
            Result.Uploaded = Progress->Uploaded.load(std::memory_order_acquire);
            co_return Result;
        }
    }

    auto DatagramEgress::ExchangeCore(
        std::shared_ptr<Prism::Network::Dns::Resolver> ResolverOwner,
        Prism::Contract::DatagramExchangeRequest Request,
        const std::shared_ptr<ExchangeProgress> &Progress)
        -> Net::awaitable<Prism::Contract::DatagramExchangeResult>
    {
        if (Request.Target.Host.Empty() || Request.Target.Port == 0U)
        {
            co_return Prism::Contract::DatagramExchangeResult{
                .Failure = Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument, {}}};
        }

        const auto Literal = Prism::Network::IpAddress(Request.Target.Host);
        std::optional<Net::ip::address> Address;
        if (Literal)
        {
            Address = *Literal;
        }
        else if (ResolverOwner)
        {
            const auto *Domain = std::get_if<Prism::Network::DomainName>(
                &Request.Target.Host.Get());
            if (Domain == nullptr)
            {
                co_return Prism::Contract::DatagramExchangeResult{
                    .Failure = Prism::Fault::Failure{
                        Prism::Fault::Code::UnsupportedAddress, {}}};
            }
            const auto Addresses = co_await ResolverOwner->AsyncResolve(Domain->View());
            if (!Addresses)
            {
                co_return Prism::Contract::DatagramExchangeResult{
                    .Failure = Addresses.error()};
            }
            if (!Addresses->Empty())
            {
                Address = (*Addresses)[0];
            }
        }
        if (!Address)
        {
            co_return Prism::Contract::DatagramExchangeResult{
                .Failure = Prism::Fault::Failure{Prism::Fault::Code::DnsFailed, {}}};
        }

        const Net::ip::udp::endpoint Target(*Address, Request.Target.Port);
        const auto Executor = co_await Net::this_coro::executor;
        Net::ip::udp::socket Socket(Executor);
        boost::system::error_code ErrorValue;
        Socket.open(Target.protocol(), ErrorValue);
        if (ErrorValue)
        {
            co_return Prism::Contract::DatagramExchangeResult{
                .Failure = Prism::Fault::FromNative(static_cast<std::error_code>(ErrorValue))};
        }

        Prism::Contract::DatagramExchangeResult Result;
        Result.Failure = {};
        Result.Uploaded = co_await Socket.async_send_to(
            Net::buffer(Request.Payload), Target,
            Net::redirect_error(Net::use_awaitable, ErrorValue));
        Progress->Uploaded.store(Result.Uploaded, std::memory_order_release);
        if (ErrorValue)
        {
            Result.Failure = Prism::Fault::FromNative(static_cast<std::error_code>(ErrorValue));
            co_return Result;
        }

        Result.Payload.resize(65535U);
        for (;;)
        {
            const auto Received = co_await Socket.async_receive_from(
                Net::buffer(Result.Payload), Result.Source,
                Net::redirect_error(Net::use_awaitable, ErrorValue));
            if (ErrorValue)
            {
                Result.Failure = Prism::Fault::FromNative(
                    static_cast<std::error_code>(ErrorValue));
                Result.Payload.clear();
                co_return Result;
            }
            if (Result.Source != Target)
            {
                continue;
            }
            Result.Payload.resize(Received);
            co_return Result;
        }
    }
}
