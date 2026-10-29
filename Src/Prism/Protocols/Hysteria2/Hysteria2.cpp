/**
 * @file Hysteria2.cpp
 * @brief Hysteria2 流连接与数据报连接工厂实现。
 */

#include <Prism/Protocols/Hysteria2/Hysteria2.hpp>
#include <Prism/Protocols/Quic/Datagram/Adapter.hpp>
#include <Prism/Transport/Unreliable.hpp>

#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <expected>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

namespace Prism::Hysteria2
{

    auto Connect(
        SharedTransmission Upstream,
        const ClientConfig &Config,
        const Address &Target) -> Net::awaitable<std::pair<Error, SharedConn>>
    {
        if (!Upstream)
        {
            co_return std::pair{Error::NotOpen, SharedConn{}};
        }
        auto Connection = std::make_shared<Conn<>>(std::move(Upstream), Config.password);
        const auto ErrorCode = co_await Connection->WriteHandshake(Target);
        SharedConn Result;
        if (ErrorCode == Error::None)
        {
            Result = SharedConn(std::move(Connection));
        }
        else
        {
            Result = SharedConn{};
        }
        co_return std::pair{ErrorCode, std::move(Result)};
    }

    auto ConnectPacket(
        Net::any_io_executor Executor,
        std::string Remote,
        ClientConfig Config)
        -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>
    {
        (void)Config;
        auto Datagram = std::make_shared<Prism::Transport::Unreliable>(Executor);
        co_await Net::dispatch(Datagram->Executor(), Net::use_awaitable);
        const auto Connected = Datagram->Connect(Remote);
        if (!Connected)
        {
            const auto Failure = Connected.error();
            (void)Datagram->Close();
            const auto Activity = Datagram->Activity();
            (void)co_await Activity->Drain();
            co_return std::unexpected(Failure);
        }
        co_return SharedDgram{std::make_shared<Dgram<>>(std::move(Datagram))};
    }

    auto ConnectPacket(
        Prism::Quic::SharedDatagramProvider Provider,
        const ClientConfig &Config) -> std::expected<SharedDgram, Prism::Fault::Failure>
    {
        (void)Config;
        if (!Provider)
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        auto Transport = std::make_shared<Prism::Quic::DatagramAdapter>(std::move(Provider));
        return SharedDgram{std::make_shared<Dgram<>>(std::move(Transport), true)};
    }

    auto Accept(
        SharedTransmission Upstream,
        const ServerConfig &Config)
        -> Net::awaitable<std::tuple<Error, Message, SharedConn>>
    {
        if (!Upstream)
        {
            co_return std::tuple{Error::NotOpen, Message{}, SharedConn{}};
        }
        auto Connection = std::make_shared<Conn<>>(
            std::move(Upstream),
            Config.password,
            Config.AuthenticatorOwner);
        auto [ErrorCode, Request] = co_await Connection->ReadHandshake();
        SharedConn Result;
        if (ErrorCode == Error::None)
        {
            Result = SharedConn(std::move(Connection));
        }
        else
        {
            Result = SharedConn{};
        }
        co_return std::tuple{ErrorCode, std::move(Request), std::move(Result)};
    }

    auto AcceptPacket(
        Net::any_io_executor Executor,
        unsigned short Port,
        ServerConfig Config)
        -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>
    {
        (void)Config;
        auto Datagram = std::make_shared<Prism::Transport::Unreliable>(Executor);
        co_await Net::dispatch(Datagram->Executor(), Net::use_awaitable);
        const auto Bound = Datagram->Bind(Port);
        if (!Bound)
        {
            const auto Failure = Bound.error();
            (void)Datagram->Close();
            const auto Activity = Datagram->Activity();
            (void)co_await Activity->Drain();
            co_return std::unexpected(Failure);
        }
        Datagram->AllowAnyPeer();
        co_return SharedDgram{std::make_shared<Dgram<>>(std::move(Datagram))};
    }

    auto AcceptPacket(
        Prism::Quic::SharedDatagramProvider Provider,
        const ServerConfig &Config) -> std::expected<SharedDgram, Prism::Fault::Failure>
    {
        (void)Config;
        if (!Provider)
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        auto Transport = std::make_shared<Prism::Quic::DatagramAdapter>(std::move(Provider));
        return SharedDgram{std::make_shared<Dgram<>>(std::move(Transport), true)};
    }

} // namespace Prism::Hysteria2
