/**
 * @file TuicFactory.hpp
 * @brief Native QUIC 到 TUIC v5 uni-auth/bidi/datagram callback 的接线。
 */
#pragma once

#include <Preview/Ingress/QuicAdmissionContext.hpp>
#include <Preview/Protocols/Quic/Native.hpp>
#include <Preview/Protocols/Quic/StreamAdapter.hpp>
#include <Preview/Protocols/Tuic/Tuic.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <functional>
#include <memory>
#include <string>
#include <utility>

namespace Preview::Composition::Quic
{

    namespace Net = boost::asio;

    namespace detail
    {

        struct TuicState final
        {
            explicit TuicState(Net::any_io_executor ExecutorValue)
                : Executor(std::move(ExecutorValue)), Ready(Executor, 8)
            {
            }

            Net::any_io_executor Executor;
            Net::experimental::channel<void(boost::system::error_code)> Ready;
            Preview::Quic::SharedStreamProvider AuthProvider;
            Preview::SharedTransmission AuthStream;
            Preview::Tuic::KeyingMaterialExporter Exporter;
            Preview::Tuic::ServerConfig Config;
            bool Closed{false};
            bool Authenticated{false};
            Preview::AccountId AccountId{};
            std::string Identity;
        };

        inline auto Notify(const std::shared_ptr<TuicState> &State) -> void
        {
            (void)State->Ready.try_send(boost::system::error_code{});
        }

        [[nodiscard]] inline auto WaitForAuthMaterial(
            const std::shared_ptr<TuicState> &State) -> Net::awaitable<bool>
        {
            while (!State->Closed && (!State->AuthStream || !State->Exporter))
            {
                boost::system::error_code Error;
                co_await State->Ready.async_receive(
                    Net::redirect_error(Net::use_awaitable, Error));
                if (Error)
                {
                    co_return false;
                }
            }
            co_return !State->Closed && static_cast<bool>(State->AuthStream) &&
                      static_cast<bool>(State->Exporter);
        }

        [[nodiscard]] inline auto AcceptBidi(
            const std::shared_ptr<TuicState> &State,
            Preview::Quic::SharedStreamProvider Provider,
            const std::function<Net::awaitable<void>(Preview::Tuic::Message,
                                                      Preview::Tuic::SharedConn)> &Handler)
            -> Net::awaitable<void>
        {
            if (!Provider || !Handler)
            {
                co_return;
            }
            auto Transport = std::make_shared<Preview::Quic::StreamAdapter>(
                Provider->Executor(), Provider);
            Preview::Tuic::SharedConn Connection;
            Preview::Tuic::Message Message;
            Preview::Error ErrorCode = Preview::Error::None;
            if (!State->Authenticated)
            {
                if (!co_await WaitForAuthMaterial(State))
                {
                    Transport->Close();
                    co_return;
                }
                State->Config.AuthStream = State->AuthStream;
                State->Config.Exporter = State->Exporter;
                auto Accepted = co_await Preview::Tuic::Accept(Transport, State->Config);
                ErrorCode = std::get<0>(Accepted);
                Message = std::move(std::get<1>(Accepted));
                Connection = std::move(std::get<2>(Accepted));
                if (ErrorCode == Preview::Error::None && Connection)
                {
                    State->Authenticated = true;
                    State->AccountId = Connection->AccountId();
                    State->Identity = std::string(Connection->Identity());
                }
            }
            else
            {
                auto Candidate = std::make_shared<Preview::Tuic::Conn<>>(
                    Transport, State->Config.uuid, nullptr, State->Config.AuthenticatorOwner);
                Candidate->MarkAuthenticated(State->AccountId, {}, State->Identity);
                auto Handshake = co_await Candidate->ReadHandshake();
                ErrorCode = Handshake.first;
                Message = std::move(Handshake.second);
                if (ErrorCode == Preview::Error::None)
                {
                    Connection = std::move(Candidate);
                }
            }
            if (ErrorCode == Preview::Error::None && Connection)
            {
                co_await Handler(std::move(Message), std::move(Connection));
            }
            else
            {
                Transport->Close();
            }
        }

    } // namespace detail

    [[nodiscard]] inline auto ConfigureTuicServer(
        Preview::Quic::ServerOptions Options,
        const Preview::Ingress::SharedQuicAdmissionContext &Context)
        -> Preview::Quic::ServerOptions
    {
        if (!Context || !Context->ReadyForTuic())
        {
            return Options;
        }
        auto State = std::make_shared<detail::TuicState>(Options.Executor);
        State->Config.uuid = Context->TuicUuid;
        State->Config.password = Context->TuicPassword;
        State->Config.AuthenticatorOwner = Context->Authenticator;

        Options.ExpectedAlpn = Context->ExpectedAlpn;
        Options.ExpectedServerName = Context->ServerName;
        Options.MaxStreams = Context->MaxStreams;
        Options.MaxDatagrams = Context->MaxDatagrams;
        Options.OnExporter = [State](Preview::Quic::ServerOptions::KeyingMaterialExporter Exporter)
        {
            if (State->Closed)
            {
                return;
            }
            State->Exporter = std::move(Exporter);
            detail::Notify(State);
        };
        Options.OnUnidirectional = [State](Preview::Quic::SharedStreamProvider Provider)
        {
            if (State->Closed || !Provider || State->AuthStream)
            {
                if (Provider)
                {
                    Provider->Close();
                }
                return;
            }
            State->AuthProvider = Provider;
            State->AuthStream = std::make_shared<Preview::Quic::StreamAdapter>(
                Provider->Executor(), Provider);
            detail::Notify(State);
        };
        Options.OnStream = [State, Handler = Context->TuicStream](
                               Preview::Quic::SharedStreamProvider Provider)
        {
            if (State->Closed || !Handler || !Provider)
            {
                if (Provider)
                {
                    Provider->Close();
                }
                return;
            }
            Net::co_spawn(
                Provider->Executor(),
                [State, Provider, Handler]() mutable -> Net::awaitable<void>
                {
                    co_await detail::AcceptBidi(State, Provider, Handler);
                },
                Net::detached);
        };
        Options.OnDatagram = [State, Handler = Context->TuicDatagram](
                                  Preview::Quic::SharedDatagramProvider Provider)
        {
            if (State->Closed || !Provider || !Handler || !State->Authenticated)
            {
                if (Provider)
                {
                    Provider->Close();
                }
                return;
            }
            auto Config = State->Config;
            Net::co_spawn(
                Provider->Executor(),
                [Provider, Handler, Config = std::move(Config)]() mutable -> Net::awaitable<void>
                {
                    auto Datagram = Preview::Tuic::AcceptPacket(Provider, Config);
                    if (Datagram)
                    {
                        co_await Handler(std::move(Datagram));
                    }
                },
                Net::detached);
        };
        Options.OnClosed = [State, CloseOwner = Context->CloseOwner]
        {
            State->Closed = true;
            detail::Notify(State);
            if (CloseOwner)
            {
                CloseOwner();
            }
        };
        return Options;
    }

} // namespace Preview::Composition::Quic
