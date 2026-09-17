/**
 * @file QuicAdmissionContext.hpp
 * @brief QUIC admission 到具体协议 handler 的共享 owner context。
 */
#pragma once

#include <Preview/Account/Credential.hpp>
#include <Preview/Foundation/Authenticator.hpp>
#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Foundation/Utility/TrafficSink.hpp>
#include <Preview/Net/Dns/Resolver.hpp>
#include <Preview/Protocols/Hysteria2/Hysteria2.hpp>
#include <Preview/Protocols/Tuic/Tuic.hpp>
#include <Preview/Runtime/Middleware/Builtin/Dial.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace Preview::Ingress
{

    namespace Net = boost::asio;

    struct QuicAdmissionContext final
    {
        std::string Protocol{"hysteria2"};
        Preview::AccountId AccountId{};
        std::shared_ptr<const Preview::Account::Credential> Credential{};
        Preview::SharedAuthenticator Authenticator{};
        std::string ExpectedAlpn;
        std::string ServerName;
        std::size_t MaxStreams{64};
        std::size_t MaxDatagrams{64};
        Net::any_io_executor Executor{};
        std::shared_ptr<Preview::Network::Dns::Resolver> Resolver{};
        Preview::Middleware::Builtin::DialMiddleware::DialFn Dial{};
        std::function<Net::awaitable<void>(Preview::Hysteria2::Message,
                                           Preview::Hysteria2::SharedConn)> Hysteria2Stream{};
        std::function<Net::awaitable<void>(Preview::Hysteria2::SharedDgram)> Hysteria2Datagram{};
        std::array<std::uint8_t, 16> TuicUuid{};
        std::string TuicPassword;
        std::function<Net::awaitable<void>(Preview::Tuic::Message,
                                           Preview::Tuic::SharedConn)> TuicStream{};
        std::function<Net::awaitable<void>(Preview::Tuic::SharedDgram)> TuicDatagram{};
        std::function<void()> CloseOwner{};
        std::shared_ptr<Preview::Foundation::TrafficSink> Metrics{};

        [[nodiscard]] auto ReadyForHysteria2() const noexcept -> bool
        {
            return Executor != Net::any_io_executor{} && !ExpectedAlpn.empty() &&
                   !ServerName.empty() &&
                   static_cast<bool>(Credential) && static_cast<bool>(Dial) &&
                   static_cast<bool>(Hysteria2Stream) && static_cast<bool>(Hysteria2Datagram) &&
                   MaxStreams != 0U && MaxDatagrams != 0U;
        }

        [[nodiscard]] auto ReadyForTuic() const noexcept -> bool
        {
            return Protocol == "tuic" && Executor != Net::any_io_executor{} &&
                   !ServerName.empty() && static_cast<bool>(Credential) &&
                   !TuicPassword.empty() && static_cast<bool>(TuicStream) &&
                   static_cast<bool>(TuicDatagram) && MaxStreams != 0U &&
                   MaxDatagrams != 0U;
        }

        [[nodiscard]] auto Ready() const noexcept -> bool
        {
            return Protocol == "tuic" ? ReadyForTuic() : ReadyForHysteria2();
        }
    };

    using SharedQuicAdmissionContext = std::shared_ptr<const QuicAdmissionContext>;

} // namespace Preview::Ingress
