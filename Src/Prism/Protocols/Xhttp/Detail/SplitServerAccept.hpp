/**
 * @file SplitServerAccept.hpp
 * @brief XHTTP Split 服务端 TLS 与请求流接纳工厂。
 */
#pragma once

#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <Prism/Protocols/Xhttp/Detail/SplitServer.hpp>
#include <Prism/Protocols/Xhttp/Detail/SplitServerWireWriter.hpp>
#include <Prism/Protocols/Xhttp/Detail/AcceptedTransport.hpp>
#include <Prism/Protocols/Xhttp/Detail/FactoryRetirement.hpp>
#include <Prism/Transport/Encrypted.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <chrono>
#include <exception>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>

namespace Prism::Xhttp::Detail
{

    struct SplitServerInitialization final
    {
        std::shared_ptr<SplitServerState> State;
        Config Configuration;
    };

    auto InitializeSplitServerState(SplitServerInitialization Request) -> void;

    auto CompleteSplitServerDriver(
        const std::shared_ptr<SplitServerState> &State,
        std::exception_ptr Exception) -> void;

    auto StartSplitServerDriver(const std::shared_ptr<SplitServerState> &State) -> void;

    /** @brief XHTTP Split 服务端接受状态的完整 owning 输入。 */
    struct XhttpSplitAcceptRequest final
    {
        SharedTransmission Raw;
        Net::ssl::context &SslContext;
        Config Configuration;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
    };

    /** @brief XHTTP Split 服务端 TLS、h2 和上传/下载流匹配编排。 */
    class XhttpSplitAccept final : public std::enable_shared_from_this<XhttpSplitAccept>
    {
    public:
        explicit XhttpSplitAccept(XhttpSplitAcceptRequest Request);

        [[nodiscard]] auto Run(Prism::Contract::InboundAdmission &Admission)
            -> Net::awaitable<ServerAcceptResult>;

    private:
        [[nodiscard]] auto RunCore(
            Prism::Contract::InboundAdmission &Admission)
            -> Net::awaitable<ServerAcceptResult>;

        [[nodiscard]] auto RetireFactoryFailure(
            Prism::Contract::InboundAdmission &Admission,
            Prism::Fault::Failure Cause)
            -> Net::awaitable<Prism::Fault::Failure>;

    private:
        SharedTransmission Raw_;
        Net::ssl::context &SslCtx_;
        Config Cfg_;
        std::shared_ptr<Prism::Memory::BytePool> Bytes_;
        std::shared_ptr<FactoryRetirement<SplitServerState>> Retirement_;
    };

} // namespace Prism::Xhttp::Detail
