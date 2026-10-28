/**
 * @file Server.hpp
 * @brief XHTTP Stream-one 服务端握手与 HTTP/2 驱动。
 */

#pragma once

#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Protocols/Xhttp/Detail/CarrierSessionSupport.hpp>
#include <Prism/Protocols/Xhttp/Detail/Stream/Transport.hpp>
#include <Prism/Protocols/Xhttp/Detail/Wire.hpp>
#include <Prism/Protocols/Xhttp/Detail/AcceptedTransport.hpp>
#include <Prism/Protocols/Xhttp/Detail/FactoryRetirement.hpp>
#include <Prism/Transport/Encrypted.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Xhttp::Detail
{

    /** @brief XHTTP Stream-one 服务端接受状态的完整 owning 输入。 */
    struct XhttpAcceptRequest final
    {
        SharedTransmission Raw;
        Net::ssl::context &SslContext;
        Config Configuration;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
    };

    struct ServerState final
    {
        std::shared_ptr<Prism::Transport::Encrypted> Encrypted;
        SharedH2Session Session;
        std::shared_ptr<WireWriter> Wire;
        std::shared_ptr<XhttpTransport> Transport;
        std::shared_ptr<DriverCompletionChannel> DriverDone;
        bool DriverStarted{false};
        bool DriverCompleted{false};
        Prism::Fault::Failure DriverFailure;
        std::string Path;
        std::string Host;
        std::atomic_bool Closing{false};

        [[nodiscard]] auto HasCloseFailure() const noexcept -> bool
        {
            return Transport && Transport->CloseFailure().Failed();
        }

        [[nodiscard]] auto CloseFailureValue() const noexcept -> Prism::Fault::Failure
        {
            if (Transport)
            {
                return Transport->CloseFailure();
            }
            return {};
        }

        [[nodiscard]] auto CloseAndDrain()
            -> Net::awaitable<FactoryRetirementReceipt>;
    };

    [[nodiscard]] auto FlushServerFrames(
        const SharedH2Session &Session,
        const std::shared_ptr<WireWriter> &Wire)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
    struct ServerHeadersEvent final
    {
        std::int32_t StreamId;
        const h2::HeaderList &Headers;
        bool EndStream;
    };

    auto CloseServerOwnerOnExecutor(const std::shared_ptr<ServerState> &State) noexcept
        -> Prism::Fault::Failure;

    /** @brief 仅由 Encrypted executor 调用；首 close failure 同步返回。 */
    auto CloseServerOwner(const std::weak_ptr<ServerState> &WeakState) noexcept
        -> Prism::Fault::Failure;

    auto FailServerControl(
        const std::shared_ptr<ServerState> &State,
        Prism::Fault::Failure Failure) noexcept -> void;

    [[nodiscard]] auto WriteServerWire(
        const std::shared_ptr<Prism::Transport::Encrypted> &Encrypted,
        std::span<const std::byte> Data)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

    auto SubmitServerData(
        const std::weak_ptr<ServerState> &WeakState,
        const std::int32_t StreamId,
        std::span<const std::byte> Data)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

    auto FinishServerStream(
        const std::weak_ptr<ServerState> &WeakState,
        std::int32_t StreamId)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

    auto HandleServerHeaders(
        const std::weak_ptr<ServerState> &WeakState,
        const ServerHeadersEvent &Event) -> void;

    auto HandleServerData(
        const std::weak_ptr<ServerState> &WeakState,
        const std::int32_t StreamId,
        std::span<const std::byte> Data) -> void;

    auto HandleServerClose(
        const std::weak_ptr<ServerState> &WeakState,
        const h2::StreamReceiveClosure &Closure) -> void;

    auto RunServerDriver(std::shared_ptr<ServerState> State)
        -> Net::awaitable<void>;

    struct ServerDriverOutcome final
    {
        Prism::Fault::Failure Failure;
        bool Failed{false};
    };

    [[nodiscard]] auto DriveServerSession(
        const std::shared_ptr<ServerState> &State,
        std::span<std::byte> Buffer,
        ServerDriverOutcome &Outcome) -> Net::awaitable<void>;

    auto CompleteServerDriver(
        const std::shared_ptr<ServerState> &State,
        std::exception_ptr Exception) -> void;

    auto StartServerDriver(const std::shared_ptr<ServerState> &State) -> void;

    /**
     * @class XhttpAccept
     * @brief 编排 XHTTP Stream-one 服务端 TLS、HTTP/2 与 POST 匹配。
     * @details 该对象只拥有本次接受操作的 Raw 传输和 TLS 上下文引用；
     *          返回的 XhttpTransport 持有数据面状态，driver 通过共享状态继续运行。
     */
    class XhttpAccept final : public std::enable_shared_from_this<XhttpAccept>
    {
    public:
        explicit XhttpAccept(XhttpAcceptRequest Request);

        [[nodiscard]] auto Run(Prism::Contract::InboundAdmission &Admission)
            -> Net::awaitable<ServerAcceptResult>;

    private:
        [[nodiscard]] auto RunCore(
            Prism::Contract::InboundAdmission &Admission,
            FactoryRetirement<ServerState> &Retirement)
            -> Net::awaitable<ServerAcceptResult>;

    private:
        SharedTransmission Raw_;
        Net::ssl::context &SslCtx_;
        Config Cfg_;
        std::shared_ptr<Prism::Memory::BytePool> Bytes_;
    };

} // namespace Prism::Xhttp::Detail
