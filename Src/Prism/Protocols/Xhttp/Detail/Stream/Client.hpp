/**
 * @file Client.hpp
 * @brief XHTTP Stream-one 客户端状态机。
 */

#pragma once

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Protocols/Xhttp/Detail/ClientTls.hpp>
#include <Prism/Protocols/Xhttp/Detail/Stream/ClientState.hpp>
#include <Prism/Protocols/Xhttp/Detail/Stream/Transport.hpp>
#include <Prism/Protocols/Xhttp/Detail/Wire.hpp>
#include <Prism/Protocols/Xhttp/Detail/AcceptedTransport.hpp>
#include <Prism/Protocols/Xhttp/Detail/FactoryRetirement.hpp>
#include <Prism/Transport/Encrypted.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace Prism::Xhttp::Detail
{

    struct ClientHeadersEvent final
    {
        std::int32_t StreamId;
        const h2::HeaderList &Headers;
        bool EndStream;
    };

    auto CloseClientOwnerOnExecutor(const std::shared_ptr<ClientState> &State) noexcept
        -> Prism::Fault::Failure;

    /** @brief 仅由 Encrypted executor 调用；首 close failure 同步返回。 */
    auto CloseClientOwner(const std::weak_ptr<ClientState> &WeakState) noexcept
        -> Prism::Fault::Failure;
[[nodiscard]] auto WriteClientWire(
        const std::shared_ptr<Prism::Transport::Encrypted> &Encrypted,
        std::span<const std::byte> Data)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

    [[nodiscard]] auto FlushClientFrames(
        const std::shared_ptr<ClientState> &State)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

    auto SubmitClientData(
        const std::weak_ptr<ClientState> &WeakState,
        const std::int32_t StreamId,
        std::span<const std::byte> Data)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

    auto FinishClientStream(
        const std::weak_ptr<ClientState> &WeakState,
        const std::int32_t StreamId)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

    auto HandleClientHeaders(
        const std::weak_ptr<ClientState> &WeakState,
        const ClientHeadersEvent &Event) -> void;

    auto HandleClientData(
        const std::weak_ptr<ClientState> &WeakState,
        const std::int32_t StreamId,
        std::span<const std::byte> Data) -> void;

    auto HandleClientClose(
        const std::weak_ptr<ClientState> &WeakState,
        const h2::StreamReceiveClosure &Closure) -> void;

    auto RunClientDriver(std::shared_ptr<ClientState> State)
        -> Net::awaitable<void>;

    struct ClientDriverOutcome final
    {
        Prism::Fault::Failure Failure;
        bool Failed{false};
        bool LocalCloseCompletion{false};
    };

    [[nodiscard]] auto DriveClientSession(
        const std::shared_ptr<ClientState> &State,
        std::span<std::byte> Buffer,
        ClientDriverOutcome &Outcome) -> Net::awaitable<void>;

    [[nodiscard]] auto MakeClientState(
        Prism::Transport::Encrypted::SharedStream Stream,
        std::shared_ptr<Prism::Memory::BytePool> Bytes) -> std::shared_ptr<ClientState>;

    [[nodiscard]] auto RetireClientState(
        FactoryRetirement<ClientState> &Retirement,
        Prism::Fault::Failure Cause) -> Net::awaitable<Prism::Fault::Failure>;

    auto CompleteClientDriver(
        const std::shared_ptr<ClientState> &State,
        std::exception_ptr Exception) -> void;

    auto StartClientDriver(const std::shared_ptr<ClientState> &State) -> void;

    /**
     * @brief 同步提交 Stream client 的 HTTP/2 设置与请求头。
     * @param State 持有 HTTP/2 会话和加密传输的状态；不转移所有权。
     * @param Cfg 请求配置；只在本次同步调用中读取。
     * @param Host 请求 authority；只借用到头字段编码完成。
     * @return 成功返回空值；stream 打开失败时保留完整 HTTP/2 Failure。
     * @details 必须在 Session executor 上调用且不可取消。POST 使用 EndStream=false，
     *          因此仅打开请求 stream，不关闭本地发送半边。client factory/retirement owner
     *          负责后续 I/O、传输排空及最终关闭。
     */
    [[nodiscard]] auto OpenClientStream(
        const std::shared_ptr<ClientState> &State,
        const Config &Cfg,
        std::string_view Host) -> std::expected<void, Prism::Fault::Failure>;

    [[nodiscard]] auto WaitClientResponse(
        const std::shared_ptr<ClientState> &State,
        FactoryRetirement<ClientState> &Retirement) -> Net::awaitable<FactoryResult>;

    [[nodiscard]] auto ConnectStreamCore(
        ClientConnectRequest Request,
        Prism::Contract::InboundAdmission &Admission,
        FactoryRetirement<ClientState> &Retirement) -> Net::awaitable<FactoryResult>;

    [[nodiscard]] auto ConnectStream(
        ClientConnectRequest Request) -> Net::awaitable<FactoryResult>;

    [[nodiscard]] auto ConnectStreamCore(
        ClientConnectRequest Request,
        Prism::Contract::InboundAdmission &Admission,
        FactoryRetirement<ClientState> &Retirement) -> Net::awaitable<FactoryResult>;

} // namespace Prism::Xhttp::Detail
