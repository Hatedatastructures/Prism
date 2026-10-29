/**
 * @file Server.hpp
 * @brief XHTTP Stream-up 与 Packet-up 服务端状态机。
 * @details 一个 h2 会话中维护上传、下载以及 Packet-up 请求的归属；
 *          只有确认下载流后才向调用方暴露 SplitTransport。
 */

#pragma once

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Xhttp/Detail/CarrierSessionSupport.hpp>
#include <Prism/Protocols/Xhttp/Detail/Split/Path.hpp>
#include <Prism/Protocols/Xhttp/Detail/Split/ServerState.hpp>
#include <Prism/Protocols/Xhttp/Detail/Split/Transport.hpp>
#include <Prism/Protocols/Xhttp/Detail/Wire.hpp>
#include <Prism/Protocols/Xhttp/Detail/FactoryRetirement.hpp>
#include <Prism/Transport/Encrypted.hpp>

#include <boost/asio/experimental/channel.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace Prism::Xhttp::Detail
{

    [[nodiscard]] auto FlushSplitSession(
        const std::shared_ptr<SplitServerState> &State)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

    struct SplitServerUploadWriter final
    {
        std::weak_ptr<SplitServerState> State;

        [[nodiscard]] auto operator()(std::span<const std::byte> Data) const
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            return Run(State, Data);
        }

        [[nodiscard]] static auto Run(
            std::weak_ptr<SplitServerState> State,
            std::span<const std::byte> Data)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
    };

    auto CloseSplitServerOwner(
        const std::weak_ptr<SplitServerState> &WeakState) noexcept -> Prism::Fault::Failure;

    struct SplitServerCloseHandler final
    {
        std::weak_ptr<SplitServerState> State;

        auto operator()() const -> Prism::Fault::Failure
        {
            return CloseSplitServerOwner(State);
        }
    };

    auto CloseSplitServerOwner(
        const std::weak_ptr<SplitServerState> &WeakState) noexcept -> Prism::Fault::Failure;

    struct SplitServerHeaderInput final
    {
        std::shared_ptr<SplitServerState> State;
        std::int32_t StreamId{0};
        const h2::HeaderList &Headers;
        bool EndStream{false};
    };

    auto SignalSplitReady(
        const std::shared_ptr<SplitServerState> &State,
        const bool Accepted,
        Prism::Fault::Failure Failure) -> void;

    auto PushSplitServerData(
        const std::shared_ptr<SplitServerState> &State,
        std::span<const std::byte> Data) -> void;

    [[nodiscard]] auto MakeSplitResponse(
        const std::string_view Status,
        const bool EndStream) -> h2::HeaderList;

    auto FailSplitServerControl(
        const std::shared_ptr<SplitServerState> &State,
        Prism::Fault::Failure Failure) -> void;

    auto RejectSplitRequest(
        const std::shared_ptr<SplitServerState> &State,
        const std::int32_t StreamId) -> void;

    auto BindSplitServerTransport(
        const std::shared_ptr<SplitServerState> &State) -> void;

    auto HandleSplitServerHeaders(SplitServerHeaderInput Input) -> void;

    auto HandleSplitServerData(
        const std::shared_ptr<SplitServerState> &State,
        const std::int32_t StreamId,
        std::span<const std::byte> Data) -> void;

    auto HandleSplitServerClose(
        const std::shared_ptr<SplitServerState> &State,
        const h2::StreamReceiveClosure &Closure) -> void;

    [[nodiscard]] auto RunSplitServerDriver(
        std::shared_ptr<SplitServerState> State) -> Net::awaitable<void>;

} // namespace Prism::Xhttp::Detail
