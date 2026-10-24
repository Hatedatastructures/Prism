/**
 * @file SplitClient.hpp
 * @brief XHTTP Stream-up 与 Packet-up 客户端状态机。
 */

#pragma once

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Xhttp/Detail/ClientTls.hpp>
#include <Prism/Protocols/Xhttp/Detail/SplitClientState.hpp>
#include <Prism/Protocols/Xhttp/Detail/SplitPath.hpp>
#include <Prism/Protocols/Xhttp/Detail/SplitTransport.hpp>
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
#include <chrono>
#include <cstddef>
#include <cstdint>
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

    [[nodiscard]] auto FlushSplitClient(
        const std::shared_ptr<SplitClientState> &State)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

    struct SplitClientWireWriter final
    {
        std::weak_ptr<Prism::Transport::Encrypted> Encrypted;

        [[nodiscard]] auto operator()(std::span<const std::byte> Data) const
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            return Run(Encrypted, Data);
        }

        [[nodiscard]] static auto Run(
            std::weak_ptr<Prism::Transport::Encrypted> Encrypted,
            std::span<const std::byte> Data)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
    };

    struct SplitClientUploadWriter final
    {
        std::weak_ptr<SplitClientState> State;

        [[nodiscard]] auto operator()(std::span<const std::byte> Data) const
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            return Run(State, Data);
        }

        [[nodiscard]] static auto Run(
            std::weak_ptr<SplitClientState> State,
            std::span<const std::byte> Data)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
    };

    auto CloseSplitClientOwner(
        const std::weak_ptr<SplitClientState> &WeakState) noexcept -> Prism::Fault::Failure;

    struct SplitClientCloseHandler final
    {
        std::weak_ptr<SplitClientState> State;

        auto operator()() const -> Prism::Fault::Failure
        {
            return CloseSplitClientOwner(State);
        }
    };

    auto CloseSplitClientOwner(
        const std::weak_ptr<SplitClientState> &WeakState) noexcept -> Prism::Fault::Failure;

    struct SplitClientHeadersObserver final
    {
        std::weak_ptr<SplitClientState> State;

        auto operator()(
            const std::int32_t StreamId, const h2::HeaderList &Headers, const bool) const -> void;
    };

    /** @brief 同步处理真实 download stream 的 FIN/RST，不强持 client owner。 */
    struct SplitClientStreamCloseObserver final
    {
        std::weak_ptr<SplitClientState> State;
        auto operator()(const h2::StreamReceiveClosure &Closure) const -> void;
    };

    struct SplitClientDataObserver final
    {
        std::weak_ptr<SplitClientState> State;

        auto operator()(
            const std::int32_t StreamId, const std::span<const std::byte> Data) const -> void;
    };

    struct SplitClientConnectRequest final
    {
        SharedTransmission Raw;
        Net::ssl::context &SslContext;
        Config Cfg;
        std::string Host;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
    };

    /** @brief XHTTP Split 客户端状态构造的完整 owning 输入。 */
    struct SplitClientStateRequest final
    {
        Prism::Transport::Encrypted::SharedStream Stream;
        Config Configuration;
        std::string Host;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
    };

    [[nodiscard]] auto FlushSplitClient(
        const std::shared_ptr<SplitClientState> &State)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

    auto CloseSplitClient(const std::shared_ptr<SplitClientState> &State) -> void;

    [[nodiscard]] auto MakeSplitClientState(SplitClientStateRequest Request)
        -> std::shared_ptr<SplitClientState>;

    /** @brief State 持有 Session/传输；在 Session executor 同步调用且不可取消，外层 owner 排空 I/O 并最终关闭传输。 */
    [[nodiscard]] auto OpenSplitClientStreams(
        const std::shared_ptr<SplitClientState> &State)
        -> std::expected<void, Prism::Fault::Failure>;

    [[nodiscard]] auto RunSplitClientDriver(
        std::shared_ptr<SplitClientState> State) -> Net::awaitable<void>;

    auto CompleteSplitClientDriver(
        const std::shared_ptr<SplitClientState> &State,
        std::exception_ptr Exception) -> void;

    auto StartSplitClientDriver(const std::shared_ptr<SplitClientState> &State) -> void;

    [[nodiscard]] auto RetireSplitClientState(
        FactoryRetirement<SplitClientState> &Retirement,
        Prism::Fault::Failure Cause) -> Net::awaitable<Prism::Fault::Failure>;

    [[nodiscard]] auto WaitSplitClientResponse(
        const std::shared_ptr<SplitClientState> &State,
        FactoryRetirement<SplitClientState> &Retirement) -> Net::awaitable<FactoryResult>;

    [[nodiscard]] auto ConnectSplitCore(
        SplitClientConnectRequest Request,
        Prism::Contract::InboundAdmission &Admission,
        FactoryRetirement<SplitClientState> &Retirement) -> Net::awaitable<FactoryResult>;

    [[nodiscard]] auto ConnectSplit(SplitClientConnectRequest Request)
        -> Net::awaitable<FactoryResult>;

    [[nodiscard]] auto ConnectSplitCore(
        SplitClientConnectRequest Request,
        Prism::Contract::InboundAdmission &Admission,
        FactoryRetirement<SplitClientState> &Retirement) -> Net::awaitable<FactoryResult>;

} // namespace Prism::Xhttp::Detail
