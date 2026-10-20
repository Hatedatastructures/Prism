/**
 * @file Server.hpp
 * @brief 通用 HTTP/3 服务端会话与构造能力。
 * @details Server 拥有 frame session，不拥有 QUIC 连接或监听器。
 */
#pragma once

#include <Prism/Protocols/Http3/Session.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace Prism::Http3
{
    struct ServerOptions final
    {
        Prism::Memory::ResourcePointer MemoryResource{nullptr};
    };

    class Server final
    {
    public:
        explicit Server(ServerOptions Options);
        Server(const Server &) = delete;
        auto operator=(const Server &) -> Server & = delete;

        [[nodiscard]] auto Init(std::function<std::int64_t()> OpenUniStream) -> bool;
        [[nodiscard]] auto Feed(
            std::int64_t StreamId,
            std::span<const std::byte> Data,
            bool Fin) -> Fault::Code;
        [[nodiscard]] auto Feed(
            std::int64_t StreamId,
            std::vector<std::byte> &&Data,
            bool Fin) -> Fault::Code;
        [[nodiscard]] auto TakeEvent() -> std::optional<ServerEvent>;
        [[nodiscard]] auto PumpOutput(std::vector<OutPacket> &Output) -> bool;
        auto AddWriteOffset(std::int64_t StreamId, std::size_t Written) -> void;
        [[nodiscard]] auto SubmitResponse(ResponseHead Response) -> Fault::Code;
        auto Close() noexcept -> void;
        [[nodiscard]] auto IsOpen() const noexcept -> bool;

    private:
        Session Session_;
    };

    using SharedServer = std::shared_ptr<Server>;

    class ServerFactory final
    {
    public:
        [[nodiscard]] auto Create(ServerOptions Options) const -> SharedServer;
    };

    [[nodiscard]] auto MakeServer(const ServerOptions &Options) -> SharedServer;
}
