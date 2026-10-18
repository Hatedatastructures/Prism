/**
 * @file Server.hpp
 * @brief 通用 HTTP/3 服务端门面。
 */

#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include <Prism/Protocols/Http3/Session.hpp>

namespace Prism::Http3
{

    /** @brief HTTP/3 服务端的构造选项。 */
    struct ServerOptions final
    {
        Prism::Memory::ResourcePointer MemoryResource{nullptr};
    };

    using OutPacket = Prism::Http3::OutPacket;

    /**
     * @class Server
     * @brief 拥有一个通用 HTTP/3 帧会话。
     * @details 它从不拥有 QUIC 连接，也不关闭 QUIC 监听器。
     */
    class Server final
    {
    public:
        explicit Server(ServerOptions Options)
            : Session_(Options.MemoryResource)
        {
        }

        Server(const Server &) = delete;
        auto operator=(const Server &) -> Server & = delete;

        [[nodiscard]] auto Init(std::function<std::int64_t()> OpenUniStream) -> bool
        {
            return Session_.Init(std::move(OpenUniStream));
        }

        [[nodiscard]] auto Feed(
            std::int64_t StreamId,
            std::span<const std::byte> Data,
            bool Fin) -> Fault::Code
        {
            return Session_.Feed(StreamId, Data, Fin);
        }

        [[nodiscard]] auto Feed(
            std::int64_t StreamId,
            std::vector<std::byte> &&Data,
            bool Fin) -> Fault::Code
        {
            return Session_.Feed(StreamId, std::move(Data), Fin);
        }

        [[nodiscard]] auto TakeEvent() -> std::optional<ServerEvent>
        {
            return Session_.TakeEvent();
        }

        [[nodiscard]] auto PumpOutput(std::vector<OutPacket> &Output) -> bool
        {
            return Session_.PumpOutput(Output);
        }

        auto AddWriteOffset(std::int64_t StreamId, std::size_t Written) -> void
        {
            Session_.AddWriteOffset(StreamId, Written);
        }

        [[nodiscard]] auto SubmitResponse(ResponseHead Response) -> Fault::Code
        {
            return Session_.SubmitResponse(std::move(Response));
        }

        auto Close() noexcept -> void
        {
            Session_.Close();
        }

        [[nodiscard]] auto IsOpen() const noexcept -> bool
        {
            return Session_.IsOpen();
        }

    private:
        Session Session_;
    };

    using SharedServer = std::shared_ptr<Server>;

    [[nodiscard]] inline auto MakeServer(const ServerOptions &Options) -> SharedServer
    {
        return std::make_shared<Server>(Options);
    }

} // namespace Prism::Http3
