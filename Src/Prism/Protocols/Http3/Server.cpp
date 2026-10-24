/**
 * @file Server.cpp
 * @brief HTTP/3 服务端 façade、factory 与输出代理实现。
 */
#include <Prism/Protocols/Http3/Server.hpp>

#include <utility>

namespace Prism::Http3
{
    Server::Server(ServerOptions Options)
        : Session_(Options.MemoryResource)
    {
    }

    auto Server::Init(std::function<std::int64_t()> OpenUniStream) -> bool
    {
        return Session_.Init(std::move(OpenUniStream));
    }

    auto Server::Feed(
        const std::int64_t StreamId,
        const std::span<const std::byte> Data,
        const bool Fin) -> Fault::Code
    {
        return Session_.Feed(StreamId, Data, Fin);
    }

    auto Server::Feed(
        const std::int64_t StreamId,
        std::vector<std::byte> &&Data,
        const bool Fin) -> Fault::Code
    {
        return Session_.Feed(StreamId, std::move(Data), Fin);
    }

    auto Server::TakeEvent() -> std::optional<ServerEvent>
    {
        return Session_.TakeEvent();
    }

    auto Server::PumpOutput(std::vector<OutPacket> &Output) -> bool
    {
        return Session_.PumpOutput(Output);
    }

    auto Server::AddWriteOffset(const std::int64_t StreamId, const std::size_t Written) -> void
    {
        Session_.AddWriteOffset(StreamId, Written);
    }

    auto Server::SubmitResponse(ResponseHead Response) -> Fault::Code
    {
        return Session_.SubmitResponse(std::move(Response));
    }

    auto Server::Close() noexcept -> void
    {
        Session_.Close();
    }

    auto Server::IsOpen() const noexcept -> bool
    {
        return Session_.IsOpen();
    }

    auto ServerFactory::Create(ServerOptions Options) const -> SharedServer
    {
        return std::make_shared<Server>(Options);
    }

    auto MakeServer(const ServerOptions &Options) -> SharedServer
    {
        return std::make_shared<Server>(Options);
    }
}
