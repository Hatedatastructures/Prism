/**
 * @file Session.cpp
 * @brief HTTP/2 会话 facade 到私有状态 owner 的实现。
 */

#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Http2/Detail/SessionState.hpp>

#include <utility>

namespace Prism::Http2
{
    Session::Session(Net::any_io_executor Executor, bool IsServer)
        : State_(std::make_unique<Detail::SessionState>(
              std::move(Executor), IsServer, *this))
    {
    }

    Session::~Session() = default;

    auto Session::Feed(
        std::span<const std::byte> Data,
        std::error_code &ErrorCode) -> bool
    {
        return State_->Feed(Data, ErrorCode);
    }

    auto Session::Collect(std::vector<std::byte> &Output) -> bool
    {
        return State_->Collect(Output);
    }

    auto Session::OpenStream(const HeaderList &Headers, bool EndStream)
        -> std::expected<std::int32_t, Prism::Fault::Failure>
    {
        return State_->OpenStream(Headers, EndStream);
    }

    auto Session::SubmitHeaders(
        std::int32_t StreamId,
        const HeaderList &Headers,
        bool EndStream) -> std::expected<void, Prism::Fault::Failure>
    {
        return State_->SubmitHeaders(StreamId, Headers, EndStream);
    }

    auto Session::SubmitData(
        std::int32_t StreamId,
        std::span<const std::byte> Data,
        bool EndStream) -> SubmitDataStatus
    {
        return State_->SubmitData(StreamId, Data, EndStream);
    }

    auto Session::AwaitWritable(std::int32_t StreamId, std::size_t RequiredBytes)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        return State_->AwaitWritable(StreamId, RequiredBytes);
    }

    auto Session::ConsumeData(std::int32_t StreamId, std::size_t Bytes) -> void
    {
        State_->ConsumeData(StreamId, Bytes);
    }

    auto Session::ResetStream(std::int32_t StreamId, std::uint32_t ErrorCode)
        -> std::expected<void, Prism::Fault::Failure>
    {
        return State_->ResetStream(StreamId, ErrorCode);
    }

    auto Session::Executor() const -> Net::any_io_executor
    {
        return State_->Executor();
    }

    auto Session::SendSettings(std::span<const SettingsEntry> Entries) -> void
    {
        State_->SendSettings(Entries);
    }

    auto Session::SendPing(std::span<const std::byte, 8> Opaque) -> void
    {
        State_->SendPing(Opaque);
    }

    auto Session::SendGoaway(std::uint32_t LastStreamId, std::uint32_t ErrorCode) -> void
    {
        State_->SendGoaway(LastStreamId, ErrorCode);
    }
}
