/**
 * @file Stream.cpp
 * @brief HTTP/2 流句柄操作实现
 */

#include <Prism/Protocols/Http2/Stream.hpp>

#include <cassert>
#include <utility>

namespace Prism::Http2
{
    auto StreamHandle::SubmitHeaders(const HeaderList &Headers, const bool EndStream)
        -> std::expected<void, Prism::Fault::Failure>
    {
        const auto LockedSession = Session();
        if (!LockedSession)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ConnectionAborted});
        }
        return LockedSession->SubmitHeaders(StreamId_, Headers, EndStream);
    }

    auto StreamHandle::Write(const std::span<const std::byte> Data, const bool EndStream)
        -> SubmitDataStatus
    {
        const auto LockedSession = Session();
        if (!LockedSession)
        {
            return SubmitDataStatus::Closed;
        }
        return LockedSession->SubmitData(StreamId_, Data, EndStream);
    }

    auto StreamHandle::AwaitWritable(const std::size_t RequiredBytes)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto LockedSession = Session();
        if (!LockedSession)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ConnectionAborted});
        }
        co_return co_await LockedSession->AwaitWritable(StreamId_, RequiredBytes);
    }

    auto StreamHandle::Reset(const std::uint32_t ErrorCode)
        -> std::expected<void, Prism::Fault::Failure>
    {
        const auto LockedSession = Session();
        if (!LockedSession)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ConnectionAborted});
        }
        return LockedSession->ResetStream(StreamId_, ErrorCode);
    }

    auto StreamHandle::Close() -> SubmitDataStatus
    {
        const auto LockedSession = Session();
        if (!LockedSession)
        {
            return SubmitDataStatus::Closed;
        }
        return LockedSession->SubmitData(StreamId_, std::span<const std::byte>{}, true);
    }

    auto OpenStreamHandle(SharedH2Session Session, const HeaderList &Headers, const bool EndStream)
        -> std::expected<SharedStreamHandle, Prism::Fault::Failure>
    {
        if (!Session)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        const auto StreamId = Session->OpenStream(Headers, EndStream);
        if (!StreamId)
        {
            return std::unexpected(StreamId.error());
        }
        auto Handle = std::make_shared<StreamHandle>(*StreamId, std::move(Session));
        assert(Handle->Session() != nullptr);
        return Handle;
    }
} // namespace Prism::Http2
