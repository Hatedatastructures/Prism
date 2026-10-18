/**
 * @file Http2DataSubmitter.hpp
 * @brief TrustTunnel H2 DATA 分块接纳与窗口背压 owner。
 */
#pragma once

#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2WireWriter.hpp>
#include <Prism/Protocols/Trusttunnel/Http2ServerTypes.hpp>

#include <algorithm>
#include <cstddef>
#include <expected>
#include <memory>
#include <span>

namespace Prism::Trusttunnel::Detail
{
    namespace Net = boost::asio;
    namespace H2 = Prism::Http2;

    struct Http2ServerDataRequest final
    {
        std::shared_ptr<H2::Session> Session;
        std::shared_ptr<Http2WireWriter> Wire;
        std::int32_t StreamId{0};
        std::span<const std::byte> Data;
    };

    struct Http2ServerDataWriter final
    {
        std::shared_ptr<H2::Session> Session;
        std::shared_ptr<Http2WireWriter> Wire;

        [[nodiscard]] auto operator()(
            const std::int32_t StreamId,
            const std::span<const std::byte> Data) const -> Net::awaitable<Http2ServerResult>
        {
            return Run({Session, Wire, StreamId, Data});
        }

        [[nodiscard]] static auto Run(Http2ServerDataRequest Value)
            -> Net::awaitable<Http2ServerResult>
        {
            std::size_t Offset = 0;
            bool EmptySubmitted = false;
            while (Offset < Value.Data.size() || !EmptySubmitted)
            {
                const auto Count = (std::min)(std::size_t{16U * 1024U}, Value.Data.size() - Offset);
                const auto Chunk = Value.Data.subspan(Offset, Count);
                auto Status = Value.Session->SubmitData(Value.StreamId, Chunk, false);
                while (Status == H2::SubmitDataStatus::Blocked)
                {
                    const auto Flushed = co_await FlushHttp2Frames(Value.Session, Value.Wire);
                    if (!Flushed) co_return std::unexpected(Flushed.error());
                    const auto Writable = co_await Value.Session->AwaitWritable(Value.StreamId, Count);
                    if (!Writable) co_return std::unexpected(Writable.error());
                    Status = Value.Session->SubmitData(Value.StreamId, Chunk, false);
                }
                if (Status != H2::SubmitDataStatus::Accepted)
                {
                    const auto Code = Status == H2::SubmitDataStatus::Closed
                        ? Prism::Fault::Code::ConnectionAborted
                        : Prism::Fault::Code::InvalidArgument;
                    co_return std::unexpected(Prism::Fault::Failure{Code});
                }
                Offset += Count;
                EmptySubmitted = true;
                const auto Flushed = co_await FlushHttp2Frames(Value.Session, Value.Wire);
                if (!Flushed) co_return std::unexpected(Flushed.error());
            }
            co_return Http2ServerResult{};
        }
    };

    struct Http2ServerFinishRequest final
    {
        std::shared_ptr<H2::Session> Session;
        std::shared_ptr<Http2WireWriter> Wire;
        std::int32_t StreamId{0};
    };

    struct Http2ServerFinisher final
    {
        std::shared_ptr<H2::Session> Session;
        std::shared_ptr<Http2WireWriter> Wire;

        [[nodiscard]] auto operator()(const std::int32_t StreamId) const
            -> Net::awaitable<Http2ServerResult>
        {
            return Run({Session, Wire, StreamId});
        }

        [[nodiscard]] static auto Run(Http2ServerFinishRequest Value)
            -> Net::awaitable<Http2ServerResult>
        {
            const auto Status = Value.Session->SubmitData(Value.StreamId, {}, true);
            if (Status != H2::SubmitDataStatus::Accepted)
            {
                const auto Code = Status == H2::SubmitDataStatus::Closed
                    ? Prism::Fault::Code::ConnectionAborted
                    : Prism::Fault::Code::InvalidArgument;
                co_return std::unexpected(Prism::Fault::Failure{Code});
            }
            co_return co_await FlushHttp2Frames(Value.Session, Value.Wire);
        }
    };
} // namespace Prism::Trusttunnel::Detail
