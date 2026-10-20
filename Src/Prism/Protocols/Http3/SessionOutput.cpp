/**
 * @file SessionOutput.cpp
 * @brief HTTP/3 输出抽取、写偏移确认和响应提交职责。
 */


#include <Prism/Protocols/Http3/Detail/SessionContract.hpp>

#include <array>
#include <charconv>
#include <limits>
#include <system_error>
#include <utility>

namespace Prism::Http3::Detail
{

    [[nodiscard]] auto Session::TakeEvent() -> std::optional<ServerEvent>
    {
        if (Events_.empty())
        {
            return std::nullopt;
        }
        auto Event = std::move(Events_.front());
        Events_.pop_front();
        const auto EventBytes = OwnedEventBytes(Event);
        if (EventBytes <= PendingEventBytes_)
        {
            PendingEventBytes_ -= EventBytes;
        }
        return Event;
    }

    auto Session::PumpOutput(std::vector<OutPacket> &Output) -> bool
    {
        if (!Conn_ || PendingOutput_)
        {
            return Conn_ != nullptr;
        }

        std::array<nghttp3_vec, 16> Vectors{};
        std::array<std::array<std::byte, 4096>, 16> Buffers{};
        for (std::size_t Index = 0; Index < Vectors.size(); ++Index)
        {
            Vectors[Index].base = reinterpret_cast<std::uint8_t *>(Buffers[Index].data());
            Vectors[Index].len = Buffers[Index].size();
        }
        std::int64_t StreamId = -1;
        int Fin = 0;
        const auto Count = nghttp3_conn_writev_stream(
            Conn_, &StreamId, &Fin, Vectors.data(), Vectors.size());
        if (Count < 0 || static_cast<std::size_t>(Count) > Vectors.size())
        {
            return false;
        }
        if (Count == 0)
        {
            if (StreamId < 0 || Fin == 0)
            {
                return StreamId < 0;
            }
            OutPacket Packet(Resource_);
            Packet.StreamId = StreamId;
            Packet.Fin = true;
            PendingOutput_ = true;
            PendingStream_ = StreamId;
            PendingBytes_ = 0;
            PendingFin_ = true;
            Output.push_back(std::move(Packet));
            return true;
        }
        if (StreamId < 0)
        {
            return false;
        }

        std::size_t ByteCount = 0;
        for (std::size_t Index = 0; Index < static_cast<std::size_t>(Count); ++Index)
        {
            if (Vectors[Index].len > (std::numeric_limits<std::size_t>::max)() - ByteCount)
            {
                return false;
            }
            ByteCount += Vectors[Index].len;
        }
        OutPacket Packet(Resource_);
        Packet.StreamId = StreamId;
        Packet.Fin = Fin != 0;
        Packet.Data.reserve(ByteCount);
        for (std::size_t Index = 0; Index < static_cast<std::size_t>(Count); ++Index)
        {
            const auto *Begin = reinterpret_cast<const std::byte *>(Vectors[Index].base);
            Packet.Data.insert(Packet.Data.end(), Begin, Begin + Vectors[Index].len);
        }
        PendingOutput_ = true;
        PendingStream_ = StreamId;
        PendingBytes_ = ByteCount;
        PendingFin_ = Packet.Fin;
        Output.push_back(std::move(Packet));
        return true;
    }

    auto Session::AddWriteOffset(
        const std::int64_t StreamId,
        const std::size_t Written) -> void
    {
        if (!Conn_ || !PendingOutput_ || StreamId != PendingStream_ || Written > PendingBytes_)
        {
            return;
        }
        if (nghttp3_conn_add_write_offset(Conn_, StreamId, Written) != 0)
        {
            return;
        }
        PendingBytes_ -= Written;
        if (PendingBytes_ != 0)
        {
            return;
        }
        if (PendingFin_)
        {
            nghttp3_conn_shutdown_stream_write(Conn_, StreamId);
            Responses_.erase(StreamId);
        }
        PendingOutput_ = false;
        PendingStream_ = -1;
        PendingFin_ = false;
    }

    auto Session::SubmitResponse(ResponseHead Response) -> Fault::Code
    {
        if (!Conn_ || Response.StreamId < 0 || Response.Status > 999 ||
            Responses_.contains(Response.StreamId))
        {
            return Fault::Code::InvalidArgument;
        }
        const auto StreamId = Response.StreamId;
        const auto Status = Response.Status;
        const auto Fin = Response.Fin;
        auto [Iterator, Inserted] = Responses_.try_emplace(
            StreamId,
            PendingResponse(std::move(Response.Headers), Fin));
        if (!Inserted)
        {
            return Fault::Code::InvalidArgument;
        }
        const auto Result = SubmitResponseHeaders(
            StreamId, Status, Iterator->second);
        if (Result != Fault::Code::Success)
        {
            Responses_.erase(Iterator);
        }
        return Result;
    }

    auto Session::SubmitResponseHeaders(
        const std::int64_t StreamId,
        const std::uint16_t Status,
        const PendingResponse &Response) -> Fault::Code
    {
        const auto &Headers = Response.Headers;
        std::array<char, 4> StatusBuffer{};
        const auto StatusText = std::to_chars(
            StatusBuffer.data(), StatusBuffer.data() + StatusBuffer.size(), Status);
        if (StatusText.ec != std::errc{})
        {
            return Fault::Code::InvalidArgument;
        }
        std::vector<nghttp3_nv> Fields;
        Fields.reserve(Headers.Fields.size() + 1);
        Fields.push_back({
            reinterpret_cast<const std::uint8_t *>(":status"),
            reinterpret_cast<const std::uint8_t *>(StatusBuffer.data()),
            7,
            static_cast<std::size_t>(StatusText.ptr - StatusBuffer.data()),
            NGHTTP3_NV_FLAG_NONE});
        for (const auto &Field : Headers.Fields)
        {
            Fields.push_back({
                reinterpret_cast<const std::uint8_t *>(Field.Name.data()),
                reinterpret_cast<const std::uint8_t *>(Field.value.data()),
                Field.Name.size(),
                Field.value.size(),
                NGHTTP3_NV_FLAG_NONE});
        }
        nghttp3_data_reader Reader{};
        Reader.read_data = ReadResponseBody;
        nghttp3_data_reader *ReaderValue = nullptr;
        if (!Response.Fin)
        {
            ReaderValue = &Reader;
        }
        const auto Result = nghttp3_conn_submit_response(
            Conn_, StreamId, Fields.data(), Fields.size(), ReaderValue);
        if (Result == 0)
        {
            return Fault::Code::Success;
        }
        return Fault::Code::ProtocolError;
    }

    auto Session::ReadResponseBody(
        nghttp3_conn *,
        std::int64_t,
        nghttp3_vec *,
        std::size_t,
        std::uint32_t *Flags,
        void *,
        void *) -> nghttp3_ssize
    {
        if (Flags)
        {
            *Flags = 0;
        }
        return NGHTTP3_ERR_WOULDBLOCK;
    }

} // namespace Prism::Http3::Detail
