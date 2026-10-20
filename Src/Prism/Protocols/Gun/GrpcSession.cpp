/**
 * @file GrpcSession.cpp
 * @brief gRPC 客户端与服务端会话实现。
 */

#include <Prism/Protocols/Gun/Detail/GrpcSession.hpp>

#include <Prism/Foundation/Fault/Failure.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <expected>
#include <span>
#include <system_error>
#include <utility>

namespace Prism::Gun::Grpc::Detail
{

    ServerSession::ServerSession(
        Prism::SharedTransmission Transport,
        Config ConfigValue,
        MessageHandler Handler)
        : Transport_(std::move(Transport)), Config_(std::move(ConfigValue)),
          Handler_(std::move(Handler)),
          Session_(std::make_shared<H2::Session>(Transport_->Executor(), true))
    {
        Session_->OnHeaders = [this](
            const std::int32_t StreamId,
            const H2::HeaderList &Headers,
            const bool EndStream)
        { OnHeaders(StreamId, Headers, EndStream); };
        Session_->OnData = [this](
            const std::int32_t StreamId,
            const std::span<const std::byte> Data)
        { OnData(StreamId, Data); };
        Session_->OnStreamClose = [this](const H2::StreamReceiveClosure &Closure)
        { OnStreamClose(Closure); };
    }

    ClientSession::ClientSession(
        Prism::SharedTransmission Transport,
        Config ConfigValue)
        : Transport_(std::move(Transport)), Config_(std::move(ConfigValue)),
          Session_(std::make_shared<H2::Session>(Transport_->Executor(), false)),
          Decoder_(Config_.MaxMessageBytes)
    {
        Session_->OnHeaders = [this](
            const std::int32_t StreamId,
            const H2::HeaderList &Headers,
            const bool EndStream)
        { HandleHeaders(StreamId, Headers, EndStream); };
        Session_->OnData = [this](
            const std::int32_t StreamId,
            const std::span<const std::byte> Data)
        { HandleData(StreamId, Data); };
        Session_->OnStreamClose = [this](const H2::StreamReceiveClosure &Closure)
        { HandleStreamClose(Closure); };
    }

    auto ClientSession::PrepareRequest()
        -> std::expected<void, Prism::Fault::Failure>
    {
        Session_->SendSettings();
        const auto Opened = Session_->OpenStream(
            MakeRequestHeaders(Config_.Path, Config_.Authority), false);
        if (!Opened)
        {
            return std::unexpected(Opened.error());
        }
        StreamId_ = *Opened;
        return {};
    }

    auto ClientSession::Run(const std::span<const std::byte> Payload)
        -> Net::awaitable<ClientOutcome>
    {
        ClientOutcome Outcome;
        const auto Prepared = PrepareRequest();
        if (!Prepared)
        {
            Outcome.Terminal = Prepared.error();
        }
        else
        {
            const auto Submitted = co_await SubmitRequest(Payload);
            if (!Submitted)
            {
                Outcome.Terminal = Submitted.error();
                Outcome.Response = BuildResponse();
                if (Outcome.Response && ReadTerminal_.Failed())
                {
                    Outcome.Terminal = ReadTerminal_;
                }
                else if (ProcessingFailure_.Failed())
                {
                    Outcome.Terminal = ProcessingFailure_;
                }
                else if (!Outcome.Response && Failed_)
                {
                    Outcome.Terminal = {Prism::Fault::Code::ProtocolError};
                }
                else if (!Outcome.Response && Done_)
                {
                    Outcome.Terminal = {Prism::Fault::Code::ProtocolError};
                }
            }
            else
            {
                Outcome = co_await ReadResponse();
            }
        }

        const auto Closed = Transport_->Close();
        if (!Closed)
        {
            Outcome.CloseFailure = Closed.error();
        }
        if (const auto Activity = Transport_->Activity())
        {
            const auto Drained = co_await Activity->Drain();
            if (!Drained)
            {
                Outcome.DrainFailure = Drained.error();
            }
        }
        else
        {
            Outcome.DrainFailure = {Prism::Fault::Code::InvalidArgument};
        }
        co_return Outcome;
    }

    auto ClientSession::ReadResponse() -> Net::awaitable<ClientOutcome>
    {
        ClientOutcome Outcome;
        while (!Done_ && !Failed_ && !ProcessingFailure_.Failed() && Transport_->IsOpen())
        {
            const auto Pumped = co_await PumpResponseFrame();
            if (!Pumped)
            {
                Outcome.Terminal = Pumped.error();
                break;
            }
        }

        if (ProcessingFailure_.Failed())
        {
            Outcome.Terminal = ProcessingFailure_;
        }
        else if (Failed_)
        {
            Outcome.Terminal = {Prism::Fault::Code::ProtocolError};
        }
        else if (Done_)
        {
            Outcome.Response = BuildResponse();
            if (!Outcome.Response)
            {
                Outcome.Terminal = {Prism::Fault::Code::ProtocolError};
            }
            else if (ReadTerminal_.Failed())
            {
                Outcome.Terminal = ReadTerminal_;
            }
        }
        else if (Outcome.Terminal.Succeeded())
        {
            Outcome.Terminal = ReadTerminal_.Failed()
                ? ReadTerminal_
                : Prism::Fault::Failure{Prism::Fault::Code::IoError};
        }
        co_return Outcome;
    }

    auto ClientSession::BuildResponse() const -> std::optional<ClientResponse>
    {
        if (!Done_ || Failed_ || ProcessingFailure_.Failed() || !Decoder_.Empty())
        {
            return std::nullopt;
        }
        ClientResponse Response;
        Response.ResponseHeaders = ResponseHeaders_;
        Response.Trailers = Trailers_;
        Response.Payload = Payload_;
        for (const auto &Header : Trailers_)
        {
            if (Header.Name == "grpc-status")
            {
                std::uint32_t Status = 1;
                const auto Parsed = std::from_chars(Header.Value.data(),
                    Header.Value.data() + Header.Value.size(), Status);
                if (Parsed.ec == std::errc{})
                {
                    Response.GrpcStatus = Status;
                }
            }
        }
        return Response;
    }

    auto ClientSession::PumpResponseFrame()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        std::array<std::byte, 16384> Buffer{};
        const auto Part = co_await Transport_->ReadSome(Buffer);
        if (Part.Bytes > Buffer.size())
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::IoError});
        }
        if (Part.Failure.Failed() && ReadTerminal_.Succeeded())
        {
            ReadTerminal_ = Part.Failure;
        }
        Prism::Fault::Failure ProcessingFailure;
        if (Part.Bytes != 0U)
        {
            std::error_code Error;
            const auto Fed = Session_->Feed(
                std::span<const std::byte>(Buffer).first(Part.Bytes), Error);
            if (!Fed || Error)
            {
                ProcessingFailure = Error
                    ? Prism::Fault::FromNative(Error)
                    : Prism::Fault::Failure{Prism::Fault::Code::ProtocolError};
            }
        }
        if (ProcessingFailure.Failed())
        {
            if (!ProcessingFailure_.Failed())
            {
                ProcessingFailure_ = ProcessingFailure;
            }
            co_return std::unexpected(ProcessingFailure);
        }
        if (Part.Failure.Failed())
        {
            if (Failed_)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::ProtocolError});
            }
            if (Part.Bytes != 0U)
            {
                const auto Flushed = co_await Flush();
                if (Part.Failure.Code == Prism::Fault::Code::Eof &&
                    Done_ && Decoder_.Empty())
                {
                    co_return std::unexpected(
                        ReadTerminal_.Failed() ? ReadTerminal_ : Part.Failure);
                }
                if (Part.Failure.Code == Prism::Fault::Code::Eof && !Flushed)
                {
                    co_return std::unexpected(Flushed.error());
                }
            }
            if (Part.Failure.Code == Prism::Fault::Code::Eof && Done_)
            {
                co_return std::unexpected(
                    ReadTerminal_.Failed() ? ReadTerminal_ : Part.Failure);
            }
            co_return std::unexpected(Part.Failure);
        }
        if (Part.Bytes == 0U)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::IoError});
        }
        if (!Done_)
        {
            const auto Flushed = co_await Flush();
            if (!Flushed)
            {
                co_return std::unexpected(Flushed.error());
            }
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

} // namespace Prism::Gun::Grpc::Detail

namespace Prism::Gun::Grpc::Detail
{
    [[nodiscard]] auto ServerSession::Run() -> Net::awaitable<Prism::Fault::Failure>
    {
        Session_->SendSettings();
        if (!co_await Flush())
        {
            co_return Prism::Fault::Failure{Prism::Fault::Code::IoError};
        }
        std::array<std::byte, 16384> Buffer{};
        while (Transport_ && Transport_->IsOpen())
        {
            const auto Part = co_await Transport_->ReadSome(Buffer);
            const auto Count = Part.Bytes;
            if (Count > Buffer.size())
            {
                co_return Prism::Fault::Failure{Prism::Fault::Code::IoError};
            }
            if (Count == 0U && Part.Failure.Succeeded())
            {
                co_return Prism::Fault::Failure{};
            }

            std::error_code FeedError;
            bool Fed = true;
            if (Count != 0U)
            {
                Fed = Session_->Feed(
                    std::span<const std::byte>(Buffer).first(Count), FeedError);
            }
            const bool FeedFailed = !Fed || FeedError;

            if (FeedFailed)
            {
                co_return Prism::Fault::Failure{
                    Prism::Fault::Code::ProtocolError, FeedError};
            }
            if (Part.Failure.Failed() &&
                Part.Failure.Code != Prism::Fault::Code::Eof)
            {
                co_return Part.Failure;
            }

            if (Part.Failure.Code == Prism::Fault::Code::Eof && Count == 0U)
            {
                co_return Completed_
                    ? Prism::Fault::Failure{}
                    : Prism::Fault::Failure{Prism::Fault::Code::IoError};
            }
            if (ControlFailure_.Failed())
            {
                co_return ControlFailure_;
            }
            const auto PendingStatus = RetryPendingResponses();
            if (PendingStatus != Prism::Fault::Code::Success)
            {
                co_return Prism::Fault::Failure{PendingStatus};
            }
            if (!co_await Flush())
            {
                co_return Prism::Fault::Failure{Prism::Fault::Code::IoError};
            }
            if (Part.Failure.Code == Prism::Fault::Code::Eof)
            {
                co_return Completed_
                    ? Prism::Fault::Failure{}
                    : Prism::Fault::Failure{Prism::Fault::Code::IoError};
            }
        }
        co_return Prism::Fault::Failure{};

    }

    [[nodiscard]] auto ServerSession::RetryPendingResponses() -> Prism::Fault::Code
    {
        auto Iterator = Streams_.begin();
        while (Iterator != Streams_.end())
        {
            auto &State = Iterator->second;
            bool Blocked = false;
            bool Erased = false;
            while (!State.PendingResponses.empty())
            {
                auto &Wire = State.PendingResponses.front();
                const auto Count = (std::min)(std::size_t{16U * 1024U}, Wire.size() - State.PendingOffset);
                const auto Chunk = std::span<const std::byte>(Wire).subspan(State.PendingOffset, Count);
                const auto Status = Session_->SubmitData(Iterator->first, Chunk, false);
                if (Status == H2::SubmitDataStatus::Blocked)
                {
                    Blocked = true;
                    break;
                }
                if (Status == H2::SubmitDataStatus::Closed)
                {
                    Iterator = Streams_.erase(Iterator);
                    Erased = true;
                    break;
                }
                if (Status == H2::SubmitDataStatus::Invalid)
                {
                    return Prism::Fault::Code::ProtocolError;
                }
                State.PendingOffset += Count;
                if (State.PendingOffset == Wire.size())
                {
                    State.PendingResponses.pop_front();
                    State.PendingOffset = 0;
                }
            }
            if (Erased)
            {
                continue;
            }
            if (!Blocked && State.TrailersPending && State.PendingResponses.empty())
            {
                if (const auto Headers = Session_->SubmitHeaders(
                        Iterator->first, MakeResponseTrailers(0), true); !Headers)
                {
                    return Headers.error().Code;
                }
                Completed_ = true;
                Iterator = Streams_.erase(Iterator);
                continue;
            }
            ++Iterator;
        }
        return Prism::Fault::Code::Success;

    }

    [[nodiscard]] auto ServerSession::Flush() -> Net::awaitable<bool>
    {
        std::vector<std::byte> Output;
        if (!Session_->Collect(Output) || Output.empty())
        {
            co_return true;
        }
        std::size_t Offset = 0;
        while (Offset < Output.size())
        {
            const auto Part = co_await Transport_->WriteSome(
                std::span<const std::byte>(Output).subspan(Offset));
            const auto Error = Prism::Fault::ToNative(Part.Failure);
            const auto Written = Part.Bytes;
            if (Error || Written == 0U || Written > Output.size() - Offset)
            {
                co_return false;
            }
            Offset += Written;
        }
        co_return true;

    }

    auto ServerSession::OnHeaders(const std::int32_t StreamId, const H2::HeaderList& Headers, const bool EndStream)
            -> void
    {
        auto [Iterator, Inserted] = Streams_.try_emplace(StreamId, Config_.MaxMessageBytes);
        if (!Inserted || Iterator->second.ResponseStarted)
        {
            const auto Reset = Session_->ResetStream(StreamId, H2::ErrorProtocol);
            if (!Reset) RecordControlFailure(Reset.error());
            return;
        }
        const auto Request = ParseRequestHeaders(Headers);
        if (!Request || Request->Path != Config_.Path || EndStream)
        {
            Iterator->second.ResponseStarted = true;
            const auto Response = Session_->SubmitHeaders(StreamId,
                {{":status", "415"}, {"content-type", "application/grpc"}}, false);
            const auto Trailers = Session_->SubmitHeaders(
                StreamId, MakeResponseTrailers(12), true);
            if (!Response) RecordControlFailure(Response.error());
            if (!Trailers) RecordControlFailure(Trailers.error());
            return;
        }
        Iterator->second.Accepted = true;
        Iterator->second.ResponseStarted = true;
        const auto ResponseHeaders = Session_->SubmitHeaders(
            StreamId, MakeResponseHeaders(), false);
        if (!ResponseHeaders) RecordControlFailure(ResponseHeaders.error());

    }

    auto ServerSession::OnData(const std::int32_t StreamId, const std::span<const std::byte> Data) -> void
    {
        const auto Iterator = Streams_.find(StreamId);
        if (Iterator == Streams_.end() || !Iterator->second.Accepted)
        {
            return;
        }
        std::vector<std::vector<std::byte>> Messages;
        if (!Iterator->second.Decoder.Feed(Data, Messages))
        {
            const auto Reset = Session_->ResetStream(StreamId, H2::ErrorProtocol);
            if (!Reset) RecordControlFailure(Reset.error());
            return;
        }
        for (const auto& Message : Messages)
        {
            std::vector<std::byte> Response;
            if (Handler_)
            {
                Response = Handler_(std::span<const std::byte>(Message));
            }
            else
            {
                Response.assign(Message.begin(), Message.end());
            }
            Iterator->second.PendingResponses.emplace_back(EncodeMessage(Response));
        }

    }

    auto ServerSession::OnStreamClose(const H2::StreamReceiveClosure &Closure) -> void
    {
        const auto Iterator = Streams_.find(Closure.StreamId);
        if (Iterator == Streams_.end())
        {
            return;
        }
        if (Closure.Kind == H2::StreamReceiveClosureKind::Reset)
        {
            Streams_.erase(Iterator);
            return;
        }
        if (Iterator->second.Accepted && Iterator->second.Decoder.Empty())
        {
            Iterator->second.TrailersPending = true;
            return;
        }
        Streams_.erase(Iterator);

    }

    auto ServerSession::RecordControlFailure(const Prism::Fault::Failure Failure) -> void
    {
        if (ControlFailure_.Succeeded()) ControlFailure_ = Failure;

    }

}
