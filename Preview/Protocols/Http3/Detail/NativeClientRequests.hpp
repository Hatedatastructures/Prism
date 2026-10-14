/**
 * @file NativeClientRequests.hpp
 * @brief HTTP/3 client请求与QUIC双向流交付。
 */
#pragma once

#include <optional>

#include <Preview/Protocols/Http3/Detail/NativeClient.hpp>

namespace Preview::Http3::Detail
{
    inline auto NativeClientSessionOwner::SendRequest(RequestHead Request)
        -> Net::awaitable<std::expected<ResponseHead, Preview::Fault::Failure>>
    {
        std::optional<std::expected<ResponseHead, Preview::Fault::Failure>> Result;
        std::exception_ptr Exception;
        try
        {
            Result.emplace(co_await SendRequestCore(std::move(Request)));
        }
        catch (...)
        {
            Exception = std::current_exception();
        }
        if (Exception)
        {
            const auto Failure =
                Preview::Contract::InboundAdmission::ExceptionFailure(
                    std::move(Exception));
            RecordFailure(Failure);
            CloseOnExecutor();
            co_return std::unexpected(CurrentFailure(Failure.Code));
        }
        co_return std::move(*Result);
    }

    inline auto NativeClientSessionOwner::SendRequestCore(RequestHead Request)
        -> Net::awaitable<std::expected<ResponseHead, Preview::Fault::Failure>>
    {
        co_await Net::dispatch(Options_.Executor, Net::use_awaitable);
        if (!Tasks_.Enter())
        {
            co_return std::unexpected(CurrentFailure(Fault::Code::Canceled));
        }
        TaskReservation Reservation{Tasks_};
        if (RequestActive_ || (RequestStream_ && !ResponseDone_))
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Fault::Code::ResourceUnavailable});
        }
        RequestReservation RequestSlot{RequestActive_};
        ResponseHeaders_.Clear();
        ResponseStatus_ = 0;
        ResponseHeadersDone_ = false;
        ResponseDone_ = false;
        ResponseFin_ = false;
        ResponseStreamId_ = -1;
        if (!Options_.Connection)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Fault::Code::InvalidArgument});
        }
        const auto Setup = co_await EnsureReady();
        if (Closed_)
        {
            co_return std::unexpected(CurrentFailure(Fault::Code::Canceled));
        }
        if (!Setup)
        {
            RecordFailure(Setup.error());
            CloseOnExecutor();
            co_return std::unexpected(CurrentFailure(Setup.error().Code));
        }
        auto Opened = co_await Options_.Connection->OpenBidirectionalStream();
        if (!Opened)
        {
            co_return std::unexpected(Opened.error());
        }
        RequestStream_ = std::move(*Opened);
        TrackPendingProvider(RequestStream_);
        if (Closed_)
        {
            const auto Closed = RequestStream_->Close();
            if (!Closed) RecordFailure(Closed.error());
            co_return std::unexpected(CurrentFailure(Fault::Code::Canceled));
        }
        if (RequestStream_->StreamId() < 0)
        {
            RecordFailure({Fault::Code::ProtocolError});
            CloseOnExecutor();
            co_return std::unexpected(
                CurrentFailure(Fault::Code::ProtocolError));
        }
        Streams_[RequestStream_->StreamId()] = RequestStream_;
        ForgetPendingProvider(RequestStream_);
        RequestStreamId_ = RequestStream_->StreamId();
        RequestHeaders_.emplace(std::move(Request.Headers));
        RequestFin_ = Request.Fin;
        if (!NativeClientCallbacks::Submit(*this))
        {
            RecordFailure({Fault::Code::ProtocolError});
            CloseOnExecutor();
            co_return std::unexpected(CurrentFailure(Fault::Code::ProtocolError));
        }
        if (!SpawnReadLoop(RequestStream_))
        {
            RecordFailure({Fault::Code::ResourceUnavailable});
            CloseOnExecutor();
            co_return std::unexpected(
                CurrentFailure(Fault::Code::ResourceUnavailable));
        }
        const auto Output = co_await DrainOutput();
        if (Closed_)
        {
            co_return std::unexpected(CurrentFailure(Fault::Code::Canceled));
        }
        if (!Output)
        {
            RecordFailure(Output.error());
            CloseOnExecutor();
            co_return std::unexpected(CurrentFailure(Output.error().Code));
        }
        co_return co_await ReceiveResponse();
    }

    inline auto NativeClientSessionOwner::EnsureReady()
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        if (Closed_ || !Options_.Connection)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Fault::Code::Canceled});
        }
        if (Ready_)
        {
            co_return std::expected<void, Preview::Fault::Failure>{};
        }
        Options_.Connection->Start();
        if (!co_await Options_.Connection->WaitHandshake())
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Fault::Code::TlsHsfail});
        }
        if (Closed_)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Fault::Code::Canceled});
        }
        const auto Opened = co_await OpenInitialStreams();
        if (!Opened) co_return std::unexpected(Opened.error());
        if (Closed_)
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Fault::Code::Canceled});
        }
        if (!InitializeHttp3())
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Fault::Code::ProtocolError});
        }
        if (!SpawnAcceptLoop())
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Fault::Code::ResourceUnavailable});
        }
        Ready_ = true;
        co_return std::expected<void, Preview::Fault::Failure>{};
    }

    inline auto NativeClientSessionOwner::OpenInitialStreams()
        -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
    {
        for (auto &Provider : Http3Streams_)
        {
            auto Opened = co_await Options_.Connection->OpenUnidirectionalStream();
            if (!Opened)
            {
                RecordFailure(Opened.error());
                co_return std::unexpected(Opened.error());
            }
            Provider = std::move(*Opened);
            TrackPendingProvider(Provider);
            if (Closed_)
            {
                const auto Closed = Provider->Close();
                if (!Closed)
                {
                    RecordFailure(Closed.error());
                    co_return std::unexpected(Closed.error());
                }
                co_return std::unexpected(
                    Preview::Fault::Failure{Fault::Code::Canceled});
            }
            if (Provider->StreamId() < 0)
            {
                RecordFailure({Fault::Code::ProtocolError});
                co_return std::unexpected(
                    Preview::Fault::Failure{Fault::Code::ProtocolError});
            }
            Streams_[Provider->StreamId()] = Provider;
            ForgetPendingProvider(Provider);
        }
        co_return std::expected<void, Preview::Fault::Failure>{};
    }

    inline auto NativeClientSessionOwner::ReceiveResponse()
        -> Net::awaitable<std::expected<ResponseHead, Preview::Fault::Failure>>
    {
        while (!Closed_ && !ResponseHeadersDone_)
        {
            auto Event = co_await Events_->Receive();
            if (Closed_)
            {
                co_return std::unexpected(CurrentFailure(Fault::Code::Canceled));
            }
            if (!Event)
            {
                co_return std::unexpected(CurrentFailure(Fault::Code::IoError));
            }
            const auto Handled = co_await HandleEvent(*Event);
            if (Closed_)
            {
                co_return std::unexpected(CurrentFailure(Fault::Code::Canceled));
            }
            if (!Handled)
            {
                RecordFailure(Handled.error());
                CloseOnExecutor();
                co_return std::unexpected(CurrentFailure(Handled.error().Code));
            }
        }
        if (Closed_ || !ResponseHeadersDone_)
        {
            co_return std::unexpected(CurrentFailure(Fault::Code::Canceled));
        }
        auto Headers = std::move(ResponseHeaders_);
        co_return ResponseHead{
            RequestStreamId_, ResponseStatus_, std::move(Headers), ResponseFin_};
    }

    inline auto NativeClientSessionOwner::OpenBidirectionalStream()
        -> Net::awaitable<std::expected<Preview::Quic::SharedStreamProvider,
                                        Preview::Fault::Failure>>
    {
        std::optional<std::expected<Preview::Quic::SharedStreamProvider,
                                    Preview::Fault::Failure>> Result;
        std::exception_ptr Exception;
        try
        {
            Result.emplace(co_await OpenBidirectionalStreamCore());
        }
        catch (...)
        {
            Exception = std::current_exception();
        }
        if (Exception)
        {
            const auto Failure =
                Preview::Contract::InboundAdmission::ExceptionFailure(
                    std::move(Exception));
            RecordFailure(Failure);
            CloseOnExecutor();
            co_return std::unexpected(CurrentFailure(Failure.Code));
        }
        co_return std::move(*Result);
    }

    inline auto NativeClientSessionOwner::OpenBidirectionalStreamCore()
        -> Net::awaitable<std::expected<Preview::Quic::SharedStreamProvider,
                                        Preview::Fault::Failure>>
    {
        co_await Net::dispatch(Options_.Executor, Net::use_awaitable);
        if (!Tasks_.Enter())
        {
            co_return std::unexpected(CurrentFailure(Fault::Code::Canceled));
        }
        TaskReservation Reservation{Tasks_};
        if (Closed_ || !Ready_ || !Options_.Connection)
        {
            auto Code = Fault::Code::InvalidArgument;
            if (Closed_) Code = Fault::Code::Canceled;
            co_return std::unexpected(CurrentFailure(Code));
        }
        auto Opened = co_await Options_.Connection->OpenBidirectionalStream();
        if (!Opened)
        {
            co_return std::unexpected(Opened.error());
        }
        auto Provider = std::move(*Opened);
        TrackPendingProvider(Provider);
        if (Closed_)
        {
            const auto Closed = Provider->Close();
            if (!Closed) RecordFailure(Closed.error());
            co_return std::unexpected(CurrentFailure(Fault::Code::Canceled));
        }
        if (Provider->StreamId() < 0)
        {
            RecordFailure({Fault::Code::ProtocolError});
            CloseOnExecutor();
            co_return std::unexpected(
                CurrentFailure(Fault::Code::ProtocolError));
        }
        ForgetPendingProvider(Provider);
        co_return Provider;
    }
}
