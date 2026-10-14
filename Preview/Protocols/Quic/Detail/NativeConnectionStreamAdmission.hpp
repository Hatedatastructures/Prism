/**
 * @file NativeConnectionStreamAdmission.hpp
 * @brief 原生 QUIC 双向与单向流的显式准入结果。
 * @details 区分关闭、尚未就绪、角色错误与 ngtcp2 原生失败；成功结果总持有真实流 owner。
 */
#pragma once

#include <Preview/Protocols/Quic/Detail/NativeConnection.hpp>
#include <Preview/Contract/Ingress/InboundAdmission.hpp>

#include <exception>
#include <optional>
#include <string>
#include <system_error>

namespace Preview::Quic::Detail
{
    class NativeNgTcp2ErrorCategory final : public std::error_category
    {
    public:
        [[nodiscard]] auto name() const noexcept -> const char * override
        {
            return "ngtcp2";
        }

        [[nodiscard]] auto message(const int Value) const -> std::string override
        {
            const auto *Text = ngtcp2_strerror(Value);
            if (Text)
            {
                return Text;
            }
            return "unknown ngtcp2 error";
        }
    };

    [[nodiscard]] inline auto NgTcp2ErrorCategoryValue() noexcept -> const std::error_category &
    {
        static const NativeNgTcp2ErrorCategory Category;
        return Category;
    }

    [[nodiscard]] inline auto StreamCanceled(std::error_code Native = {}) noexcept
        -> Preview::Fault::Failure
    {
        if (!Native)
        {
            return {Preview::Fault::Code::Canceled};
        }
        return {Preview::Fault::Code::Canceled, Native};
    }

    [[nodiscard]] inline auto StreamBlocked() noexcept -> Preview::Fault::Failure
    {
        return {Preview::Fault::Code::Blocked};
    }

    [[nodiscard]] inline auto NgTcp2Failure(const int NativeValue) noexcept
        -> Preview::Fault::Failure
    {
        auto Code = Preview::Fault::Code::IoError;
        if (NativeValue == NGTCP2_ERR_STREAM_ID_BLOCKED)
        {
            Code = Preview::Fault::Code::WouldBlock;
        }
        else if (NativeValue == NGTCP2_ERR_NOBUF)
        {
            Code = Preview::Fault::Code::ResourceUnavailable;
        }
        return {Code, std::error_code{NativeValue, NgTcp2ErrorCategoryValue()}};
    }

    inline auto NativeConnection::AbandonOpenedStream(const std::int64_t StreamId)
        -> std::optional<Preview::Fault::Failure>
    {
        if (!Conn_)
        {
            return {};
        }
        const auto NativeResult = ngtcp2_conn_shutdown_stream(Conn_, 0, StreamId, 0);
        if (NativeResult != 0)
        {
            CloseOnExecutor();
            return NgTcp2Failure(NativeResult);
        }
        QueueFlush();
        return {};
    }

    inline auto NativeConnection::OpenStream(const bool Unidirectional)
        -> Net::awaitable<std::expected<SharedStreamProvider, Preview::Fault::Failure>>
    {
        const auto Self = shared_from_this();
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        OperationReservation Reservation{Self};
        if (!Reservation || Closed_ || !Conn_)
        {
            co_return std::unexpected(StreamCanceled());
        }
        if (!Unidirectional && Role_ != Role::Client)
        {
            co_return std::unexpected(Preview::Fault::Failure{
                Preview::Fault::Code::InvalidArgument});
        }
        if (!HandshakeSignaled_)
        {
            co_return std::unexpected(StreamBlocked());
        }
        if (!HandshakeResult_)
        {
            co_return std::unexpected(Preview::Fault::Failure{
                Preview::Fault::Code::TlsHsfail});
        }

        boost::system::error_code PermitError;
        co_await WritePermit_.async_receive(Net::redirect_error(Net::use_awaitable, PermitError));
        if (PermitError)
        {
            const auto Native = static_cast<std::error_code>(PermitError);
            if (Closed_)
            {
                co_return std::unexpected(StreamCanceled(Native));
            }
            co_return std::unexpected(Preview::Fault::FromNative(Native));
        }
        WritePermitRelease PermitRelease{WritePermit_};
        if (Closed_ || !Conn_)
        {
            co_return std::unexpected(StreamCanceled());
        }

        std::int64_t StreamId = -1;
        auto NativeResult = 0;
        if (Unidirectional)
        {
            NativeResult = ngtcp2_conn_open_uni_stream(Conn_, &StreamId, nullptr);
        }
        else
        {
            NativeResult = ngtcp2_conn_open_bidi_stream(Conn_, &StreamId, nullptr);
        }
        if (NativeResult != 0)
        {
            co_return std::unexpected(NgTcp2Failure(NativeResult));
        }

        try
        {
            auto Made = MakeStream(StreamId, false, Unidirectional);
            if (!Made)
            {
                const auto AbandonFailure = AbandonOpenedStream(StreamId);
                if (AbandonFailure)
                {
                    co_return std::unexpected(*AbandonFailure);
                }
                co_return std::unexpected(Made.error());
            }
            if (!*Made)
            {
                const auto AbandonFailure = AbandonOpenedStream(StreamId);
                if (AbandonFailure)
                {
                    co_return std::unexpected(*AbandonFailure);
                }
                co_return std::unexpected(Preview::Fault::Failure{
                    Preview::Fault::Code::ProtocolError});
            }
            co_return *Made;
        }
        catch (...)
        {
            const auto Failure = Preview::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
            const auto AbandonFailure = AbandonOpenedStream(StreamId);
            if (AbandonFailure)
            {
                co_return std::unexpected(*AbandonFailure);
            }
            co_return std::unexpected(Failure);
        }
    }

    inline auto NativeConnection::OpenBidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Preview::Fault::Failure>>
    {
        co_return co_await OpenStream(false);
    }

    inline auto NativeConnection::OpenUnidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Preview::Fault::Failure>>
    {
        co_return co_await OpenStream(true);
    }

    inline auto NativeConnection::AcceptBidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Preview::Fault::Failure>>
    {
        const auto Self = shared_from_this();
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        OperationReservation Reservation{Self};
        if (!Reservation)
        {
            co_return std::unexpected(StreamCanceled());
        }
        if (Role_ != Role::Server)
        {
            co_return std::unexpected(Preview::Fault::Failure{
                Preview::Fault::Code::InvalidArgument});
        }
        while (true)
        {
            if (Closed_)
            {
                co_return std::unexpected(StreamCanceled());
            }
            if (!IncomingStreams_.empty())
            {
                auto State = std::move(IncomingStreams_.front());
                IncomingStreams_.pop_front();
                const auto StreamId = State->Id;
                try
                {
                    auto Provider = std::make_shared<NativeStream>(weak_from_this(), std::move(State));
                    co_return SharedStreamProvider{std::move(Provider)};
                }
                catch (...)
                {
                    const auto Failure = Preview::Contract::InboundAdmission::ExceptionFailure(
                        std::current_exception());
                    const auto AbandonFailure = AbandonOpenedStream(StreamId);
                    if (AbandonFailure)
                    {
                        co_return std::unexpected(*AbandonFailure);
                    }
                    co_return std::unexpected(Failure);
                }
            }
            IncomingNotify_.reset();
            boost::system::error_code NotifyError;
            co_await IncomingNotify_.async_receive(Net::redirect_error(Net::use_awaitable, NotifyError));
            if (NotifyError)
            {
                const auto Native = static_cast<std::error_code>(NotifyError);
                if (Closed_)
                {
                    co_return std::unexpected(StreamCanceled(Native));
                }
                co_return std::unexpected(Preview::Fault::FromNative(Native));
            }
        }
    }

    inline auto NativeConnection::AcceptUnidirectionalStream()
        -> Net::awaitable<std::expected<SharedStreamProvider, Preview::Fault::Failure>>
    {
        const auto Self = shared_from_this();
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        OperationReservation Reservation{Self};
        if (!Reservation)
        {
            co_return std::unexpected(StreamCanceled());
        }
        while (true)
        {
            if (Closed_)
            {
                co_return std::unexpected(StreamCanceled());
            }
            if (!IncomingUnidirectionalStreams_.empty())
            {
                auto State = std::move(IncomingUnidirectionalStreams_.front());
                IncomingUnidirectionalStreams_.pop_front();
                const auto StreamId = State->Id;
                try
                {
                    auto Provider = std::make_shared<NativeStream>(weak_from_this(), std::move(State));
                    co_return SharedStreamProvider{std::move(Provider)};
                }
                catch (...)
                {
                    const auto Failure = Preview::Contract::InboundAdmission::ExceptionFailure(
                        std::current_exception());
                    const auto AbandonFailure = AbandonOpenedStream(StreamId);
                    if (AbandonFailure)
                    {
                        co_return std::unexpected(*AbandonFailure);
                    }
                    co_return std::unexpected(Failure);
                }
            }
            IncomingUnidirectionalNotify_.reset();
            boost::system::error_code NotifyError;
            co_await IncomingUnidirectionalNotify_.async_receive(
                Net::redirect_error(Net::use_awaitable, NotifyError));
            if (NotifyError)
            {
                const auto Native = static_cast<std::error_code>(NotifyError);
                if (Closed_)
                {
                    co_return std::unexpected(StreamCanceled(Native));
                }
                co_return std::unexpected(Preview::Fault::FromNative(Native));
            }
        }
    }
} // namespace Preview::Quic::Detail
