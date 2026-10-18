/**
 * @file NativeServerRun.hpp
 * @brief HTTP/3 server 运行、输出排空与首因交付。
 */
#pragma once

#include <Prism/Protocols/Http3/Detail/NativeServer.hpp>

namespace Prism::Http3::Detail
{
    inline auto NativeServerSessionOwner::Run()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        std::expected<void, Prism::Fault::Failure> Result;
        std::exception_ptr Exception;
        try
        {
            Result = co_await RunCore();
        }
        catch (...)
        {
            Exception = std::current_exception();
        }
        if (Exception)
        {
            RecordFailure(Prism::Contract::InboundAdmission::ExceptionFailure(
                std::move(Exception)));
            CloseOnExecutor();
            co_return std::unexpected(FirstFailure_);
        }
        co_return Result;
    }

    inline auto NativeServerSessionOwner::RunCore()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await Net::dispatch(Options_.Executor, Net::use_awaitable);
        if (!Tasks_.Enter())
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Fault::Code::Canceled});
        }
        TaskReservation Reservation{Tasks_};
        Observe(NativeServerSessionStage::RunStarted);
        if (!Server_ || !Options_.OpenUnidirectional ||
            !Options_.AcceptUnidirectional || !Options_.AcceptBidirectional)
        {
            Observe(NativeServerSessionStage::Error, Fault::Code::ProtocolError);
            RecordFailure({Fault::Code::ProtocolError});
            CloseOnExecutor();
            co_return std::unexpected(FirstFailure_);
        }
        const auto StreamsOpened = co_await OpenHttp3Streams();
        if (!StreamsOpened &&
            !(Closed_ && StreamsOpened.error().Code == Fault::Code::Canceled))
        {
            RecordFailure(StreamsOpened.error());
        }
        if (Closed_)
        {
            if (FirstFailure_.Failed()) co_return std::unexpected(FirstFailure_);
            if (!StreamsOpened && StreamsOpened.error().Code != Fault::Code::Canceled)
            {
                co_return std::unexpected(StreamsOpened.error());
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        if (!StreamsOpened)
        {
            Observe(NativeServerSessionStage::OpenHttp3Streams,
                    StreamsOpened.error().Code);
            CloseOnExecutor();
            co_return std::unexpected(FirstFailure_);
        }
        Observe(NativeServerSessionStage::OpenHttp3Streams);
        if (!InitializeHttp3())
        {
            Observe(NativeServerSessionStage::InitializeHttp3,
                    Fault::Code::ProtocolError);
            RecordFailure({Fault::Code::ProtocolError});
            CloseOnExecutor();
            co_return std::unexpected(FirstFailure_);
        }
        Observe(NativeServerSessionStage::InitializeHttp3);
        if (!SpawnAcceptLoop(true) || !SpawnAcceptLoop(false))
        {
            RecordFailure({Fault::Code::ResourceUnavailable});
            CloseOnExecutor();
            co_return std::unexpected(FirstFailure_);
        }
        const auto Output = co_await NativeServerOutputDriver::Drain(*this);
        if (Closed_)
        {
            if (FirstFailure_.Failed()) co_return std::unexpected(FirstFailure_);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        if (!Output)
        {
            Observe(NativeServerSessionStage::DrainOutput, Output.error().Code);
            RecordFailure(Output.error());
            CloseOnExecutor();
            co_return std::unexpected(FirstFailure_);
        }
        while (!Closed_)
        {
            auto Event = co_await Events_->Receive();
            if (!Event) break;
            const auto Handled = co_await HandleEvent(*Event);
            if (Closed_) break;
            if (!Handled)
            {
                RecordFailure(Handled.error());
                Observe(NativeServerSessionStage::Error, Handled.error().Code);
                break;
            }
        }
        auto Status = Fault::Code::Success;
        if (FirstFailure_.Failed()) Status = FirstFailure_.Code;
        Observe(NativeServerSessionStage::RunFinished, Status);
        CloseOnExecutor();
        if (FirstFailure_.Failed()) co_return std::unexpected(FirstFailure_);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }
}
