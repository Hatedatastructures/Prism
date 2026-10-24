/**
 * @file FactoryScenario.hpp
 * @brief XHTTP factory Stream-one 端到端场景驱动。
 */
#pragma once

#include "XhttpNgxE2ESupport.hpp"

namespace
{
    struct FactoryClientRequest final
    {
        SharedTransmission Raw;
        SharedSslContext Context;
        Xhttp::Config Config;
        std::string Host;
        std::string Payload;
        std::shared_ptr<bool> Succeeded;
        std::shared_ptr<FactoryScenarioRequest::SplitTrace> Trace;
    };

    struct FactoryServerRequest final
    {
        SharedTransmission Raw;
        SharedSslContext Context;
        Xhttp::Config Config;
        std::string Payload;
        std::shared_ptr<bool> Succeeded;
        std::shared_ptr<FactoryScenarioRequest::SplitTrace> Trace;
    };

    auto RunFactoryClient(FactoryClientRequest Request) -> Net::awaitable<void>
    {
        *Request.Succeeded = false;
        if (Request.Trace) Request.Trace->ClientStage = "connect:start";
        auto Connected = co_await Xhttp::Connect(Xhttp::ClientConnectRequest{
            std::move(Request.Raw), Request.Context.get(), Request.Config, Request.Host,
            MakeXhttpFactoryBytes()});
        if (!Connected)
        {
            if (Request.Trace) Request.Trace->ClientStage = "connect:failed";
            co_return;
        }
        if (Request.Trace) Request.Trace->ClientStage = "connect:ok";
        auto Transport = std::move(*Connected);

        const auto PayloadBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Request.Payload.data()), Request.Payload.size());
        std::error_code WriteError;
        const auto Write = co_await Transport->WriteExact(PayloadBytes);
        WriteError = Prism::Fault::ToNative(Write.Failure);
        const auto BytesWritten = Write.Bytes;
        if (WriteError || BytesWritten != PayloadBytes.size())
        {
            if (Request.Trace)
            {
                Request.Trace->ClientBytes = BytesWritten;
                Request.Trace->ClientError = ErrorText(WriteError);
                Request.Trace->ClientStage = "write:failed";
            }
            const auto Retirement = co_await CloseAndDrainXhttp(Transport);
            if (!Retirement) *Request.Succeeded = false;
            co_return;
        }
        if (Request.Trace) Request.Trace->ClientStage = "write:ok";

        const auto Finished = co_await Transport->WriteShutdown();
        if (!Finished)
        {
            if (Request.Trace)
            {
                Request.Trace->ClientError = ErrorText(
                    Prism::Fault::ToNative(Finished.error()));
                Request.Trace->ClientStage = "write-shutdown:failed";
            }
            const auto Retirement = co_await CloseAndDrainXhttp(Transport);
            if (!Retirement) *Request.Succeeded = false;
            co_return;
        }

        std::vector<std::byte> Received;
        std::array<std::byte, 256> Buffer{};
        std::error_code ReadError;
        bool ResponseEnded = false;
        if (Request.Trace) Request.Trace->ClientStage = "read:response";
        while (!ResponseEnded)
        {
            const auto Read = co_await Transport->ReadSome(Buffer);
            ReadError = Prism::Fault::ToNative(Read.Failure);
            const auto BytesRead = Read.Bytes;
            if (ReadError)
            {
                if (Request.Trace)
                {
                    Request.Trace->ClientError = ErrorText(ReadError);
                    Request.Trace->ClientStage = "read:failed";
                }
                const auto Retirement = co_await CloseAndDrainXhttp(Transport);
                if (!Retirement) *Request.Succeeded = false;
                co_return;
            }
            if (BytesRead == 0)
            {
                ResponseEnded = true;
                if (Request.Trace) Request.Trace->ClientStage = "read:end-stream";
                break;
            }
            const auto ReceivedSpan = std::span<const std::byte>(Buffer.data(), BytesRead);
            Received.insert(Received.end(), ReceivedSpan.begin(), ReceivedSpan.end());
            if (Request.Trace) Request.Trace->ClientBytes += BytesRead;
        }

        const auto ReceivedBytes = std::span<const std::byte>(Received);
        const bool PayloadValid = Received.size() == Request.Payload.size() &&
            HasPayload(ReceivedBytes, Request.Payload);
        *Request.Succeeded = ResponseEnded && PayloadValid;
        if (Request.Trace)
            Request.Trace->ClientStage = *Request.Succeeded
                ? "response:payload+end-stream" : "response:payload-mismatch";
        const auto Retirement = co_await CloseAndDrainXhttp(Transport);
        *Request.Succeeded = *Request.Succeeded && Retirement.has_value();
        if (Request.Trace)
        {
            if (!Retirement)
            {
                Request.Trace->ClientError = ErrorText(
                    Prism::Fault::ToNative(Retirement.error()));
                Request.Trace->ClientStage = "close-drain:failed";
            }
            else if (*Request.Succeeded)
            {
                Request.Trace->ClientStage = "complete";
            }
        }
        Transport.reset();
        co_return;
    }

    auto RunFactoryServer(FactoryServerRequest Request) -> Net::awaitable<void>
    {
        *Request.Succeeded = false;
        if (Request.Trace) Request.Trace->ServerStage = "accept:start";
        auto Accepted = co_await Xhttp::Accept(Xhttp::AcceptRequest{
            std::move(Request.Raw), *Request.Context, Request.Config, MakeXhttpFactoryBytes()});
        if (!Accepted)
        {
            if (Request.Trace)
            {
                Request.Trace->ServerStage = "accept:failed";
                Request.Trace->ServerError = ErrorText(
                    Prism::Fault::ToNative(Accepted.error()));
            }
            co_return;
        }
        if (Request.Trace) Request.Trace->ServerStage = "accept:ok";
        auto Transport = std::move(Accepted->Transport);

        std::array<std::byte, 256> Buffer{};
        std::error_code ReadError;
        if (Request.Trace) Request.Trace->ServerStage = "read:start";
        const auto Read = co_await Transport->ReadSome(Buffer);
        ReadError = Prism::Fault::ToNative(Read.Failure);
        const auto BytesRead = Read.Bytes;
        if (Request.Trace)
        {
            Request.Trace->ServerBytes = BytesRead;
            Request.Trace->ServerError = ErrorText(ReadError);
        }
        if (ReadError || BytesRead == 0)
        {
            if (Request.Trace) Request.Trace->ServerStage = "read:failed";
            const auto Retirement = co_await CloseAndDrainXhttp(Transport);
            if (!Retirement && Request.Trace)
                Request.Trace->ServerRetirementError = ErrorText(
                    Prism::Fault::ToNative(Retirement.error()));
            if (!Retirement) *Request.Succeeded = false;
            co_return;
        }

        const auto EchoSpan = std::span<const std::byte>(Buffer.data(), BytesRead);
        std::error_code WriteError;
        if (Request.Trace) Request.Trace->ServerStage = "write:start";
        const auto Write = co_await Transport->WriteExact(EchoSpan);
        WriteError = Prism::Fault::ToNative(Write.Failure);
        const auto BytesWritten = Write.Bytes;
        const bool WriteSucceeded = !WriteError && BytesWritten == EchoSpan.size();
        *Request.Succeeded = WriteSucceeded;
        if (Request.Trace)
        {
            Request.Trace->ServerBytes = BytesWritten;
            Request.Trace->ServerError = ErrorText(WriteError);
            Request.Trace->ServerStage = WriteSucceeded ? "write:ok" : "write:failed";
        }
        if (WriteSucceeded && Request.Trace)
            Request.Trace->ServerStage = "write-shutdown:start";
        if (WriteSucceeded)
        {
            const auto Finished = co_await Transport->WriteShutdown();
            const bool FinishSucceeded = Finished.has_value();
            *Request.Succeeded = FinishSucceeded;
            if (Request.Trace)
            {
                Request.Trace->ServerStage = FinishSucceeded
                    ? "write-shutdown:ok" : "write-shutdown:failed";
                if (!Finished)
                    Request.Trace->ServerError = ErrorText(
                        Prism::Fault::ToNative(Finished.error()));
            }
        }
        const bool ResponseFinished = *Request.Succeeded;
        if (ResponseFinished && Request.Trace)
            Request.Trace->ServerStage = "close-drain:start";
        const auto Retirement = co_await CloseAndDrainXhttp(Transport);
        *Request.Succeeded = *Request.Succeeded && Retirement.has_value();
        if (Request.Trace)
        {
            if (!Retirement)
            {
                Request.Trace->ServerRetirementError = ErrorText(
                    Prism::Fault::ToNative(Retirement.error()));
                if (ResponseFinished)
                    Request.Trace->ServerStage = "close-drain:failed";
            }
            else if (ResponseFinished)
            {
                Request.Trace->ServerStage = "close-drain:ok";
            }
        }
        Transport.reset();
        co_return;
    }

    auto RunFactoryPair(FactoryScenarioRequest Request) -> Net::awaitable<void>
    {
        FactoryClientRequest ClientRequest{
            std::move(Request.ClientRaw),
            Request.ClientContext,
            Request.Config,
            "example.com",
            Request.Payload,
            Request.ClientSucceeded,
            Request.Trace};
        FactoryServerRequest ServerRequest{
            std::move(Request.ServerRaw),
            Request.ServerContext,
            Request.Config,
            Request.Payload,
            Request.ServerSucceeded,
            Request.Trace};
        auto ClientOperation = Net::co_spawn(
            Request.Executor, RunFactoryClient(std::move(ClientRequest)), Net::use_awaitable);
        auto ServerOperation = Net::co_spawn(
            Request.Executor, RunFactoryServer(std::move(ServerRequest)), Net::use_awaitable);
        co_await (std::move(ClientOperation) && std::move(ServerOperation));
        co_return;
    }

    auto RunFactoryScenario(FactoryScenarioRequest Request) -> Net::awaitable<void>
    {
        auto PairOperation = Net::co_spawn(
            Request.Executor, RunFactoryPair(Request), Net::use_awaitable);
        auto WatchdogOperation = Net::co_spawn(
            Request.Executor,
            RunWatchdog(Request.Executor, std::chrono::seconds(5), Request.TimedOut),
            Net::use_awaitable);
        try
        {
            auto RaceResult = co_await (std::move(PairOperation) || std::move(WatchdogOperation));
            (void)RaceResult;
        }
        catch (...)
        {
            *Request.ClientSucceeded = false;
            *Request.ServerSucceeded = false;
            if (Request.Trace) Request.Trace->Exception = "pair:exception";
        }
        if (Request.ClientRaw)
        {
            const auto Retirement = co_await CloseAndDrainXhttp(Request.ClientRaw);
            if (!Retirement) *Request.ClientSucceeded = false;
        }
        if (Request.ServerRaw)
        {
            const auto Retirement = co_await CloseAndDrainXhttp(Request.ServerRaw);
            if (!Retirement) *Request.ServerSucceeded = false;
        }
        co_return;
    }
}
