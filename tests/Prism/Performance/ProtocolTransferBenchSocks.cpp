/**
 * @file ProtocolTransferBenchSocks.cpp
 * @brief ProtocolTransferBench module owner.
 */

#include "ProtocolTransferBench.hpp"

namespace ProtocolTransferBench
{
    auto RunSocksServer(const LaneExecution &Request) -> Net::awaitable<void>
    {
        auto &Metric = *Request.Metric;
        Net::ip::tcp::socket Socket(Request.Acceptor->get_executor());
        boost::system::error_code AcceptError;
        co_await Request.Acceptor->async_accept(
            Socket, Net::redirect_error(Net::use_awaitable, AcceptError));
        if (AcceptError)
        {
            ++Metric.Errors;
            SignalLaneReady(Metric, true, Request.Ready);
            SignalLaneTransfer(Metric, true, Request.TransferDone);
            co_await WaitLaneEnd(Request, true);
            SignalLaneCleanup(Metric, true, Request.CleanupDone);
            co_return;
        }
        auto Reliable = std::make_shared<Transport::Reliable>(std::move(Socket));
        auto [ErrorValue, ProtocolRequest, Conn] = co_await Socks5::Accept(
            Reliable, Socks5::ServerConfig{});
        (void)ProtocolRequest;
        if (ErrorValue != Error::None || !Conn)
        {
            ++Metric.Errors;
            SignalLaneReady(Metric, true, Request.Ready);
            SignalLaneTransfer(Metric, true, Request.TransferDone);
            co_await WaitLaneEnd(Request, true);
            SignalLaneCleanup(Metric, true, Request.CleanupDone);
            co_return;
        }
        Metric.ServerOwner = Conn;
        Metric.ServerBuffer = std::make_shared<std::vector<std::uint8_t>>(Request.BlockSize);
        SignalLaneReady(Metric, true, Request.Ready);
        (void)co_await Request.Start->async_receive(Net::use_awaitable);
        while (Metric.ServerBytes < Request.Total)
        {
            std::error_code ErrorCode;
            const auto Limit = (std::min)(Request.BlockSize, Request.Total - Metric.ServerBytes);
            const auto Read = co_await Conn->ReadSome(
                AsBytes(*Metric.ServerBuffer).first(Limit));
            ErrorCode = Prism::Fault::ToNative(Read.Failure);
            const auto Count = Read.Bytes;
            if (ErrorCode || Count == 0 || Count > Limit)
            {
                ++Metric.Errors;
                break;
            }
            if (Count < Limit)
            {
                ++Metric.PartialIo;
            }
            HashBytes(Metric.ServerInputHash,
                      AsConstBytes(*Metric.ServerBuffer).first(Count));
            Metric.ServerBytes += Count;
            const auto Written = co_await WriteAll(
                Conn, AsConstBytes(*Metric.ServerBuffer).first(Count), ErrorCode);
            if (ErrorCode || Written != Count)
            {
                ++Metric.Errors;
                break;
            }
        }
        Metric.ServerComplete = Metric.Errors == 0 && Metric.ServerBytes == Request.Total;
        SignalLaneTransfer(Metric, true, Request.TransferDone);
        co_await WaitLaneEnd(Request, true);
        ReleaseLaneMetric(Metric, true);
        SignalLaneCleanup(Metric, true, Request.CleanupDone);
    }

    auto RunSocksClient(const LaneExecution &Request) -> Net::awaitable<void>
    {
        auto &Metric = *Request.Metric;
        auto Reliable = std::make_shared<Transport::Reliable>(Request.Acceptor->get_executor());
        const auto ConnectError = co_await Reliable->Connect(
            Net::ip::tcp::endpoint(Net::ip::address_v4::loopback(),
                                   Request.Acceptor->local_endpoint().port()));
        if (ConnectError)
        {
            ++Metric.Errors;
            SignalLaneReady(Metric, false, Request.Ready);
            SignalLaneTransfer(Metric, false, Request.TransferDone);
            co_await WaitLaneEnd(Request, false);
            SignalLaneCleanup(Metric, false, Request.CleanupDone);
            co_return;
        }
        auto [ErrorValue, Conn] = co_await Socks5::Connect(
            Reliable, Socks5::ClientConfig{},
            Socks5::Address{Socks5::AddressType::Domain, "Target.internal", 443});
        if (ErrorValue != Error::None || !Conn)
        {
            ++Metric.Errors;
            SignalLaneReady(Metric, false, Request.Ready);
            SignalLaneTransfer(Metric, false, Request.TransferDone);
            co_await WaitLaneEnd(Request, false);
            SignalLaneCleanup(Metric, false, Request.CleanupDone);
            co_return;
        }
        Metric.ClientOwner = Conn;
        SignalLaneReady(Metric, false, Request.Ready);
        (void)co_await Request.Start->async_receive(Net::use_awaitable);
        const auto ChunkCount =
            (Request.BlockSize + sizeof(AlignedPayload) - 1U) / sizeof(AlignedPayload);
        Metric.ClientChunks = std::make_shared<std::vector<AlignedPayload>>(ChunkCount);
        auto Chunk = std::as_writable_bytes(std::span<AlignedPayload>(*Metric.ClientChunks));
        Metric.ClientEcho = std::make_shared<std::vector<std::uint8_t>>(Request.BlockSize);
        while (Metric.ClientSent < Request.Total)
        {
            const auto Limit = (std::min)(Request.BlockSize, Request.Total - Metric.ClientSent);
            FillPayload(Chunk.first(Limit), Metric.ClientSent);
            const auto Start = NowNs();
            std::error_code ErrorCode;
            const auto Written = co_await WriteAll(
                Conn, std::span<const std::byte>(Chunk).first(Limit), ErrorCode);
            if (ErrorCode || Written != Limit)
            {
                ++Metric.Errors;
                break;
            }
            if (Written < Limit)
            {
                ++Metric.PartialIo;
            }
            Metric.ClientSent += Written;
            const auto Read = co_await ReadExact(
                Conn, AsBytes(*Metric.ClientEcho).first(Written), ErrorCode);
            if (ErrorCode || Read != Written)
            {
                ++Metric.Errors;
                break;
            }
            if (Read < Written)
            {
                ++Metric.PartialIo;
            }
            Metric.ClientEchoed += Read;
            HashBytes(Metric.ClientOutputHash,
                      AsConstBytes(*Metric.ClientEcho).first(Read));
            Metric.BlockSamples.push_back(NowNs() - Start);
        }
        Metric.ClientComplete = Metric.Errors == 0 &&
                                 Metric.ClientSent == Request.Total &&
                                 Metric.ClientEchoed == Request.Total;
        SignalLaneTransfer(Metric, false, Request.TransferDone);
        co_await WaitLaneEnd(Request, false);
        ReleaseLaneMetric(Metric, false);
        SignalLaneCleanup(Metric, false, Request.CleanupDone);
    }

    auto RunSocksServerGuarded(LaneExecution Request) -> Net::awaitable<void>
    {
        try
        {
            co_await RunSocksServer(Request);
            co_return;
        }
        catch (...)
        {
            ++Request.Metric->Errors;
            SignalLaneReady(*Request.Metric, true, Request.Ready);
            SignalLaneTransfer(*Request.Metric, true, Request.TransferDone);
        }
        co_await WaitLaneEnd(Request, true);
        ReleaseLaneMetric(*Request.Metric, true);
        SignalLaneCleanup(*Request.Metric, true, Request.CleanupDone);
    }

    auto RunSocksClientGuarded(LaneExecution Request) -> Net::awaitable<void>
    {
        try
        {
            co_await RunSocksClient(Request);
            co_return;
        }
        catch (...)
        {
            ++Request.Metric->Errors;
            SignalLaneReady(*Request.Metric, false, Request.Ready);
            SignalLaneTransfer(*Request.Metric, false, Request.TransferDone);
        }
        co_await WaitLaneEnd(Request, false);
        ReleaseLaneMetric(*Request.Metric, false);
        SignalLaneCleanup(*Request.Metric, false, Request.CleanupDone);
    }

    auto RunSocksLane(LaneExecution Request) -> Net::awaitable<void>
    {
        const auto Executor = Request.Acceptor->get_executor();
        const auto ServerEnd = std::make_shared<DoneChannel>(Executor, 1);
        const auto ClientEnd = std::make_shared<DoneChannel>(Executor, 1);
        auto ServerRequest = Request;
        auto ClientRequest = Request;
        ServerRequest.End = ServerEnd;
        ClientRequest.End = ClientEnd;
        Net::co_spawn(Executor, RunSocksServerGuarded(std::move(ServerRequest)), Net::detached);
        Net::co_spawn(Executor, RunSocksClientGuarded(std::move(ClientRequest)), Net::detached);
        co_await Request.TransferDone->async_receive(Net::use_awaitable);
        co_await Request.TransferDone->async_receive(Net::use_awaitable);
        (void)Request.Done->try_send(boost::system::error_code{});
        PrintLaneDiagnostic(*Request.Metric, "coordinator", "done-sent");
        co_await Request.End->async_receive(Net::use_awaitable);
        PrintLaneDiagnostic(*Request.Metric, "coordinator", "end-received");
        (void)ServerEnd->try_send(boost::system::error_code{});
        (void)ClientEnd->try_send(boost::system::error_code{});
        co_await Request.CleanupDone->async_receive(Net::use_awaitable);
        co_await Request.CleanupDone->async_receive(Net::use_awaitable);
        PrintLaneDiagnostic(*Request.Metric, "coordinator", "cleanup-joined");
        (void)Request.Exited->try_send(boost::system::error_code{});
        PrintLaneDiagnostic(*Request.Metric, "coordinator", "exited");
    }


}
