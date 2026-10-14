/**
 * @file ProtocolTransferBenchVmess.cpp
 * @brief ProtocolTransferBench module owner.
 */

#include "ProtocolTransferBench.hpp"

#include <variant>

namespace ProtocolTransferBench
{
    namespace
    {
        [[nodiscard]] auto WriteVmessAll(
            Vmess::SharedConn Conn,
            std::span<const std::byte> Buffer) -> Net::awaitable<Preview::IoResult>
        {
            Preview::IoResult Result{};
            while (Result.Bytes < Buffer.size())
            {
                const auto Remaining = Buffer.subspan(Result.Bytes);
                const auto Part = co_await Conn->WriteSome(Remaining);
                if (Part.Bytes > Remaining.size())
                {
                    Result.Failure = {Preview::Fault::Code::InvalidArgument, Part.Failure.Native};
                    co_return Result;
                }
                Result.Bytes += Part.Bytes;
                Result.Failure = Part.Failure;
                if (Result.Failure.Failed())
                {
                    co_return Result;
                }
                if (Part.Bytes == 0)
                {
                    Result.Failure = {Preview::Fault::Code::WouldBlock};
                    co_return Result;
                }
            }
            co_return Result;
        }

        [[nodiscard]] auto ReadVmessExact(
            Vmess::SharedConn Conn,
            std::span<std::byte> Buffer) -> Net::awaitable<Preview::IoResult>
        {
            Preview::IoResult Result{};
            while (Result.Bytes < Buffer.size())
            {
                const auto Remaining = Buffer.subspan(Result.Bytes);
                const auto Part = co_await Conn->ReadSome(Remaining);
                if (Part.Bytes > Remaining.size())
                {
                    Result.Failure = {Preview::Fault::Code::InvalidArgument, Part.Failure.Native};
                    co_return Result;
                }
                Result.Bytes += Part.Bytes;
                Result.Failure = Part.Failure;
                if (Result.Failure.Failed())
                {
                    co_return Result;
                }
                if (Part.Bytes == 0)
                {
                    Result.Failure = {Preview::Fault::Code::WouldBlock};
                    co_return Result;
                }
            }
            co_return Result;
        }
    }

    [[nodiscard]] auto VmessUuid() -> std::array<std::uint8_t, 16>
    {
        return {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
    }

    auto RunVmessServer(const LaneExecution &Request) -> Net::awaitable<void>
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
        Vmess::ServerConfig ServerConfig;
        ServerConfig.uuid = VmessUuid();
        auto AcceptResult = co_await Vmess::AcceptSession(Reliable, ServerConfig);
        EXPECT_TRUE(AcceptResult);
        auto *Accepted = AcceptResult
            ? std::get_if<Vmess::AcceptedConnection>(&*AcceptResult)
            : nullptr;
        if (AcceptResult) EXPECT_NE(Accepted, nullptr);
        if (!AcceptResult || !Accepted || !Accepted->Connection)
        {
            if (AcceptResult && std::holds_alternative<Vmess::AcceptedDatagram>(*AcceptResult))
            {
                auto Datagram = std::move(
                    std::get<Vmess::AcceptedDatagram>(*AcceptResult).Connection);
                auto Underlying = Datagram->Stream();
                (void)Datagram->Close();
                (void)Underlying->Close();
                (void)co_await Datagram->Activity()->Drain();
                (void)co_await Underlying->Activity()->Drain();
            }
            ++Metric.Errors;
            SignalLaneReady(Metric, true, Request.Ready);
            SignalLaneTransfer(Metric, true, Request.TransferDone);
            co_await WaitLaneEnd(Request, true);
            SignalLaneCleanup(Metric, true, Request.CleanupDone);
            co_return;
        }
        auto Conn = std::move(Accepted->Connection);
        Metric.ServerOwner = Conn;
        Metric.ServerBuffer = std::make_shared<std::vector<std::uint8_t>>(Request.BlockSize);
        SignalLaneReady(Metric, true, Request.Ready);
        (void)co_await Request.Start->async_receive(Net::use_awaitable);
        while (Metric.ServerBytes < Request.Total)
        {
            const auto Limit = (std::min)(Request.BlockSize, Request.Total - Metric.ServerBytes);
            const auto Read = co_await Conn->ReadSome(
                AsBytes(*Metric.ServerBuffer).first(Limit));
            const auto Count = Read.Bytes;
            if (Count > Limit)
            {
                ++Metric.Errors;
                break;
            }
            if (Count > 0)
            {
                if (Count < Limit)
                {
                    ++Metric.PartialIo;
                }
                HashBytes(Metric.ServerInputHash,
                          AsConstBytes(*Metric.ServerBuffer).first(Count));
                Metric.ServerBytes += Count;
            }
            if (Count == 0)
            {
                ++Metric.Errors;
                break;
            }
            const auto Written = co_await WriteVmessAll(
                Conn, AsConstBytes(*Metric.ServerBuffer).first(Count));
            if (Written.Bytes < Count)
            {
                ++Metric.PartialIo;
            }
            if (Written.Failure.Failed() || Written.Bytes != Count)
            {
                ++Metric.Errors;
                break;
            }
            if (Read.Failure.Failed())
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

    auto RunVmessClient(const LaneExecution &Request) -> Net::awaitable<void>
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
        Vmess::ClientConfig ClientConfig;
        ClientConfig.uuid = VmessUuid();
        auto ConnectResult = co_await Vmess::Connect(Vmess::ConnectParameters{
            Reliable, ClientConfig,
            Vmess::Address{Vmess::AddressType::Domain, "Target.internal", 443}});
        EXPECT_TRUE(ConnectResult);
        if (ConnectResult) EXPECT_TRUE(*ConnectResult);
        if (!ConnectResult || !*ConnectResult)
        {
            ++Metric.Errors;
            SignalLaneReady(Metric, false, Request.Ready);
            SignalLaneTransfer(Metric, false, Request.TransferDone);
            co_await WaitLaneEnd(Request, false);
            SignalLaneCleanup(Metric, false, Request.CleanupDone);
            co_return;
        }
        auto Conn = std::move(*ConnectResult);
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
            const auto Written = co_await WriteVmessAll(
                Conn, std::span<const std::byte>(Chunk).first(Limit));
            if (Written.Bytes > Limit)
            {
                ++Metric.Errors;
                break;
            }
            Metric.ClientSent += Written.Bytes;
            if (Written.Bytes < Limit)
            {
                ++Metric.PartialIo;
            }
            if (Written.Bytes == 0)
            {
                ++Metric.Errors;
                break;
            }
            const auto Read = co_await ReadVmessExact(
                Conn, AsBytes(*Metric.ClientEcho).first(Written.Bytes));
            if (Read.Bytes > Written.Bytes)
            {
                ++Metric.Errors;
                break;
            }
            Metric.ClientEchoed += Read.Bytes;
            if (Read.Bytes < Written.Bytes)
            {
                ++Metric.PartialIo;
            }
            HashBytes(Metric.ClientOutputHash,
                      AsConstBytes(*Metric.ClientEcho).first(Read.Bytes));
            if (Read.Failure.Failed() || Read.Bytes != Written.Bytes ||
                Written.Failure.Failed() || Written.Bytes != Limit)
            {
                ++Metric.Errors;
                break;
            }
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

    auto RunVmessServerGuarded(LaneExecution Request) -> Net::awaitable<void>
    {
        try
        {
            co_await RunVmessServer(Request);
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

    auto RunVmessClientGuarded(LaneExecution Request) -> Net::awaitable<void>
    {
        try
        {
            co_await RunVmessClient(Request);
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

    auto RunVmessLane(LaneExecution Request) -> Net::awaitable<void>
    {
        const auto Executor = Request.Acceptor->get_executor();
        const auto ServerEnd = std::make_shared<DoneChannel>(Executor, 1);
        const auto ClientEnd = std::make_shared<DoneChannel>(Executor, 1);
        auto ServerRequest = Request;
        auto ClientRequest = Request;
        ServerRequest.End = ServerEnd;
        ClientRequest.End = ClientEnd;
        Net::co_spawn(Executor, RunVmessServerGuarded(std::move(ServerRequest)), Net::detached);
        Net::co_spawn(Executor, RunVmessClientGuarded(std::move(ClientRequest)), Net::detached);
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

    [[nodiscard]] auto RunVmessRound(
        const ProtocolRoundOptions& Options) -> ProtocolRound
    {
        return RunProtocolRound(Options, RunVmessLane);
    }


}
