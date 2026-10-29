/**
 * @file PerfMux.cpp
 * @brief 独立的真实 Mux child 传输性能与生命周期 lane。
 * @details 本 target 不复用 TCP transport 对照的 IoEndpoint：Mux::Client/
 *          Server 的根传输和 StreamTransmission 需要在同一条可控内存管道
 *          上验证。根传输通过固定碎片窗口注入可重复 partial I/O，child
 *          则按 Shutdown -> FIN -> peer EOF -> DrainTerminations 收口。
 */

#include "PerfMux.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <limits>
#include <memory>
#include <span>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Protocols/Mux/Client.hpp>
#include <Prism/Protocols/Mux/Server.hpp>
#include <Prism/Protocols/Mux/Smux/Smux.hpp>
#include <Prism/Protocols/Mux/Stream.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Net = boost::asio;
namespace Mux = Prism::Mux;

namespace TransferPerfMux
{
    using MuxClient = Mux::Smux::Client<>;
    using MuxServer = Mux::Smux::Server<>;
    using SharedTransmission = Prism::SharedTransmission;

    struct FragmentMetrics final
    {
        std::size_t ReadPartials{0};
        std::size_t WritePartials{0};
    };

    class FragmentedTransmission final : public Prism::Transmission
    {
    public:
        FragmentedTransmission(
            SharedTransmission Inner,
            const std::size_t Fragment,
            std::shared_ptr<FragmentMetrics> Metrics)
            : Prism::Transmission(Inner->Executor()), Inner_(std::move(Inner)), Fragment_(Fragment),
              Metrics_(std::move(Metrics))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Inner_->Executor();
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(ReadWork{}, Executor()), Handler,
                ReadInput{std::static_pointer_cast<FragmentedTransmission>(Prism::Transmission::shared_from_this()), Buffer});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(WriteWork{}, Executor()), Handler,
                WriteInput{std::static_pointer_cast<FragmentedTransmission>(Prism::Transmission::shared_from_this()), Buffer});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto *Inner = NextLayer())
            {
                Inner->WriteShutdown(std::move(Handler));
                return;
            }
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            (void)Inner_->Close();
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            (void)Inner_->Cancel();
            return {};
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Inner_->IsOpen();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission * override
        {
            return Inner_.get();
        }

    private:
        struct ReadInput final
        {
            std::shared_ptr<FragmentedTransmission> Owner;
            std::span<std::byte> Buffer;
        };
        struct WriteInput final
        {
            std::shared_ptr<FragmentedTransmission> Owner;
            std::span<const std::byte> Buffer;
        };
        /** @brief 原协程体原位保留，新前门一次性映射正式结果。 */
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                std::error_code Error;
                const auto Count = co_await Input.Owner->ReadPartial(Input.Buffer, Error);
                co_return std::tuple{Prism::IoResult{Count, Prism::Fault::FromNative(Error)}};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                std::error_code Error;
                const auto Count = co_await Input.Owner->WritePartial(Input.Buffer, Error);
                co_return std::tuple{Prism::IoResult{Count, Prism::Fault::FromNative(Error)}};
            }
        };
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t>
        {
            const auto Window = Buffer.first((std::min)(Fragment_, Buffer.size()));
            const auto Part = co_await Inner_->ReadSome(Window);
            ErrorCode = Prism::Fault::ToNative(Part.Failure);
            if (Part.Bytes > 0 && Part.Bytes < Buffer.size())
            {
                ++Metrics_->ReadPartials;
            }
            co_return Part.Bytes;
        }
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t>
        {
            const auto Window = Buffer.first((std::min)(Fragment_, Buffer.size()));
            const auto Part = co_await Inner_->WriteSome(Window);
            ErrorCode = Prism::Fault::ToNative(Part.Failure);
            if (Part.Bytes > 0 && Part.Bytes < Buffer.size())
            {
                ++Metrics_->WritePartials;
            }
            co_return Part.Bytes;
        }
        SharedTransmission Inner_;
        std::size_t Fragment_;
        std::shared_ptr<FragmentMetrics> Metrics_;
    };

    struct ServerOutcome final
    {
        std::size_t InputBytes{0};
        std::uint64_t InputHash{InitialHash};
        std::size_t PartialIo{0};
        bool PeerEof{false};
        bool FinSubmitted{false};
        bool FinDrained{false};
        bool Cleanup{false};
        bool Failed{false};
        std::exception_ptr Failure;
    };

    using ServerCompletion =
        Net::experimental::channel<void(boost::system::error_code, ServerOutcome)>;

    auto HashBytes(std::uint64_t &Hash, std::span<const std::byte> Data) -> void
    {
        for (const auto Byte : Data)
        {
            Hash ^= std::to_integer<std::uint8_t>(Byte);
            Hash *= 1099511628211ULL;
        }
    }

    auto FillPayload(std::span<std::byte> Buffer, const std::size_t Offset) -> void
    {
        for (std::size_t Index = 0; Index < Buffer.size(); ++Index)
        {
            Buffer[Index] = std::byte{
                static_cast<unsigned char>((Offset + Index) & 0xFFU)};
        }
    }

    [[nodiscard]] auto PayloadHash(const std::size_t Total) -> std::uint64_t
    {
        std::uint64_t Hash = InitialHash;
        for (std::size_t Offset = 0; Offset < Total; ++Offset)
        {
            Hash ^= static_cast<std::uint8_t>(Offset & 0xFFU);
            Hash *= 1099511628211ULL;
        }
        return Hash;
    }

    [[nodiscard]] auto IsEof(const std::error_code &ErrorCode) -> bool
    {
        return ErrorCode == Prism::Fault::make_error_code(Prism::Fault::Code::Eof);
    }

    [[nodiscard]] auto WriteExact(
        const SharedTransmission &Connection,
        std::span<const std::byte> Data,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        std::size_t Done = 0;
        while (Done < Data.size())
        {
            const auto Written = co_await Connection->WriteSome(Data.subspan(Done));
            ErrorCode = Prism::Fault::ToNative(Written.Failure);
            const auto Count = Written.Bytes;
            if (ErrorCode || Count == 0 || Count > Data.size() - Done)
            {
                co_return Done;
            }
            Done += Count;
        }
        co_return Done;
    }

    struct ServerRequest final
    {
        MuxServer *Server{nullptr};
        LaneInput Input{};
        std::uint64_t ExpectedInputHash{InitialHash};
        std::shared_ptr<ServerCompletion> Completion;
    };

    auto RunServer(ServerRequest Request) -> Net::awaitable<void>
    {
        ServerOutcome Outcome;
        std::shared_ptr<Mux::StreamTransmission> Stream;
        bool CleanupAfterFailure = false;
        try
        {
            auto Handle = co_await Request.Server->Session()->AcceptStream();
            if (!Handle)
            {
                throw std::system_error(std::make_error_code(std::errc::io_error));
            }
            Stream = std::make_shared<Mux::StreamTransmission>(std::move(Handle));
            std::vector<std::byte> Buffer(Request.Input.Block);
            Outcome.InputHash = InitialHash;
            while (Outcome.InputBytes < Request.Input.Total)
            {
                const auto Limit = (std::min)(
                    Request.Input.Block, Request.Input.Total - Outcome.InputBytes);
                std::error_code ErrorCode;
                const auto Read = co_await Stream->ReadSome(
                    std::span<std::byte>(Buffer).first(Limit));
                ErrorCode = Prism::Fault::ToNative(Read.Failure);
                const auto Count = Read.Bytes;
                if (ErrorCode || Count == 0 || Count > Limit)
                {
                    throw std::system_error(
                        ErrorCode ? ErrorCode : std::make_error_code(std::errc::io_error));
                }
                if (Count < Limit)
                {
                    ++Outcome.PartialIo;
                }
                HashBytes(Outcome.InputHash,
                          std::span<const std::byte>(Buffer).first(Count));
                Outcome.InputBytes += Count;
                const auto Written = co_await WriteExact(
                    Stream, std::span<const std::byte>(Buffer).first(Count), ErrorCode);
                if (ErrorCode || Written != Count)
                {
                    throw std::system_error(
                        ErrorCode ? ErrorCode : std::make_error_code(std::errc::io_error));
                }
            }

            std::array<std::byte, 1> Tail{};
            std::error_code PeerError;
            const auto TailRead = co_await Stream->ReadSome(Tail);
            PeerError = Prism::Fault::ToNative(TailRead.Failure);
            const auto TailCount = TailRead.Bytes;
            Outcome.PeerEof = TailCount == 0 && IsEof(PeerError);
            if (!Outcome.PeerEof)
            {
                throw std::system_error(
                    PeerError ? PeerError : std::make_error_code(std::errc::io_error));
            }
            (void)co_await Stream->WriteShutdown();
            Outcome.FinSubmitted = true;
            const auto FinDrain = co_await Stream->DrainTerminations();
            if (!FinDrain)
                throw std::system_error(Prism::Fault::ToNative(FinDrain.error()));
            Outcome.FinDrained = true;
            (void)Stream->Close();
            const auto CloseDrain = co_await Stream->DrainTerminations();
            Outcome.Cleanup = CloseDrain.has_value() && !Stream->IsOpen();
            Outcome.Failed = Outcome.InputHash != Request.ExpectedInputHash;
        }
        catch (...)
        {
            Outcome.Failed = true;
            Outcome.Failure = std::current_exception();
            CleanupAfterFailure = true;
        }
        if (CleanupAfterFailure && Stream)
        {
            (void)Stream->Close();
            const auto CleanupDrain = co_await Stream->DrainTerminations();
            Outcome.Cleanup = CleanupDrain.has_value() && !Stream->IsOpen();
        }
        (void)Request.Completion->try_send(boost::system::error_code{}, std::move(Outcome));
    }

    struct ClientTransferRequest final
    {
        std::shared_ptr<Mux::StreamTransmission> Stream;
        LaneInput Input{};
        MuxLaneResult *Result{nullptr};
    };

    using LaneCompletion = Net::experimental::channel<
        void(boost::system::error_code, std::size_t)>;

    struct LaneRequest final
    {
        MuxClient *Client{nullptr};
        MuxServer *Server{nullptr};
        LaneInput Input{};
        std::size_t LaneId{0};
        bool ServerFirst{true};
        std::uint64_t ExpectedInputHash{InitialHash};
        MuxLaneResult *Result{nullptr};
        std::shared_ptr<LaneCompletion> Completion;
    };

    struct LaneRunCompletionHandler final
    {
        MuxClient *Client{nullptr};
        MuxServer *Server{nullptr};
        MuxLaneResult *Result{nullptr};
        std::shared_ptr<LaneCompletion> Completion;
        std::size_t LaneId{0};

        auto operator()(std::exception_ptr Failure) const -> void
        {
            if (Failure)
            {
                ++Result->Errors;
                Result->NaturalExit = false;
                (void)Client->Close();
                (void)Server->Close();
            }
            (void)Completion->try_send(boost::system::error_code{}, LaneId);
        }
    };

    auto RunClientReceive(ClientTransferRequest Request) -> Net::awaitable<void>
    {
        auto &Result = *Request.Result;
        std::vector<std::byte> Echo(Request.Input.Block);
        std::vector<std::byte> Expected(Request.Input.Block);
        std::size_t Received = 0;
        while (Received < Request.Input.Total)
        {
            const auto Limit = (std::min)(Request.Input.Block, Request.Input.Total - Received);
            std::error_code ErrorCode;
            const auto Read = co_await Request.Stream->ReadSome(
                std::span<std::byte>(Echo).first(Limit));
            ErrorCode = Prism::Fault::ToNative(Read.Failure);
            const auto Count = Read.Bytes;
            if (ErrorCode || Count == 0 || Count > Limit)
            {
                throw std::system_error(
                    ErrorCode ? ErrorCode : std::make_error_code(std::errc::io_error));
            }
            if (Count < Limit)
            {
                ++Result.PartialIo;
            }
            FillPayload(std::span<std::byte>(Expected).first(Count), Received);
            if (!std::equal(
                    Echo.begin(), Echo.begin() + static_cast<std::ptrdiff_t>(Count),
                    Expected.begin()))
            {
                throw std::system_error(std::make_error_code(std::errc::io_error));
            }
            HashBytes(Result.ClientOutputHash,
                      std::span<const std::byte>(Echo).first(Count));
            Received += Count;
        }
        Result.Received = Received;

        std::array<std::byte, 1> Tail{};
        std::error_code PeerError;
        const auto TailRead = co_await Request.Stream->ReadSome(Tail);
        PeerError = Prism::Fault::ToNative(TailRead.Failure);
        const auto TailCount = TailRead.Bytes;
        Result.ClientPeerEof = TailCount == 0 && IsEof(PeerError);
        if (!Result.ClientPeerEof)
        {
            throw std::system_error(
                PeerError ? PeerError : std::make_error_code(std::errc::io_error));
        }
        (void)Request.Stream->Close();
        const auto CleanupDrain = co_await Request.Stream->DrainTerminations();
        Result.ClientCleanup = CleanupDrain.has_value() && !Request.Stream->IsOpen();
    }

    using ClientReceiveCompletion = Net::experimental::channel<void(boost::system::error_code)>;

    /** @brief 同一并行传输的接收任务拥有请求、结束通知和首个异常观察。 */
    struct ClientReceiveTask final
    {
        ClientTransferRequest Request;
        std::shared_ptr<ClientReceiveCompletion> Done;
        std::shared_ptr<std::exception_ptr> Failure;

        auto operator()() -> Net::awaitable<void>
        {
            try { co_await RunClientReceive(Request); }
            catch (...) { *Failure = std::current_exception(); }
            (void)Done->try_send(boost::system::error_code{});
        }
    };

    /** @brief 接收已退栈的server任务异常并提交完整失败结果，保持同一完成channel owner。 */
    struct ServerTransferCompletion final
    {
        std::shared_ptr<ServerCompletion> Completion;

        auto operator()(std::exception_ptr Failure) -> void
        {
            if (!Failure) return;
            ServerOutcome Outcome;
            Outcome.Failed = true;
            Outcome.Failure = std::move(Failure);
            (void)Completion->try_send(boost::system::error_code{}, std::move(Outcome));
        }
    };

    auto RunClientTransfer(ClientTransferRequest Request) -> Net::awaitable<void>
    {
        const auto Executor = co_await Net::this_coro::executor;
        using Completion = Net::experimental::channel<void(boost::system::error_code)>;
        const auto ReaderDone = std::make_shared<Completion>(Executor, 1);
        const auto ReaderFailure = std::make_shared<std::exception_ptr>();

        Net::co_spawn(Executor,
            ClientReceiveTask{Request, ReaderDone, ReaderFailure}, Net::detached);

        std::exception_ptr WriterFailure;
        try
        {
            auto &Result = *Request.Result;
            std::vector<std::byte> Payload(Request.Input.Block);
            std::size_t Sent = 0;
            while (Sent < Request.Input.Total)
            {
                const auto Limit = (std::min)(Request.Input.Block, Request.Input.Total - Sent);
                FillPayload(std::span<std::byte>(Payload).first(Limit), Sent);
                std::error_code ErrorCode;
                const auto Written = co_await WriteExact(
                    Request.Stream, std::span<const std::byte>(Payload).first(Limit), ErrorCode);
                if (ErrorCode || Written != Limit)
                {
                    throw std::system_error(
                        ErrorCode ? ErrorCode : std::make_error_code(std::errc::io_error));
                }
                Sent += Written;
            }
            Result.Sent = Sent;

            (void)co_await Request.Stream->WriteShutdown();
            Result.ClientFinSubmitted = true;
            const auto FinDrain = co_await Request.Stream->DrainTerminations();
            if (!FinDrain)
                throw std::system_error(Prism::Fault::ToNative(FinDrain.error()));
            Result.ClientFinDrained = true;
        }
        catch (...)
        {
            WriterFailure = std::current_exception();
            (void)Request.Stream->Close();
        }

        boost::system::error_code CompletionError;
        co_await ReaderDone->async_receive(
            Net::redirect_error(Net::use_awaitable, CompletionError));
        if (WriterFailure)
        {
            std::rethrow_exception(WriterFailure);
        }
        if (CompletionError)
        {
            throw std::system_error(CompletionError);
        }
        if (*ReaderFailure)
        {
            std::rethrow_exception(*ReaderFailure);
        }
    }

    auto RunLane(LaneRequest Request) -> Net::awaitable<void>
    {
        const auto Executor = co_await Net::this_coro::executor;
        auto &Result = *Request.Result;
        const auto ServerDone = std::make_shared<ServerCompletion>(Executor, 1);
        std::shared_ptr<Mux::StreamTransmission> ClientStream;
        bool ServerStarted = false;
        bool Failed = false;

        try
        {
            if (Request.ServerFirst)
            {
                Net::co_spawn(Executor,
                    RunServer(ServerRequest{Request.Server, Request.Input,
                        Request.ExpectedInputHash, ServerDone}),
                    ServerTransferCompletion{ServerDone});
                ServerStarted = true;
            }
            auto ClientHandle = co_await Request.Client->Session()->OpenStream();
            if (!ClientHandle)
            {
                throw std::system_error(std::make_error_code(std::errc::io_error));
            }
            ClientStream = std::make_shared<Mux::StreamTransmission>(std::move(ClientHandle));
            if (!ServerStarted)
            {
                Net::co_spawn(Executor,
                    RunServer(ServerRequest{Request.Server, Request.Input,
                        Request.ExpectedInputHash, ServerDone}),
                    ServerTransferCompletion{ServerDone});
                ServerStarted = true;
            }
            co_await RunClientTransfer(
                ClientTransferRequest{ClientStream, Request.Input, &Result});
        }
        catch (...)
        {
            Failed = true;
            ++Result.Errors;
        }

        if (Failed)
        {
            (void)Request.Client->Close();
            (void)Request.Server->Close();
            if (ClientStream)
            {
                (void)ClientStream->Close();
                const auto Drain = co_await ClientStream->DrainTerminations();
                Result.ClientCleanup = Drain.has_value() && !ClientStream->IsOpen();
            }
        }

        if (ServerStarted)
        {
            boost::system::error_code CompletionError;
            const auto ServerValue = co_await ServerDone->async_receive(
                Net::redirect_error(Net::use_awaitable, CompletionError));
            if (CompletionError || ServerValue.Failed)
            {
                Failed = true;
                ++Result.Errors;
            }
            Result.ServerInputBytes = ServerValue.InputBytes;
            Result.ServerInputHash = ServerValue.InputHash;
            Result.ServerPeerEof = ServerValue.PeerEof;
            Result.ServerFinSubmitted = ServerValue.FinSubmitted;
            Result.ServerFinDrained = ServerValue.FinDrained;
            Result.ServerCleanup = ServerValue.Cleanup;
            Result.PartialIo += ServerValue.PartialIo;
        }

        Result.NaturalExit = !Failed && Result.Errors == 0 &&
            Result.ClientCleanup && Result.ServerCleanup;
        (void)Request.Completion->try_send(boost::system::error_code{}, Request.LaneId);
    }

    auto RunRoundCoroutine(RoundRequest Request) -> Net::awaitable<void>
    {
        const auto Executor = co_await Net::this_coro::executor;
        auto &Result = *Request.Result;
        Result.Round = Request.Round;
        Result.LaneCount = Request.LaneCount;
        Result.ForwardOrder = Request.ForwardOrder;
        auto [ClientMemory, ServerMemory] = Prism::MakeMemoryPair(Executor);
        if (Request.LaneCount == 0 || Request.LaneCount > MaxLaneCount ||
            (Request.Input.Total != 0 && Request.LaneCount >
                (std::numeric_limits<std::size_t>::max)() / Request.Input.Total))
        {
            throw std::system_error(std::make_error_code(std::errc::value_too_large));
        }
        const auto ClientMetrics = std::make_shared<FragmentMetrics>();
        const auto ServerMetrics = std::make_shared<FragmentMetrics>();
        auto ClientRoot = std::make_shared<FragmentedTransmission>(
            std::make_shared<Prism::MemoryStream>(std::move(ClientMemory)),
            Request.Input.Fragment, ClientMetrics);
        auto ServerRoot = std::make_shared<FragmentedTransmission>(
            std::make_shared<Prism::MemoryStream>(std::move(ServerMemory)),
            Request.Input.Fragment, ServerMetrics);

        MuxClient Client;
        MuxServer Server;
        Mux::SessionOptions Options;
        Options.MaxStreams = Request.LaneCount;
        Options.MaxStreamRxBytes = Request.Input.Total;
        Options.MaxSessionRxBytes = Request.Input.Total * Request.LaneCount;
        if (!Client.Connect(ClientRoot, Options) || !Server.Accept(ServerRoot, Options))
        {
            throw std::system_error(std::make_error_code(std::errc::io_error));
        }

        const auto Completion = std::make_shared<LaneCompletion>(Executor, Request.LaneCount);
        std::size_t Spawned = 0;
        try
        {
            for (std::size_t Position = 0; Position < Request.LaneCount; ++Position)
            {
                const auto LaneId = Request.ForwardOrder
                    ? Position
                    : Request.LaneCount - Position - 1U;
                auto &Lane = Result.Lanes[LaneId];
                Lane.LaneId = LaneId;
                Lane.ExpectedInputHash = Request.ExpectedInputHash;
                Net::co_spawn(Executor,
                    RunLane(LaneRequest{
                        &Client, &Server, Request.Input, LaneId, Request.ServerFirst,
                        Request.ExpectedInputHash, &Lane, Completion}),
                    LaneRunCompletionHandler{
                        &Client, &Server, &Lane, Completion, LaneId});
                Result.LaneSpawned[LaneId] = true;
                ++Spawned;
            }
        }
        catch (...)
        {
            ++Result.Errors;
            (void)Client.Close();
            (void)Server.Close();
        }

        for (std::size_t Count = 0; Count < Spawned; ++Count)
        {
            const auto LaneId = co_await Completion->async_receive(Net::use_awaitable);
            if (LaneId >= Request.LaneCount || Result.LaneReceived[LaneId])
            {
                ++Result.Errors;
                (void)Client.Close();
                (void)Server.Close();
                continue;
            }
            Result.LaneReceived[LaneId] = true;
            Result.Errors += Result.Lanes[LaneId].Errors;
            Result.PartialIo += Result.Lanes[LaneId].PartialIo;
        }

        Result.PartialIo += ClientMetrics->ReadPartials + ClientMetrics->WritePartials +
                            ServerMetrics->ReadPartials + ServerMetrics->WritePartials;
        Result.NaturalExit = Result.Errors == 0 && Spawned == Request.LaneCount;
        for (std::size_t Index = 0; Index < Request.LaneCount; ++Index)
        {
            Result.NaturalExit = Result.NaturalExit && Result.LaneReceived[Index] &&
                                 Result.Lanes[Index].NaturalExit;
        }

        co_await Client.Session()->Close();
        co_await Server.Session()->Close();
        Result.ClientSessionCleanup = !Client.IsOpen() &&
                                      Client.Session()->StreamCount() == 0;
        Result.ServerSessionCleanup = !Server.IsOpen() &&
                                      Server.Session()->StreamCount() == 0;
        if (!Result.ClientSessionCleanup || !Result.ServerSessionCleanup)
        {
            ++Result.Errors;
            Result.NaturalExit = false;
        }
    }

    [[nodiscard]] auto RunRound(RoundRequest Request) -> MuxRoundResult
    {
        MuxRoundResult Result;
        Request.ExpectedInputHash = PayloadHash(Request.Input.Total);
        Request.Result = &Result;
        Net::io_context Io;
        Net::co_spawn(
            Io,
            RunRoundCoroutine(Request),
            [&Result](std::exception_ptr Error)
            {
                if (Error)
                {
                    ++Result.Errors;
                    Result.NaturalExit = false;
                }
            });
        Io.run();
        return Result;
    }

    auto PrintRound(const MuxRoundResult &Result) -> void
    {
        for (std::size_t Index = 0; Index < Result.LaneCount; ++Index)
        {
            const auto &Lane = Result.Lanes[Index];
            std::printf(
                "mux-lane lanes=%zu round=%zu lane=%zu sent=%zu received=%zu "
                "server-input=%zu partial=%zu errors=%zu expected-hash=%016llx "
                "server-input-hash=%016llx client-output-hash=%016llx "
                "client-fin=%s/%s server-eof=%s server-fin=%s/%s client-eof=%s "
                "cleanup=%s/%s natural-exit=%s valid=%s\n",
                Result.LaneCount, Result.Round + 1U, Lane.LaneId + 1U,
                Lane.Sent, Lane.Received, Lane.ServerInputBytes, Lane.PartialIo,
                Lane.Errors, static_cast<unsigned long long>(Lane.ExpectedInputHash),
                static_cast<unsigned long long>(Lane.ServerInputHash),
                static_cast<unsigned long long>(Lane.ClientOutputHash),
                Lane.ClientFinSubmitted ? "submitted" : "missing",
                Lane.ClientFinDrained ? "drained" : "pending",
                Lane.ServerPeerEof ? "yes" : "no",
                Lane.ServerFinSubmitted ? "submitted" : "missing",
                Lane.ServerFinDrained ? "drained" : "pending",
                Lane.ClientPeerEof ? "yes" : "no",
                Lane.ClientCleanup ? "clean" : "leaked",
                Lane.ServerCleanup ? "clean" : "leaked",
                Lane.NaturalExit ? "yes" : "no", Lane.Valid() ? "yes" : "no");
        }
        std::printf(
            "mux-round lanes=%zu round=%zu order=%s partial=%zu errors=%zu "
            "session-cleanup=%s/%s natural-exit=%s valid=%s\n",
            Result.LaneCount, Result.Round + 1U,
            Result.ForwardOrder ? "ascending_AB" : "descending_BA",
            Result.PartialIo, Result.Errors,
            Result.ClientSessionCleanup ? "clean" : "leaked",
            Result.ServerSessionCleanup ? "clean" : "leaked",
            Result.NaturalExit ? "yes" : "no", Result.Valid() ? "yes" : "no");
    }

} // namespace TransferPerfMux

int main()
{
    bool AllValid = true;
    for (const auto LaneCount : TransferPerfMux::LaneCounts)
    {
        for (std::size_t Round = 0; Round < TransferPerfMux::RoundCount; ++Round)
        {
            const auto ForwardOrder = Round % 2U == 0U;
            TransferPerfMux::RoundRequest Request;
            Request.Input = TransferPerfMux::LaneInput{};
            Request.Round = Round;
            Request.LaneCount = LaneCount;
            Request.ForwardOrder = ForwardOrder;
            Request.ServerFirst = ForwardOrder;
            const auto Result = TransferPerfMux::RunRound(Request);
            TransferPerfMux::PrintRound(Result);
            AllValid = Result.Valid() && AllValid;
        }
    }
    std::printf(
        "TransferPerfMux: lane-counts=1,2,4 rounds=%zu total-bytes-per-lane=%zu "
        "block-bytes=%zu fragment-bytes=%zu valid=%s\n",
        TransferPerfMux::RoundCount, TransferPerfMux::TotalBytes,
        TransferPerfMux::BlockSize, TransferPerfMux::FragmentBytes,
        AllValid ? "yes" : "no");
    return AllValid ? 0 : 1;
}
