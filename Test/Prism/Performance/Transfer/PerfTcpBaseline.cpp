/**
 * @file PerfTcpBaseline.cpp
 * @brief TransferPerf 模块所有者。
 */

#include "TransferPerf.hpp"

namespace TransferPerf
{
    struct ServerState
    {
        Net::any_io_executor Executor;
        Net::ip::tcp::acceptor &Acceptor;
        std::size_t TotalBytes;
        std::size_t BlockSize;
        std::shared_ptr<CompletionChannel> Completion;
    };

    [[nodiscard]] auto NowNs() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }

    auto RunServer(ServerState State) -> Net::awaitable<void>
    {
        Net::ip::tcp::socket Socket(State.Executor);
        boost::system::error_code AcceptError;
        auto AcceptToken =
            Net::redirect_error(Net::use_awaitable, AcceptError);
        co_await State.Acceptor.async_accept(Socket, AcceptToken);
        if (AcceptError)
        {
            (void)State.Completion->try_send(
                boost::system::error_code{}, false);
            co_return;
        }

        std::vector<std::uint8_t> Buffer(State.BlockSize);
        std::size_t Received = 0;
        while (Received < State.TotalBytes)
        {
            const auto ReadSize =
                std::min(State.BlockSize, State.TotalBytes - Received);
            auto ReadBuffer = Net::buffer(Buffer.data(), ReadSize);
            boost::system::error_code ReadError;
            auto ReadToken =
                Net::redirect_error(Net::use_awaitable, ReadError);
            const auto Count =
                co_await Socket.async_read_some(ReadBuffer, ReadToken);
            if (ReadError || Count == 0 || Count > ReadSize)
            {
                break;
            }
            Received += Count;
        }

        boost::system::error_code CloseError;
        Socket.close(CloseError);
        const bool Completed = Received == State.TotalBytes;
        (void)State.Completion->try_send(
            boost::system::error_code{},
            Completed);
    }

    struct RawTcpClientRequest final
    {
        Net::any_io_executor Executor;
        Net::ip::tcp::acceptor &Acceptor;
        std::uint16_t Port{0};
        std::size_t TotalBytes{0};
        std::size_t BlockSize{0};
        const std::shared_ptr<CompletionChannel> &Completion;
        bool &Completed;
    };

    auto RunRawTcpClient(RawTcpClientRequest Request) -> Net::awaitable<void>
    {
        auto ServerCompletion = [Completion = Request.Completion](std::exception_ptr Exception)
            -> void
        {
            if (Exception)
            {
                (void)Completion->try_send(boost::system::error_code{}, false);
            }
        };
        Net::co_spawn(Request.Executor, RunServer(ServerState{
            Request.Executor, Request.Acceptor, Request.TotalBytes,
            Request.BlockSize, Request.Completion}), std::move(ServerCompletion));

        Net::ip::tcp::socket Socket(Request.Executor);
        const auto Endpoint = Net::ip::tcp::endpoint(
            Net::ip::address_v4::loopback(), Request.Port);
        boost::system::error_code ConnectError;
        auto ConnectToken = Net::redirect_error(Net::use_awaitable, ConnectError);
        co_await Socket.async_connect(Endpoint, ConnectToken);
        if (ConnectError)
        {
            boost::system::error_code CloseError;
            Request.Acceptor.close(CloseError);
            (void)co_await Request.Completion->async_receive(Net::use_awaitable);
            co_return;
        }

        std::vector<std::uint8_t> Chunk(Request.BlockSize);
        std::size_t Sent = 0;
        while (Sent < Request.TotalBytes)
        {
            const auto WriteSize = std::min(Request.BlockSize, Request.TotalBytes - Sent);
            FillPayload(std::as_writable_bytes(std::span(Chunk)).first(WriteSize), Sent);
            auto WriteBuffer = Net::buffer(Chunk.data(), WriteSize);
            boost::system::error_code WriteError;
            auto WriteToken = Net::redirect_error(Net::use_awaitable, WriteError);
            const auto Count = co_await Socket.async_write_some(WriteBuffer, WriteToken);
            if (WriteError || Count == 0 || Count > WriteSize)
            {
                break;
            }
            Sent += Count;
        }

        boost::system::error_code CloseError;
        Socket.close(CloseError);
        const auto ServerCompleted = co_await Request.Completion->async_receive(
            Net::use_awaitable);
        Request.Completed = Sent == Request.TotalBytes && ServerCompleted;
    }

    [[nodiscard]] auto BenchRawTcp(
        const std::size_t TotalBytes,
        const std::size_t BlockSize) -> std::int64_t
    {
        Net::io_context IoContext;
        const auto Executor = IoContext.get_executor();
        Net::ip::tcp::acceptor Acceptor(
            IoContext,
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto Port = Acceptor.local_endpoint().port();
        const auto Completion =
            std::make_shared<CompletionChannel>(Executor, 1);
        bool Completed = false;
        const auto Start = NowNs();
        RunCoroutine(IoContext, RunRawTcpClient(
            RawTcpClientRequest{Executor, Acceptor, Port, TotalBytes, BlockSize,
                                Completion, Completed}));
        if (!Completed)
        {
            return 0;
        }
        return NowNs() - Start;
    }

}
