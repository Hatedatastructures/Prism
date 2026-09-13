/**
 * @file TransferPerf.cpp
 * @brief 原生 TCP 传输吞吐基准（Release）
 * @details 每个块大小运行 3 次并取中位数；服务端完成通知和实际字节数
 *          都参与门禁，避免断链或未执行路径被误报为通过。
 */

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <span>
#include <thread>
#include <vector>

namespace Net = boost::asio;

namespace
{
    using Clock = std::chrono::steady_clock;
    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;

    struct ServerState
    {
        Net::any_io_executor Executor;
        Net::ip::tcp::acceptor &Acceptor;
        std::size_t TotalBytes;
        std::size_t BlockSize;
        std::shared_ptr<CompletionChannel> Completion;
    };

    struct Result
    {
        std::array<std::int64_t, 3> Samples{};

        [[nodiscard]] auto Median() const -> std::int64_t
        {
            auto Sorted = Samples;
            std::sort(Sorted.begin(), Sorted.end());
            return Sorted[1];
        }
    };

    [[nodiscard]] auto NowNs() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   Clock::now().time_since_epoch())
            .count();
    }

    template <typename Awaitable>
    auto RunCoroutine(
        Net::io_context &IoContext,
        Awaitable Coroutine) -> void
    {
        std::exception_ptr Exception;
        auto Completion =
            [&Exception, &IoContext](std::exception_ptr ErrorValue) -> void
        {
            Exception = ErrorValue;
            IoContext.stop();
        };
        Net::co_spawn(
            IoContext,
            std::move(Coroutine),
            std::move(Completion));
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
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
        const ServerState State{
            Executor,
            Acceptor,
            TotalBytes,
            BlockSize,
            Completion};
        bool Completed = false;
        const auto Start = NowNs();
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            auto ServerCompletion =
                [Completion](std::exception_ptr Exception) -> void
            {
                if (Exception)
                {
                    (void)Completion->try_send(
                        boost::system::error_code{}, false);
                }
            };
            Net::co_spawn(
                Executor,
                RunServer(State),
                std::move(ServerCompletion));

            Net::ip::tcp::socket Socket(Executor);
            const auto Endpoint = Net::ip::tcp::endpoint(
                Net::ip::address_v4::loopback(),
                Port);
            boost::system::error_code ConnectError;
            auto ConnectToken =
                Net::redirect_error(Net::use_awaitable, ConnectError);
            co_await Socket.async_connect(Endpoint, ConnectToken);
            if (ConnectError)
            {
                boost::system::error_code CloseError;
                Acceptor.close(CloseError);
                (void)co_await Completion->async_receive(
                    Net::use_awaitable);
                co_return;
            }

            const std::vector<std::uint8_t> Chunk(
                BlockSize,
                0x5A);
            std::size_t Sent = 0;
            while (Sent < TotalBytes)
            {
                const auto WriteSize =
                    std::min(BlockSize, TotalBytes - Sent);
                auto WriteBuffer = Net::buffer(
                    Chunk.data(),
                    WriteSize);
                boost::system::error_code WriteError;
                auto WriteToken =
                    Net::redirect_error(Net::use_awaitable, WriteError);
                const auto Count = co_await Socket.async_write_some(
                    WriteBuffer,
                    WriteToken);
                if (WriteError || Count == 0 || Count > WriteSize)
                {
                    break;
                }
                Sent += Count;
            }

            boost::system::error_code CloseError;
            Socket.close(CloseError);
            const auto ServerCompleted = co_await Completion->async_receive(
                Net::use_awaitable);
            Completed = Sent == TotalBytes && ServerCompleted;
        };
        RunCoroutine(IoContext, std::move(Coroutine));
        if (!Completed)
        {
            return 0;
        }
        return NowNs() - Start;
    }

    auto Report(
        const char *Name,
        const std::size_t Bytes,
        const Result &Measurement) -> void
    {
        const double Megabytes =
            static_cast<double>(Bytes) / (1024.0 * 1024.0);
        const auto MedianNs = Measurement.Median();
        const double Seconds =
            static_cast<double>(MedianNs) / 1e9;
        std::printf(
            "%-38s %7.1f MB  med=%7.2f ms (3 runs: %7.2f/%7.2f/%7.2f)  => %9.1f MB/s\n",
            Name,
            Megabytes,
            Seconds * 1000,
            Measurement.Samples[0] / 1e6,
            Measurement.Samples[1] / 1e6,
            Measurement.Samples[2] / 1e6,
            Megabytes / Seconds);
    }

    [[nodiscard]] auto Gate(
        const char *Name,
        const std::size_t Bytes,
        const Result &Measurement) -> bool
    {
        constexpr double MinMegabytesPerSecond = 50.0;
        Report(Name, Bytes, Measurement);
        const auto MedianNs = Measurement.Median();
        const auto HasIncompleteSample = std::any_of(
            Measurement.Samples.begin(),
            Measurement.Samples.end(),
            [](const std::int64_t Sample) -> bool
            {
                return Sample <= 0;
            });
        if (HasIncompleteSample)
        {
            std::printf(
                "FAIL %s: 存在数据面未完成运行（断链/死循环）\n",
                Name);
            return false;
        }
        const double MegabytesPerSecond =
            static_cast<double>(Bytes) /
            (1024.0 * 1024.0) /
            (static_cast<double>(MedianNs) / 1e9);
        if (MegabytesPerSecond < MinMegabytesPerSecond)
        {
            std::printf(
                "FAIL %s: 吞吐 %.1f MB/s < 下限 %.1f MB/s\n",
                Name,
                MegabytesPerSecond,
                MinMegabytesPerSecond);
            return false;
        }
        return true;
    }
} // namespace

auto main() -> int
{
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    constexpr std::size_t TotalBytes = 256ULL * 1024 * 1024;
    Result Block16K;
    Result Block256K;
    for (std::size_t SampleIndex = 0;
         SampleIndex < Block16K.Samples.size();
         ++SampleIndex)
    {
        Block16K.Samples[SampleIndex] =
            BenchRawTcp(TotalBytes, 16384);
        Block256K.Samples[SampleIndex] =
            BenchRawTcp(TotalBytes, 262144);
    }
    if (!Gate("Tcp raw 16KB block", TotalBytes, Block16K))
    {
        return 1;
    }
    if (!Gate("Tcp raw 256KB block", TotalBytes, Block256K))
    {
        return 1;
    }
    std::printf("TransferPerf: ALL PASS\n");
    return 0;
}
