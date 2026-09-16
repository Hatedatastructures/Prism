/**
 * @file PerformanceContract.cpp
 * @brief Production/Preview 同一编解码输入的性能对拍
 * @details 使用同一 payload、预热次数、迭代次数和三次采样，分别测量
 *          VLESS 请求解析、SS2022 会话密钥派生、SOCKS5 地址解析、TCP/UDP
 *          loopback 传输，并记录环境指纹。结果写入 PRISM_PERF_OUTPUT 指定的
 *          JSON 文件。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#include <psapi.h>
#else
#include <time.h>
#include <sys/resource.h>
#endif

#include <prism/crypto/blake3.hpp>
#include <prism/foundation/fault/code.hpp>
#include <prism/protocol/shadowsocks/constants.hpp>
#include <prism/protocol/shadowsocks/codec/framing.hpp>
#include <prism/protocol/vless/codec/framing.hpp>

#include <Preview/Protocols/Shadowsocks2022/KeyDerivation.hpp>
#include <Preview/Protocols/Socks5/Codec.hpp>
#include <Preview/Protocols/Vless/Codec.hpp>
#include <Preview/Transport/Reliable.hpp>
#include <Preview/Transport/Unreliable.hpp>

#include <prism/net/transport/reliable.hpp>
#include <prism/net/transport/transmission.hpp>
#include <prism/net/transport/unreliable.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <TestSupport/Production/ProductionMockTransport.hpp>

namespace
{

    using Clock = std::chrono::steady_clock;
    namespace net = boost::asio;
    using Tcp = net::ip::tcp;
    using Udp = net::ip::udp;

    struct Metric
    {
        std::string Name;
        std::string Implementation;
        std::array<double, 3> Samples{};
        double CpuNanoseconds{0};
        std::size_t PayloadBytes{0};
        std::size_t Warmup{100};
        std::size_t Iterations{10000};
        std::array<double, 3> CpuSamples{};
    };

    struct Measurement
    {
        double WallNanoseconds{0};
        double CpuNanoseconds{0};
    };

    struct TransportRunData
    {
        std::shared_ptr<const std::vector<std::byte>> Payload;
        std::size_t Warmup{0};
        std::size_t Iterations{0};
        Measurement *Result{nullptr};
        bool *Failed{nullptr};
    };

    struct TransportObservation
    {
        Measurement Result{};
        bool Failed{false};
    };

    [[nodiscard]] auto CpuNowNanoseconds() -> double
    {
        double Best = 0.0;
#if defined(_WIN32)
        const auto FileTimeNanoseconds = [](const FILETIME &Kernel, const FILETIME &User) -> double
        {
            ULARGE_INTEGER KernelTicks{};
            KernelTicks.LowPart = Kernel.dwLowDateTime;
            KernelTicks.HighPart = Kernel.dwHighDateTime;
            ULARGE_INTEGER UserTicks{};
            UserTicks.LowPart = User.dwLowDateTime;
            UserTicks.HighPart = User.dwHighDateTime;
            return static_cast<double>(KernelTicks.QuadPart + UserTicks.QuadPart) * 100.0;
        };
        FILETIME Creation{}, Exit{}, Kernel{}, User{};
        if (GetThreadTimes(GetCurrentThread(), &Creation, &Exit, &Kernel, &User))
        {
            Best = (std::max)(Best, FileTimeNanoseconds(Kernel, User));
        }
        if (GetProcessTimes(GetCurrentProcess(), &Creation, &Exit, &Kernel, &User))
        {
            Best = (std::max)(Best, FileTimeNanoseconds(Kernel, User));
        }
#elif defined(CLOCK_THREAD_CPUTIME_ID)
        timespec Time{};
        if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &Time) == 0)
        {
            Best = (std::max)(Best, static_cast<double>(Time.tv_sec) * 1.0e9 +
                                         static_cast<double>(Time.tv_nsec));
        }
#endif
        const auto ClockTime = static_cast<double>(std::clock()) *
                               (1.0e9 / static_cast<double>(CLOCKS_PER_SEC));
        return (std::max)(Best, ClockTime);
    }

    [[nodiscard]] auto PeakWorkingSetBytes() -> std::uint64_t
    {
#if defined(_WIN32)
        PROCESS_MEMORY_COUNTERS Counters{};
        if (GetProcessMemoryInfo(GetCurrentProcess(), &Counters, sizeof(Counters)) != 0)
        {
            return static_cast<std::uint64_t>(Counters.PeakWorkingSetSize);
        }
        return 0;
#elif defined(RUSAGE_SELF)
        rusage Usage{};
        if (getrusage(RUSAGE_SELF, &Usage) != 0)
        {
            return 0;
        }
#if defined(__APPLE__)
        return static_cast<std::uint64_t>(Usage.ru_maxrss);
#else
        return static_cast<std::uint64_t>(Usage.ru_maxrss) * 1024ULL;
#endif
#else
        return 0;
#endif
    }

    template <typename Function>
    [[nodiscard]] auto Measure(Function &&Fn, const std::size_t Warmup,
                                const std::size_t Iterations) -> Measurement
    {
        for (std::size_t Index = 0; Index < Warmup; ++Index)
        {
            Fn();
        }
        const auto Start = Clock::now();
        const auto CpuStart = CpuNowNanoseconds();
        for (std::size_t Index = 0; Index < Iterations; ++Index)
        {
            Fn();
        }
        const auto CpuEnd = CpuNowNanoseconds();
        const auto End = Clock::now();
        const auto Count = static_cast<double>(Iterations);
        const auto CpuElapsed = (std::max)(0.0, CpuEnd - CpuStart);
        return Measurement{
            std::chrono::duration<double, std::nano>(End - Start).count() / Count,
            CpuElapsed / Count};
    }

    [[nodiscard]] auto Median(std::array<double, 3> Values) -> double
    {
        std::sort(Values.begin(), Values.end());
        return Values[1];
    }

    [[nodiscard]] auto Percentile(std::array<double, 3> Values, const double Quantile) -> double
    {
        std::sort(Values.begin(), Values.end());
        const auto Position = Quantile * static_cast<double>(Values.size() - 1);
        const auto Lower = static_cast<std::size_t>(Position);
        const auto Upper = (std::min)(Lower + 1, Values.size() - 1);
        const auto Fraction = Position - static_cast<double>(Lower);
        return Values[Lower] + (Values[Upper] - Values[Lower]) * Fraction;
    }

    [[nodiscard]] auto Mad(std::array<double, 3> Values) -> double
    {
        const auto Center = Median(Values);
        for (auto &Value : Values)
        {
            Value = std::abs(Value - Center);
        }
        return Median(Values);
    }

    [[nodiscard]] auto RegressionClass(const double DeltaPercent) -> std::string_view
    {
        if (DeltaPercent <= 5.0)
        {
            return "noise";
        }
        if (DeltaPercent <= 10.0)
        {
            return "review";
        }
        return "block";
    }

    [[nodiscard]] auto OperatingSystemName() noexcept -> std::string_view
    {
#if defined(_WIN32)
        return "windows";
#elif defined(__linux__)
        return "linux";
#elif defined(__APPLE__)
        return "macos";
#else
        return "unknown";
#endif
    }

    [[nodiscard]] auto CompilerName() noexcept -> std::string_view
    {
#if defined(__clang__)
        return "clang";
#elif defined(__GNUC__)
        return "gcc";
#elif defined(_MSC_VER)
        return "msvc";
#else
        return "unknown";
#endif
    }

    [[nodiscard]] auto CompilerVersion() noexcept -> std::string_view
    {
#if defined(__clang__)
        return __clang_version__;
#elif defined(__VERSION__)
        return __VERSION__;
#elif defined(_MSC_VER)
        return "msvc";
#else
        return "unknown";
#endif
    }

    [[nodiscard]] auto HardwareThreadCount() noexcept -> unsigned int
    {
        const auto Count = std::thread::hardware_concurrency();
        return Count == 0 ? 1U : Count;
    }

    [[nodiscard]] auto MakeMetric(std::string Name, std::string Implementation,
                                  const std::array<Measurement, 3> &Measurements,
                                  const std::size_t PayloadBytes = 0,
                                  const std::size_t Warmup = 100,
                                  const std::size_t Iterations = 10000) -> Metric
    {
        std::array<double, 3> Samples{};
        std::array<double, 3> Cpu{};
        for (std::size_t Index = 0; Index < Measurements.size(); ++Index)
        {
            Samples[Index] = Measurements[Index].WallNanoseconds;
            Cpu[Index] = Measurements[Index].CpuNanoseconds;
        }
        Metric Result{std::move(Name), std::move(Implementation), Samples, Median(Cpu), PayloadBytes, Warmup,
                      Iterations};
        Result.CpuSamples = Cpu;
        return Result;
    }

    TEST(PerformanceContract, CpuClockReportsNonZeroSample)
    {
        volatile std::uint64_t Value = 0;
        const auto Result = Measure(
            [&Value]
            {
                for (std::uint64_t Index = 0; Index < 16384; ++Index)
                {
                    Value += Index;
                }
            },
            1, 1000);
        EXPECT_GT(Result.CpuNanoseconds, 0.0);
    }

    TEST(PerformanceContract, ClassifiesRegressionThresholds)
    {
        EXPECT_EQ(RegressionClass(-1.0), "noise");
        EXPECT_EQ(RegressionClass(5.0), "noise");
        EXPECT_EQ(RegressionClass(5.01), "review");
        EXPECT_EQ(RegressionClass(10.0), "review");
        EXPECT_EQ(RegressionClass(10.01), "block");
    }

    auto RunProductionTransport(std::shared_ptr<Psm::Testing::ProductionMockTransport> Transport,
                                TransportRunData Data) -> net::awaitable<void>
    {
        const auto Buffer = std::span<const std::byte>(Data.Payload->data(), Data.Payload->size());
        std::error_code Error;
        for (std::size_t Index = 0; Index < Data.Warmup; ++Index)
        {
            const auto Written = co_await psm::transport::async_write(*Transport, Buffer, Error);
            if (Error || Written != Buffer.size())
            {
                *Data.Failed = true;
                co_return;
            }
        }
        const auto Start = Clock::now();
        const auto CpuStart = CpuNowNanoseconds();
        for (std::size_t Index = 0; Index < Data.Iterations; ++Index)
        {
            Error.clear();
            const auto Written = co_await psm::transport::async_write(*Transport, Buffer, Error);
            if (Error || Written != Buffer.size())
            {
                *Data.Failed = true;
                co_return;
            }
        }
        const auto CpuEnd = CpuNowNanoseconds();
        const auto End = Clock::now();
        const auto Count = static_cast<double>(Data.Iterations);
        Data.Result->WallNanoseconds =
            std::chrono::duration<double, std::nano>(End - Start).count() / Count;
        Data.Result->CpuNanoseconds = (std::max)(0.0, CpuEnd - CpuStart) / Count;
        co_return;
    }

    auto RunPreviewTransport(std::shared_ptr<Preview::PreviewMockTransport> Transport,
                             TransportRunData Data) -> net::awaitable<void>
    {
        const auto Buffer = std::span<const std::byte>(Data.Payload->data(), Data.Payload->size());
        std::error_code Error;
        for (std::size_t Index = 0; Index < Data.Warmup; ++Index)
        {
            const auto Written = co_await Transport->AsyncWrite(Buffer, Error);
            if (Error || Written != Buffer.size())
            {
                *Data.Failed = true;
                co_return;
            }
        }
        const auto Start = Clock::now();
        const auto CpuStart = CpuNowNanoseconds();
        for (std::size_t Index = 0; Index < Data.Iterations; ++Index)
        {
            Error.clear();
            const auto Written = co_await Transport->AsyncWrite(Buffer, Error);
            if (Error || Written != Buffer.size())
            {
                *Data.Failed = true;
                co_return;
            }
        }
        const auto CpuEnd = CpuNowNanoseconds();
        const auto End = Clock::now();
        const auto Count = static_cast<double>(Data.Iterations);
        Data.Result->WallNanoseconds =
            std::chrono::duration<double, std::nano>(End - Start).count() / Count;
        Data.Result->CpuNanoseconds = (std::max)(0.0, CpuEnd - CpuStart) / Count;
        co_return;
    }

    [[nodiscard]] auto ObserveProductionTransport(
        std::shared_ptr<const std::vector<std::byte>> Payload, const std::size_t Warmup,
        const std::size_t Iterations) -> TransportObservation
    {
        auto Transport = std::make_shared<Psm::Testing::ProductionMockTransport>();
        auto &Io = Transport->GetIoContext();
        TransportObservation Observation;
        TransportRunData Data{std::move(Payload), Warmup, Iterations, &Observation.Result, &Observation.Failed};
        net::co_spawn(Io, RunProductionTransport(Transport, std::move(Data)),
                      [&Io, &Observation](std::exception_ptr Failure)
                      {
                          Observation.Failed = Observation.Failed || static_cast<bool>(Failure);
                          Io.stop();
                      });
        Io.run();
        return Observation;
    }

    [[nodiscard]] auto ObservePreviewTransport(
        std::shared_ptr<const std::vector<std::byte>> Payload, const std::size_t Warmup,
        const std::size_t Iterations) -> TransportObservation
    {
        net::io_context Io;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Io.get_executor());
        TransportObservation Observation;
        TransportRunData Data{std::move(Payload), Warmup, Iterations, &Observation.Result, &Observation.Failed};
        net::co_spawn(Io, RunPreviewTransport(Transport, std::move(Data)),
                      [&Io, &Observation](std::exception_ptr Failure)
                      {
                          Observation.Failed = Observation.Failed || static_cast<bool>(Failure);
                          Io.stop();
                      });
        Io.run();
        return Observation;
    }

    struct TcpRunState
    {
        std::shared_ptr<const std::vector<std::byte>> Payload;
        std::size_t Warmup{0};
        std::size_t Iterations{0};
        std::shared_ptr<net::experimental::channel<void(boost::system::error_code)>> ServerDone;
        Measurement Result{};
        bool Failed{false};
    };

    auto RunProductionTcpServer(std::shared_ptr<TcpRunState> State,
                                std::shared_ptr<Tcp::acceptor> Acceptor) -> net::awaitable<void>
    {
        auto Socket = co_await Acceptor->async_accept(net::use_awaitable);
        auto Transport = std::make_shared<psm::transport::reliable>(std::move(Socket));
        const auto Expected = (State->Warmup + State->Iterations) * State->Payload->size();
        std::vector<std::byte> Buffer(32 * 1024);
        std::size_t Received = 0;
        while (Received < Expected)
        {
            std::error_code Error;
            const auto Count = co_await Transport->async_read_some(Buffer, Error);
            if (Error || Count == 0)
            {
                State->Failed = true;
                co_return;
            }
            Received += Count;
        }
        (void)State->ServerDone->try_send(boost::system::error_code{});
        Transport->close();
        co_return;
    }

    auto RunPreviewTcpServer(std::shared_ptr<TcpRunState> State,
                             std::shared_ptr<Tcp::acceptor> Acceptor) -> net::awaitable<void>
    {
        auto Socket = co_await Acceptor->async_accept(net::use_awaitable);
        auto Transport = std::make_shared<Preview::Transport::Reliable>(std::move(Socket));
        const auto Expected = (State->Warmup + State->Iterations) * State->Payload->size();
        std::vector<std::byte> Buffer(32 * 1024);
        std::size_t Received = 0;
        while (Received < Expected)
        {
            std::error_code Error;
            const auto Count = co_await Transport->async_read_some(Buffer, Error);
            if (Error || Count == 0)
            {
                State->Failed = true;
                co_return;
            }
            Received += Count;
        }
        (void)State->ServerDone->try_send(boost::system::error_code{});
        Transport->Close();
        co_return;
    }

    auto RunProductionTcpClient(std::shared_ptr<TcpRunState> State, Tcp::endpoint Target,
                                net::io_context *Io) -> net::awaitable<void>
    {
        Tcp::socket Socket(co_await net::this_coro::executor);
        co_await Socket.async_connect(Target, net::use_awaitable);
        auto Transport = std::make_shared<psm::transport::reliable>(std::move(Socket));
        const auto Buffer = std::span<const std::byte>(State->Payload->data(), State->Payload->size());
        std::error_code Error;
        for (std::size_t Index = 0; Index < State->Warmup; ++Index)
        {
            const auto Count = co_await psm::transport::async_write(*Transport, Buffer, Error);
            if (Error || Count != Buffer.size())
            {
                State->Failed = true;
                Io->stop();
                co_return;
            }
        }
        const auto Start = Clock::now();
        const auto CpuStart = CpuNowNanoseconds();
        for (std::size_t Index = 0; Index < State->Iterations; ++Index)
        {
            Error.clear();
            const auto Count = co_await psm::transport::async_write(*Transport, Buffer, Error);
            if (Error || Count != Buffer.size())
            {
                State->Failed = true;
                Io->stop();
                co_return;
            }
        }
        boost::system::error_code ShutdownError;
        Transport->native_socket().shutdown(Tcp::socket::shutdown_send, ShutdownError);
        co_await State->ServerDone->async_receive(net::use_awaitable);
        const auto CpuEnd = CpuNowNanoseconds();
        const auto End = Clock::now();
        const auto Count = static_cast<double>(State->Iterations);
        State->Result.WallNanoseconds =
            std::chrono::duration<double, std::nano>(End - Start).count() / Count;
        State->Result.CpuNanoseconds = (std::max)(0.0, CpuEnd - CpuStart) / Count;
        Transport->close();
        Io->stop();
        co_return;
    }

    auto RunPreviewTcpClient(std::shared_ptr<TcpRunState> State, Tcp::endpoint Target,
                             net::io_context *Io) -> net::awaitable<void>
    {
        Tcp::socket Socket(co_await net::this_coro::executor);
        co_await Socket.async_connect(Target, net::use_awaitable);
        auto Transport = std::make_shared<Preview::Transport::Reliable>(std::move(Socket));
        const auto Buffer = std::span<const std::byte>(State->Payload->data(), State->Payload->size());
        std::error_code Error;
        for (std::size_t Index = 0; Index < State->Warmup; ++Index)
        {
            const auto Count = co_await Transport->AsyncWrite(Buffer, Error);
            if (Error || Count != Buffer.size())
            {
                State->Failed = true;
                Io->stop();
                co_return;
            }
        }
        const auto Start = Clock::now();
        const auto CpuStart = CpuNowNanoseconds();
        for (std::size_t Index = 0; Index < State->Iterations; ++Index)
        {
            Error.clear();
            const auto Count = co_await Transport->AsyncWrite(Buffer, Error);
            if (Error || Count != Buffer.size())
            {
                State->Failed = true;
                Io->stop();
                co_return;
            }
        }
        boost::system::error_code ShutdownError;
        Transport->NativeSocket().shutdown(Tcp::socket::shutdown_send, ShutdownError);
        co_await State->ServerDone->async_receive(net::use_awaitable);
        const auto CpuEnd = CpuNowNanoseconds();
        const auto End = Clock::now();
        const auto Count = static_cast<double>(State->Iterations);
        State->Result.WallNanoseconds =
            std::chrono::duration<double, std::nano>(End - Start).count() / Count;
        State->Result.CpuNanoseconds = (std::max)(0.0, CpuEnd - CpuStart) / Count;
        Transport->Close();
        Io->stop();
        co_return;
    }

    [[nodiscard]] auto ObserveProductionTcp(
        std::shared_ptr<const std::vector<std::byte>> Payload, const std::size_t Warmup,
        const std::size_t Iterations) -> TransportObservation
    {
        net::io_context Io;
        auto Acceptor = std::make_shared<Tcp::acceptor>(
            Io, Tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        auto State = std::make_shared<TcpRunState>();
        State->Payload = std::move(Payload);
        State->Warmup = Warmup;
        State->Iterations = Iterations;
        State->ServerDone =
            std::make_shared<net::experimental::channel<void(boost::system::error_code)>>(Io.get_executor(), 1);
        const auto Target = Acceptor->local_endpoint();
        net::co_spawn(Io, RunProductionTcpServer(State, Acceptor), net::detached);
        net::co_spawn(Io, RunProductionTcpClient(State, Target, &Io), net::detached);
        Io.run();
        return TransportObservation{State->Result, State->Failed};
    }

    [[nodiscard]] auto ObservePreviewTcp(
        std::shared_ptr<const std::vector<std::byte>> Payload, const std::size_t Warmup,
        const std::size_t Iterations) -> TransportObservation
    {
        net::io_context Io;
        auto Acceptor = std::make_shared<Tcp::acceptor>(
            Io, Tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        auto State = std::make_shared<TcpRunState>();
        State->Payload = std::move(Payload);
        State->Warmup = Warmup;
        State->Iterations = Iterations;
        State->ServerDone =
            std::make_shared<net::experimental::channel<void(boost::system::error_code)>>(Io.get_executor(), 1);
        const auto Target = Acceptor->local_endpoint();
        net::co_spawn(Io, RunPreviewTcpServer(State, Acceptor), net::detached);
        net::co_spawn(Io, RunPreviewTcpClient(State, Target, &Io), net::detached);
        Io.run();
        return TransportObservation{State->Result, State->Failed};
    }

    struct UdpRunState
    {
        std::shared_ptr<const std::vector<std::byte>> Payload;
        std::size_t Warmup{0};
        std::size_t Iterations{0};
        std::shared_ptr<net::experimental::channel<void(boost::system::error_code)>> ServerDone;
        Measurement Result{};
        bool Failed{false};
    };

    [[nodiscard]] auto UdpFailure() -> boost::system::error_code
    {
        return boost::system::errc::make_error_code(boost::system::errc::io_error);
    }

    auto RunProductionUdpServer(std::shared_ptr<UdpRunState> State,
                                std::shared_ptr<psm::transport::unreliable> Transport)
        -> net::awaitable<void>
    {
        std::vector<std::byte> Buffer(State->Payload->size());
        const auto Expected = State->Warmup + State->Iterations;
        for (std::size_t Index = 0; Index < Expected; ++Index)
        {
            std::error_code Error;
            const auto Count = co_await Transport->async_read_some(Buffer, Error);
            if (Error || Count != Buffer.size() || !std::equal(Buffer.begin(), Buffer.end(), State->Payload->begin()))
            {
                State->Failed = true;
                (void)State->ServerDone->try_send(UdpFailure());
                co_return;
            }
        }
        (void)State->ServerDone->try_send(boost::system::error_code{});
        Transport->close();
        co_return;
    }

    auto RunPreviewUdpServer(std::shared_ptr<UdpRunState> State,
                             std::shared_ptr<Preview::Transport::Unreliable> Transport)
        -> net::awaitable<void>
    {
        std::vector<std::byte> Buffer(State->Payload->size());
        const auto Expected = State->Warmup + State->Iterations;
        for (std::size_t Index = 0; Index < Expected; ++Index)
        {
            std::error_code Error;
            const auto Count = co_await Transport->async_read_some(Buffer, Error);
            if (Error || Count != Buffer.size() || !std::equal(Buffer.begin(), Buffer.end(), State->Payload->begin()))
            {
                State->Failed = true;
                (void)State->ServerDone->try_send(UdpFailure());
                co_return;
            }
        }
        (void)State->ServerDone->try_send(boost::system::error_code{});
        Transport->Close();
        co_return;
    }

    auto RunProductionUdpClient(std::shared_ptr<UdpRunState> State,
                                std::shared_ptr<psm::transport::unreliable> Transport,
                                net::io_context *Io) -> net::awaitable<void>
    {
        const auto Buffer = std::span<const std::byte>(State->Payload->data(), State->Payload->size());
        std::error_code Error;
        for (std::size_t Index = 0; Index < State->Warmup; ++Index)
        {
            const auto Count = co_await Transport->async_write_some(Buffer, Error);
            if (Error || Count != Buffer.size())
            {
                State->Failed = true;
                Io->stop();
                co_return;
            }
        }
        const auto Start = Clock::now();
        const auto CpuStart = CpuNowNanoseconds();
        for (std::size_t Index = 0; Index < State->Iterations; ++Index)
        {
            Error.clear();
            const auto Count = co_await Transport->async_write_some(Buffer, Error);
            if (Error || Count != Buffer.size())
            {
                State->Failed = true;
                Io->stop();
                co_return;
            }
        }
        boost::system::error_code Completion;
        co_await State->ServerDone->async_receive(net::redirect_error(net::use_awaitable, Completion));
        if (Completion)
        {
            State->Failed = true;
        }
        const auto CpuEnd = CpuNowNanoseconds();
        const auto End = Clock::now();
        const auto Count = static_cast<double>(State->Iterations);
        State->Result.WallNanoseconds =
            std::chrono::duration<double, std::nano>(End - Start).count() / Count;
        State->Result.CpuNanoseconds = (std::max)(0.0, CpuEnd - CpuStart) / Count;
        Transport->close();
        Io->stop();
        co_return;
    }

    auto RunPreviewUdpClient(std::shared_ptr<UdpRunState> State,
                             std::shared_ptr<Preview::Transport::Unreliable> Transport,
                             net::io_context *Io) -> net::awaitable<void>
    {
        const auto Buffer = std::span<const std::byte>(State->Payload->data(), State->Payload->size());
        std::error_code Error;
        for (std::size_t Index = 0; Index < State->Warmup; ++Index)
        {
            const auto Count = co_await Transport->async_write_some(Buffer, Error);
            if (Error || Count != Buffer.size())
            {
                State->Failed = true;
                Io->stop();
                co_return;
            }
        }
        const auto Start = Clock::now();
        const auto CpuStart = CpuNowNanoseconds();
        for (std::size_t Index = 0; Index < State->Iterations; ++Index)
        {
            Error.clear();
            const auto Count = co_await Transport->async_write_some(Buffer, Error);
            if (Error || Count != Buffer.size())
            {
                State->Failed = true;
                Io->stop();
                co_return;
            }
        }
        boost::system::error_code Completion;
        co_await State->ServerDone->async_receive(net::redirect_error(net::use_awaitable, Completion));
        if (Completion)
        {
            State->Failed = true;
        }
        const auto CpuEnd = CpuNowNanoseconds();
        const auto End = Clock::now();
        const auto Count = static_cast<double>(State->Iterations);
        State->Result.WallNanoseconds =
            std::chrono::duration<double, std::nano>(End - Start).count() / Count;
        State->Result.CpuNanoseconds = (std::max)(0.0, CpuEnd - CpuStart) / Count;
        Transport->Close();
        Io->stop();
        co_return;
    }

    [[nodiscard]] auto ObserveProductionUdp(
        std::shared_ptr<const std::vector<std::byte>> Payload, const std::size_t Warmup,
        const std::size_t Iterations) -> TransportObservation
    {
        net::io_context Io;
        Udp::socket ServerSocket(Io, Udp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        Udp::socket ClientSocket(Io, Udp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        const auto ServerEndpoint = ServerSocket.local_endpoint();
        const auto ClientEndpoint = ClientSocket.local_endpoint();
        auto ServerTransport = std::make_shared<psm::transport::unreliable>(
            std::move(ServerSocket), ClientEndpoint);
        auto ClientTransport = std::make_shared<psm::transport::unreliable>(
            std::move(ClientSocket), ServerEndpoint);
        auto State = std::make_shared<UdpRunState>();
        State->Payload = std::move(Payload);
        State->Warmup = Warmup;
        State->Iterations = Iterations;
        State->ServerDone =
            std::make_shared<net::experimental::channel<void(boost::system::error_code)>>(Io.get_executor(), 1);
        net::co_spawn(Io, RunProductionUdpServer(State, std::move(ServerTransport)), net::detached);
        net::co_spawn(Io, RunProductionUdpClient(State, std::move(ClientTransport), &Io), net::detached);
        Io.run();
        return TransportObservation{State->Result, State->Failed};
    }

    [[nodiscard]] auto ObservePreviewUdp(
        std::shared_ptr<const std::vector<std::byte>> Payload, const std::size_t Warmup,
        const std::size_t Iterations) -> TransportObservation
    {
        net::io_context Io;
        Udp::socket ServerSocket(Io, Udp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        Udp::socket ClientSocket(Io, Udp::endpoint(net::ip::make_address("127.0.0.1"), 0));
        const auto ServerEndpoint = ServerSocket.local_endpoint();
        const auto ClientEndpoint = ClientSocket.local_endpoint();
        auto ServerTransport = std::make_shared<Preview::Transport::Unreliable>(
            std::move(ServerSocket), ClientEndpoint);
        auto ClientTransport = std::make_shared<Preview::Transport::Unreliable>(
            std::move(ClientSocket), ServerEndpoint);
        auto State = std::make_shared<UdpRunState>();
        State->Payload = std::move(Payload);
        State->Warmup = Warmup;
        State->Iterations = Iterations;
        State->ServerDone =
            std::make_shared<net::experimental::channel<void(boost::system::error_code)>>(Io.get_executor(), 1);
        net::co_spawn(Io, RunPreviewUdpServer(State, std::move(ServerTransport)), net::detached);
        net::co_spawn(Io, RunPreviewUdpClient(State, std::move(ClientTransport), &Io), net::detached);
        Io.run();
        return TransportObservation{State->Result, State->Failed};
    }

    [[nodiscard]] auto OutputPath() -> std::string
    {
        if (const auto *Path = std::getenv("PRISM_PERF_OUTPUT"); Path && *Path)
        {
            return Path;
        }
        return "preview-production-perf.json";
    }

    [[nodiscard]] auto BuildVlessWire() -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Wire{0x00};
        Wire.insert(Wire.end(), 16, 0x11);
        Wire.insert(Wire.end(), {0x00, 0x01, 0x01, 0xBB, 0x02,
                                 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e'});
        return Wire;
    }

    [[nodiscard]] auto BuildSocksWire() -> std::vector<std::uint8_t>
    {
        return {0x01, 8, 8, 8, 8, 0x00, 0x35};
    }

    [[nodiscard]] auto WriteMetrics(const std::vector<Metric> &Metrics) -> bool
    {
        struct Comparison
        {
            std::string Name;
            double MedianDeltaPercent{0};
            double P95DeltaPercent{0};
            std::string_view Classification{"noise"};
        };
        std::vector<Comparison> Comparisons;
        for (const auto &Production : Metrics)
        {
            if (Production.Implementation != "production")
            {
                continue;
            }
            const auto Preview = std::find_if(
                Metrics.begin(), Metrics.end(), [&Production](const Metric &Candidate)
                {
                    return Candidate.Name == Production.Name && Candidate.Implementation == "preview";
                });
            if (Preview == Metrics.end())
            {
                continue;
            }
            const auto ProductionMedian = Median(Production.Samples);
            const auto ProductionP95 = Percentile(Production.Samples, 0.95);
            if (ProductionMedian <= 0 || ProductionP95 <= 0)
            {
                continue;
            }
            const auto MedianDelta = (Median(Preview->Samples) - ProductionMedian) * 100.0 / ProductionMedian;
            const auto P95Delta = (Percentile(Preview->Samples, 0.95) - ProductionP95) * 100.0 / ProductionP95;
            Comparisons.push_back(Comparison{Production.Name, MedianDelta, P95Delta,
                                              RegressionClass((std::max)(MedianDelta, P95Delta))});
        }

        std::ofstream Output(OutputPath(), std::ios::binary | std::ios::trunc);
        if (!Output)
        {
            return false;
        }
        Output << "{\n  \"schema\": \"prism.perf-contract.v2\",\n"
               << "  \"environment\": {\"os\": \"" << OperatingSystemName()
               << "\", \"compiler\": \"" << CompilerName()
               << "\", \"compiler_version\": \"" << CompilerVersion()
               << "\", \"pointer_bits\": " << sizeof(void *) * 8
               << ", \"hardware_threads\": " << HardwareThreadCount()
               << ", \"peak_working_set_bytes\": " << PeakWorkingSetBytes() << "},\n"
               << "  \"warmup\": 100,\n  \"iterations\": 10000,\n"
               << "  \"repetitions\": 3,\n  \"metrics\": [\n";
        for (std::size_t Index = 0; Index < Metrics.size(); ++Index)
        {
            const auto &MetricValue = Metrics[Index];
            Output << "    {\"metric\": \"" << MetricValue.Name
                   << "\", \"implementation\": \"" << MetricValue.Implementation
                   << "\", \"sample_count\": " << MetricValue.Samples.size()
                   << ", \"samples_ns\": [" << MetricValue.Samples[0] << ", "
                   << MetricValue.Samples[1] << ", " << MetricValue.Samples[2] << "]"
                   << ", \"cpu_samples_ns\": [" << MetricValue.CpuSamples[0] << ", "
                   << MetricValue.CpuSamples[1] << ", " << MetricValue.CpuSamples[2] << "]"
                   << ", \"payload_bytes\": " << MetricValue.PayloadBytes
                   << ", \"warmup\": " << MetricValue.Warmup
                   << ", \"iterations\": " << MetricValue.Iterations
                   << ", \"median_ns\": " << std::setprecision(12)
                   << Median(MetricValue.Samples)
                   << ", \"p95_ns\": " << Percentile(MetricValue.Samples, 0.95)
                   << ", \"p99_ns\": " << Percentile(MetricValue.Samples, 0.99)
                   << ", \"mad_ns\": " << Mad(MetricValue.Samples)
                   << ", \"cpu_ns\": " << MetricValue.CpuNanoseconds;
            const auto MedianNanoseconds = Median(MetricValue.Samples);
            if (MedianNanoseconds > 0 && MetricValue.Name == "transport.tcp_loopback")
            {
                const auto Bytes = static_cast<double>(MetricValue.PayloadBytes) *
                                   static_cast<double>(MetricValue.Iterations);
                Output << ", \"bytes_per_second\": " << Bytes * 1.0e9 / MedianNanoseconds;
            }
            else if (MedianNanoseconds > 0 && MetricValue.Name == "transport.udp_loopback")
            {
                const auto Packets = static_cast<double>(MetricValue.Iterations);
                Output << ", \"packets_per_second\": " << Packets * 1.0e9 / MedianNanoseconds;
            }
            Output << "}";
            if (Index + 1 != Metrics.size())
            {
                Output << ',';
            }
            Output << "\n";
        }
        Output << "  ],\n  \"comparisons\": [\n";
        for (std::size_t Index = 0; Index < Comparisons.size(); ++Index)
        {
            const auto &ComparisonValue = Comparisons[Index];
            Output << "    {\"metric\": \"" << ComparisonValue.Name
                   << "\", \"baseline\": \"production\", \"candidate\": \"preview\""
                   << ", \"median_delta_percent\": " << ComparisonValue.MedianDeltaPercent
                   << ", \"p95_delta_percent\": " << ComparisonValue.P95DeltaPercent
                   << ", \"classification\": \"" << ComparisonValue.Classification << "\"}";
            if (Index + 1 != Comparisons.size())
            {
                Output << ',';
            }
            Output << "\n";
        }
        Output << "  ]\n}\n";
        return static_cast<bool>(Output);
    }

    TEST(PerformanceContract, StatisticalMetricSchemaContainsRequiredFields)
    {
        const Metric TcpProduction{"transport.tcp_loopback", "production", {1.0, 2.0, 4.0}, 3.0,
                                   16 * 1024, 1, 4};
        const Metric TcpPreview{"transport.tcp_loopback", "preview", {1.0, 2.0, 4.0}, 3.0,
                                16 * 1024, 1, 4};
        const Metric UdpProduction{"transport.udp_loopback", "production", {1.0, 2.0, 4.0}, 3.0,
                                   1200, 1, 4};
        const Metric UdpPreview{"transport.udp_loopback", "preview", {1.0, 2.0, 4.0}, 3.0,
                                1200, 1, 4};
        const auto JsonPath = OutputPath();
        ASSERT_TRUE(WriteMetrics({TcpProduction, TcpPreview, UdpProduction, UdpPreview}));

        std::ifstream Input(JsonPath, std::ios::binary);
        ASSERT_TRUE(Input);
        std::ostringstream Contents;
        Contents << Input.rdbuf();
        const auto Json = Contents.str();
        EXPECT_NE(Json.find("\"schema\": \"prism.perf-contract.v2\""), std::string::npos);
        EXPECT_NE(Json.find("\"sample_count\": 3"), std::string::npos);
        EXPECT_NE(Json.find("\"p95_ns\":"), std::string::npos);
        EXPECT_NE(Json.find("\"p99_ns\":"), std::string::npos);
        EXPECT_NE(Json.find("\"mad_ns\":"), std::string::npos);
        EXPECT_NE(Json.find("\"cpu_ns\":"), std::string::npos);
        EXPECT_NE(Json.find("\"environment\": {"), std::string::npos);
        EXPECT_NE(Json.find("\"compiler\":"), std::string::npos);
        EXPECT_NE(Json.find("\"pointer_bits\":"), std::string::npos);
        EXPECT_NE(Json.find("\"peak_working_set_bytes\":"), std::string::npos);
        EXPECT_NE(Json.find("\"bytes_per_second\":"), std::string::npos);
        EXPECT_NE(Json.find("\"packets_per_second\":"), std::string::npos);
        EXPECT_NE(Json.find("\"samples_ns\": ["), std::string::npos);
        EXPECT_NE(Json.find("\"cpu_samples_ns\": ["), std::string::npos);
        EXPECT_NE(Json.find("\"comparisons\": ["), std::string::npos);
        EXPECT_NE(Json.find("\"classification\":"), std::string::npos);
    }

    TEST(PerformanceContract, WritesComparableCodecMetrics)
    {
        constexpr std::size_t Warmup = 100;
        constexpr std::size_t Iterations = 10000;
        const auto VlessWire = BuildVlessWire();
        const auto SocksWire = BuildSocksWire();
        constexpr std::array<std::uint8_t, 16> Psk{
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        constexpr std::array<std::uint8_t, 16> Salt{
            0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
            0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F};

        std::array<Measurement, 3> ProductionVless{};
        std::array<Measurement, 3> PreviewVless{};
        std::array<Measurement, 3> ProductionSs{};
        std::array<Measurement, 3> PreviewSs{};
        std::array<Measurement, 3> ProductionSocks{};
        std::array<Measurement, 3> PreviewSocks{};
        std::array<Measurement, 3> ProductionTransport{};
        std::array<Measurement, 3> PreviewTransport{};
        std::array<bool, 3> ProductionTransportFailed{};
        std::array<bool, 3> PreviewTransportFailed{};
        std::array<Measurement, 3> ProductionTcp{};
        std::array<Measurement, 3> PreviewTcp{};
        std::array<bool, 3> ProductionTcpFailed{};
        std::array<bool, 3> PreviewTcpFailed{};
        std::array<Measurement, 3> ProductionUdp{};
        std::array<Measurement, 3> PreviewUdp{};
        std::array<bool, 3> ProductionUdpFailed{};
        std::array<bool, 3> PreviewUdpFailed{};
        const auto TransportPayload = std::make_shared<const std::vector<std::byte>>(
            16 * 1024, std::byte{0x5A});
        const auto UdpPayload = std::make_shared<const std::vector<std::byte>>(
            1200, std::byte{0xA5});
        constexpr std::size_t TransportWarmup = 10;
        constexpr std::size_t TransportIterations = 100;
        constexpr std::size_t TcpWarmup = 1;
        constexpr std::size_t TcpIterations = 4;
        constexpr std::size_t UdpWarmup = 1;
        constexpr std::size_t UdpIterations = 64;

        for (std::size_t Repetition = 0; Repetition < 3; ++Repetition)
        {
            ProductionVless[Repetition] = Measure(
                [&]
                {
                    const auto Parsed = psm::protocol::vless::format::parse_request(VlessWire);
                    EXPECT_TRUE(Parsed.has_value());
                },
                Warmup, Iterations);
            PreviewVless[Repetition] = Measure(
                [&]
                {
                    Preview::Vless::RequestHeader Parsed;
                    std::size_t Consumed = 0;
                    EXPECT_EQ(Preview::Vless::ParseRequest(VlessWire, Parsed, Consumed), Preview::Error::None);
                },
                Warmup, Iterations);
            ProductionSs[Repetition] = Measure(
                [&]
                {
                    std::array<std::uint8_t, 16> Output{};
                    psm::crypto::derive_key(psm::protocol::shadowsocks::kdf_context,
                                            std::span<const std::uint8_t>(Psk.data(), Psk.size()),
                                            Output);
                },
                Warmup, Iterations);
            PreviewSs[Repetition] = Measure(
                [&]
                {
                    const auto Output = Preview::Shadowsocks2022::SessionKey(Psk, Salt, 16);
                    EXPECT_EQ(Output.size(), 16u);
                },
                Warmup, Iterations);
            ProductionSocks[Repetition] = Measure(
                [&]
                {
                    const auto Parsed = psm::protocol::shadowsocks::format::parse_addr_port(SocksWire);
                    EXPECT_EQ(Parsed.first, psm::fault::code::success);
                },
                Warmup, Iterations);
            PreviewSocks[Repetition] = Measure(
                [&]
                {
                    Preview::Socks5::Address Parsed;
                    std::size_t Consumed = 0;
                    EXPECT_EQ(Preview::Socks5::ParseAddress(SocksWire, Parsed, Consumed), Preview::Error::None);
                },
                Warmup, Iterations);
            const auto ProductionTransportObservation =
                ObserveProductionTransport(TransportPayload, TransportWarmup, TransportIterations);
            const auto PreviewTransportObservation =
                ObservePreviewTransport(TransportPayload, TransportWarmup, TransportIterations);
            ProductionTransport[Repetition] = ProductionTransportObservation.Result;
            PreviewTransport[Repetition] = PreviewTransportObservation.Result;
            ProductionTransportFailed[Repetition] = ProductionTransportObservation.Failed;
            PreviewTransportFailed[Repetition] = PreviewTransportObservation.Failed;
            const auto ProductionTcpObservation = ObserveProductionTcp(TransportPayload, TcpWarmup, TcpIterations);
            const auto PreviewTcpObservation = ObservePreviewTcp(TransportPayload, TcpWarmup, TcpIterations);
            ProductionTcp[Repetition] = ProductionTcpObservation.Result;
            PreviewTcp[Repetition] = PreviewTcpObservation.Result;
            ProductionTcpFailed[Repetition] = ProductionTcpObservation.Failed;
            PreviewTcpFailed[Repetition] = PreviewTcpObservation.Failed;
            const auto ProductionUdpObservation = ObserveProductionUdp(UdpPayload, UdpWarmup, UdpIterations);
            const auto PreviewUdpObservation = ObservePreviewUdp(UdpPayload, UdpWarmup, UdpIterations);
            ProductionUdp[Repetition] = ProductionUdpObservation.Result;
            PreviewUdp[Repetition] = PreviewUdpObservation.Result;
            ProductionUdpFailed[Repetition] = ProductionUdpObservation.Failed;
            PreviewUdpFailed[Repetition] = PreviewUdpObservation.Failed;
        }

        const std::vector<Metric> Metrics{
            MakeMetric("vless.parse_request", "production", ProductionVless, VlessWire.size()),
            MakeMetric("vless.parse_request", "preview", PreviewVless, VlessWire.size()),
            MakeMetric("ss2022.session_key", "production", ProductionSs, Psk.size()),
            MakeMetric("ss2022.session_key", "preview", PreviewSs, Psk.size()),
            MakeMetric("socks5.parse_addr_port", "production", ProductionSocks, SocksWire.size()),
            MakeMetric("socks5.parse_addr_port", "preview", PreviewSocks, SocksWire.size()),
            MakeMetric("transport.mock_write", "production", ProductionTransport, TransportPayload->size()),
            MakeMetric("transport.mock_write", "preview", PreviewTransport, TransportPayload->size()),
            MakeMetric("transport.tcp_loopback", "production", ProductionTcp, TransportPayload->size(), TcpWarmup,
                       TcpIterations),
            MakeMetric("transport.tcp_loopback", "preview", PreviewTcp, TransportPayload->size(), TcpWarmup,
                       TcpIterations),
            MakeMetric("transport.udp_loopback", "production", ProductionUdp, UdpPayload->size(), UdpWarmup,
                       UdpIterations),
            MakeMetric("transport.udp_loopback", "preview", PreviewUdp, UdpPayload->size(), UdpWarmup,
                       UdpIterations),
        };
        for (const auto Failed : ProductionTransportFailed)
        {
            EXPECT_FALSE(Failed);
        }
        for (const auto Failed : PreviewTransportFailed)
        {
            EXPECT_FALSE(Failed);
        }
        for (const auto Failed : ProductionTcpFailed)
        {
            EXPECT_FALSE(Failed);
        }
        for (const auto Failed : PreviewTcpFailed)
        {
            EXPECT_FALSE(Failed);
        }
        for (const auto Failed : ProductionUdpFailed)
        {
            EXPECT_FALSE(Failed);
        }
        for (const auto Failed : PreviewUdpFailed)
        {
            EXPECT_FALSE(Failed);
        }
        for (const auto &MetricValue : Metrics)
        {
            EXPECT_GT(Median(MetricValue.Samples), 0.0);
        }
        ASSERT_TRUE(WriteMetrics(Metrics));

        std::ifstream Input(OutputPath(), std::ios::binary);
        ASSERT_TRUE(Input);
        std::ostringstream Contents;
        Contents << Input.rdbuf();
        EXPECT_NE(Contents.str().find("\"metric\": \"transport.mock_write\""), std::string::npos);
        EXPECT_NE(Contents.str().find("\"metric\": \"transport.tcp_loopback\""), std::string::npos);
        EXPECT_NE(Contents.str().find("\"metric\": \"transport.udp_loopback\""), std::string::npos);
    }

} // namespace
