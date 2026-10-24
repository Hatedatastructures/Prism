/**
 * @file Bench.hpp
 * @brief 性能基准工具（吞吐量 / 延迟统计）
 * @details 提供协议性能测试的统一测量原语：
 *          - BenchOptions：测试参数（总字节数 / 块大小 / 队列深度）
 *          - BenchReport：完整往返吞吐量及延迟分位数
 *          - BenchThroughput() / BenchThroughputTx() / BenchPrismThroughput()：单连接吞吐与延迟测量
 * @note 配合 MemoryStream（内存）或真实 socket 使用。
 * @note 旧接口与 Prism typed Transmission 使用独立具名入口；Prism 结果保留部分字节、耗时和 Failure。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <concepts>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <numeric>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism
{

    namespace Net = boost::asio;

    /** @brief 吞吐与延迟测量选项。 */
    struct BenchOptions
    {
        /** @brief 单方向计划传输总字节数。 */
        std::size_t Total{64 * 1024 * 1024};
        /** @brief 单块缓冲区大小。 */
        std::size_t Block{64 * 1024};
        /** @brief 保留的历史选项字段；当前基准入口不据此创建并发操作。 */
        std::size_t Depth{8};
    };

    /** @brief 完整读写往返的吞吐量、延迟与样本数。 */
    struct BenchReport
    {
        /** @brief 完整写入并完整读回的 payload 字节数；不含未完成块。 */
        std::size_t Bytes{0};
        /** @brief 实际测量耗时；即使 I/O 失败也记录已耗时。 */
        std::chrono::duration<double> Elapsed{0.0};
        /** @brief 完整往返 payload 的 MiB/s。 */
        double Mbps{0.0};
        /** @brief 完整块往返延迟统计，单位为毫秒。 */
        double LatencyAvg{0.0};
        double LatencyP50{0.0};
        double LatencyP95{0.0};
        double LatencyP99{0.0};
        double LatencyMin{0.0};
        double LatencyMax{0.0};
        /** @brief 已完整往返并进入延迟分布的块数。 */
        std::size_t Samples{0};
    };

    /**
     * @brief Prism typed 基准的唯一结果：实际测量报告与同次领域失败。
     * @details Report.Bytes 只累计完整往返块；BytesWritten 和 BytesRead 分别保留写入与回读的
     *          实际部分字节。Failure 为唯一终态事实，不用 expected 丢弃部分测量结果。
     */
    struct PrismBenchResult final
    {
        BenchReport Report{};
        std::size_t BytesWritten{0};
        std::size_t BytesRead{0};
        Fault::Failure Failure{};
    };
    /** @brief 旧版 ReadSome/WriteAll 基准入口接受的独立传输契约。 */
    /** @tparam T 满足旧版读写接口的传输类型。 */
    template <typename T>
    concept BenchStream = requires(
        T &Value,
        std::span<std::uint8_t> ReadBuffer,
        std::span<const std::uint8_t> WriteBuffer)
    {
        { Value.ReadSome(ReadBuffer) } -> std::same_as<Net::awaitable<std::size_t>>;
        { Value.WriteAll(WriteBuffer) } -> std::same_as<Net::awaitable<boost::system::error_code>>;
    };

    /** @brief 旧版 async_read_some/async_write_some 基准入口的独立传输契约。 */
    /** @tparam T 满足旧版异步读写接口的传输类型。 */
    template <typename T>
    concept BenchTx =
        requires(
            T &Value,
            std::span<std::byte> ReadBuffer,
            std::span<const std::byte> WriteBuffer,
            std::error_code &ErrorValue)
        {
            { Value.async_read_some(ReadBuffer, ErrorValue) } -> std::same_as<Net::awaitable<std::size_t>>;
            { Value.async_write_some(WriteBuffer, ErrorValue) } -> std::same_as<Net::awaitable<std::size_t>>;
        };

    /**
     * @brief Prism 正式传输能力：只接受唯一 ReadSome/WriteSome 与 IoResult 契约。
     * @tparam T 由 Transmission 或遵循相同正式接口的测试传输实现。
     */
    template <typename T>
    concept PrismBenchTransport =
        requires(T &Value, std::span<std::byte> ReadBuffer,
                 std::span<const std::byte> WriteBuffer)
        {
            { Value.ReadSome(ReadBuffer) } -> std::same_as<Net::awaitable<IoResult>>;
            { Value.WriteSome(WriteBuffer) } -> std::same_as<Net::awaitable<IoResult>>;
        };

    namespace Detail
    {

        /**
         * @brief 旧版基准共享测量循环。
         * @tparam WriteBlock 写块操作；true 表示整块写入完成。
         * @tparam ReadBlock 读块操作；返回实际读回字节数。
         * @param Write 写块协程
         * @param Read 读块协程
         * @param Options 测试选项。
         * @return 完整往返字节数、吞吐率与延迟分布。
         * @details 顺序执行写块和读回，直到计划完成、写失败或读回不足。
         */
        template <typename WriteBlock, typename ReadBlock>
        auto RunBench(WriteBlock Write, ReadBlock Read, const BenchOptions &Options)
            -> Net::awaitable<BenchReport>
        {
            BenchReport Report;
            const auto Started = std::chrono::steady_clock::now();

            std::vector<std::uint8_t> WriteBuffer(Options.Block, 0x5a);
            std::vector<std::uint8_t> ReadBuffer(Options.Block);
            std::vector<double> Latencies;
            if (Options.Block != 0)
            {
                Latencies.reserve(Options.Total / Options.Block);
            }

            std::size_t Completed = 0;
            while (Completed < Options.Total && Options.Block != 0)
            {
                const auto Chunk = std::min(Options.Block, Options.Total - Completed);
                const auto BlockStarted = std::chrono::steady_clock::now();
                const bool WriteSucceeded = co_await Write(
                    std::span<const std::uint8_t>(WriteBuffer.data(), Chunk));
                if (!WriteSucceeded)
                {
                    break;
                }
                const auto BytesRead = co_await Read(
                    std::span<std::uint8_t>(ReadBuffer.data(), Chunk));
                if (BytesRead < Chunk)
                {
                    break;
                }
                const auto BlockFinished = std::chrono::steady_clock::now();
                const double ElapsedMilliseconds = std::chrono::duration<double, std::milli>(
                    BlockFinished - BlockStarted).count();
                Latencies.push_back(ElapsedMilliseconds);
                Completed += Chunk;
            }

            const auto Finished = std::chrono::steady_clock::now();
            Report.Elapsed = std::chrono::duration<double>(Finished - Started);
            Report.Bytes = Completed;
            Report.Samples = Latencies.size();
            if (!Latencies.empty())
            {
                const double Seconds = Report.Elapsed.count();
                if (Seconds > 0)
                {
                    Report.Mbps = static_cast<double>(Completed) / (1024.0 * 1024.0) / Seconds;
                }
                else
                {
                    Report.Mbps = static_cast<double>(Completed) / (1024.0 * 1024.0) / 1e-9;
                }
                std::sort(Latencies.begin(), Latencies.end());
                const auto Percentile = [&Latencies](double Position) -> double
                {
                    const auto Index = static_cast<std::size_t>(
                        Position * static_cast<double>(Latencies.size() - 1));
                    return Latencies[Index];
                };
                Report.LatencyAvg = std::accumulate(Latencies.begin(), Latencies.end(), 0.0) /
                                    static_cast<double>(Latencies.size());
                Report.LatencyP50 = Percentile(0.50);
                Report.LatencyP95 = Percentile(0.95);
                Report.LatencyP99 = Percentile(0.99);
                Report.LatencyMin = Latencies.front();
                Report.LatencyMax = Latencies.back();
            }
            co_return Report;
        }

        template <BenchStream Stream>
        struct BenchStreamWriteOperation final
        {
            Stream &Value;

            auto operator()(std::span<const std::uint8_t> Data) -> Net::awaitable<bool>
            {
                const auto ErrorValue = co_await Value.WriteAll(Data);
                co_return !ErrorValue;
            }
        };

        template <BenchStream Stream>
        struct BenchStreamReadOperation final
        {
            Stream &Value;

            auto operator()(std::span<std::uint8_t> Data) -> Net::awaitable<std::size_t>
            {
                std::size_t BytesRead = 0;
                while (BytesRead < Data.size())
                {
                    const auto Part = co_await Value.ReadSome(Data.subspan(BytesRead));
                    if (Part == 0)
                    {
                        break;
                    }
                    BytesRead += Part;
                }
                co_return BytesRead;
            }
        };

        template <BenchTx Stream>
        struct BenchTxWriteOperation final
        {
            Stream &Value;

            auto operator()(std::span<const std::uint8_t> Data) -> Net::awaitable<bool>
            {
                std::size_t BytesWritten = 0;
                while (BytesWritten < Data.size())
                {
                    std::error_code ErrorValue;
                    const auto Part = co_await Value.async_write_some(
                        AsBytes(std::span<const std::uint8_t>(Data.data() + BytesWritten,
                                                              Data.size() - BytesWritten)),
                        ErrorValue);
                    if (ErrorValue || Part == 0)
                    {
                        co_return false;
                    }
                    BytesWritten += Part;
                }
                co_return true;
            }
        };

        template <BenchTx Stream>
        struct BenchTxReadOperation final
        {
            Stream &Value;

            auto operator()(std::span<std::uint8_t> Data) -> Net::awaitable<std::size_t>
            {
                std::size_t BytesRead = 0;
                while (BytesRead < Data.size())
                {
                    std::error_code ErrorValue;
                    const auto Part = co_await Value.async_read_some(
                        AsBytes(Data.subspan(BytesRead)), ErrorValue);
                    if (ErrorValue || Part == 0)
                    {
                        break;
                    }
                    BytesRead += Part;
                }
                co_return BytesRead;
            }
        };

        /**
         * @brief 逐次写满基准块，累计真实 Bytes 后再交付同次 Failure。
         * @param Stream 唯一 typed 写入载体。
         * @param Data 本轮写入块。
         * @return 实际写入字节与终态失败；非空块零进度映射为 IoError。
         */
        template <PrismBenchTransport T>
        auto WritePrismBlock(T &Stream, std::span<const std::uint8_t> Data)
            -> Net::awaitable<IoResult>
        {
            std::size_t Bytes = 0;
            while (Bytes < Data.size())
            {
                const auto Remaining = Data.subspan(Bytes);
                const auto Result = co_await Stream.WriteSome(AsBytes(Remaining));
                if (Result.Bytes > Remaining.size())
                {
                    co_return IoResult{Bytes, Fault::Failure{Fault::Code::InvalidArgument}};
                }
                Bytes += Result.Bytes;
                if (Result.Failure.Failed())
                {
                    co_return IoResult{Bytes, Result.Failure};
                }
                if (Result.Bytes == 0)
                {
                    co_return IoResult{Bytes, Fault::Failure{Fault::Code::IoError}};
                }
            }
            co_return IoResult{Bytes, {}};
        }

        /**
         * @brief 逐次读满基准块，累计真实 Bytes 后再交付同次 Failure。
         * @param Stream 唯一 typed 读取载体。
         * @param Data 本轮读取块。
         * @return 实际读取字节与终态失败；非空块零进度映射为 IoError。
         */
        template <PrismBenchTransport T>
        auto ReadPrismBlock(T &Stream, std::span<std::uint8_t> Data)
            -> Net::awaitable<IoResult>
        {
            std::size_t Bytes = 0;
            while (Bytes < Data.size())
            {
                const auto Remaining = Data.subspan(Bytes);
                const auto Result = co_await Stream.ReadSome(AsBytes(Remaining));
                if (Result.Bytes > Remaining.size())
                {
                    co_return IoResult{Bytes, Fault::Failure{Fault::Code::InvalidArgument}};
                }
                Bytes += Result.Bytes;
                if (Result.Failure.Failed())
                {
                    co_return IoResult{Bytes, Result.Failure};
                }
                if (Result.Bytes == 0)
                {
                    co_return IoResult{Bytes, Fault::Failure{Fault::Code::IoError}};
                }
            }
            co_return IoResult{Bytes, {}};
        }

        struct PrismBenchMeasurement final
        {
            PrismBenchResult Result{};
            std::vector<double> Latencies;
            std::chrono::steady_clock::time_point Started{std::chrono::steady_clock::now()};

            auto Finish() -> PrismBenchResult
            {
                Result.Report.Elapsed = std::chrono::duration<double>(
                    std::chrono::steady_clock::now() - Started);
                Result.Report.Samples = Latencies.size();
                const auto Seconds = Result.Report.Elapsed.count();
                if (Seconds > 0.0)
                {
                    Result.Report.Mbps = static_cast<double>(Result.Report.Bytes)
                        / (1024.0 * 1024.0) / Seconds;
                }
                else if (Result.Report.Bytes > 0)
                {
                    Result.Report.Mbps = static_cast<double>(Result.Report.Bytes)
                        / (1024.0 * 1024.0) / 1e-9;
                }

                if (Latencies.empty())
                {
                    return std::move(Result);
                }
                std::sort(Latencies.begin(), Latencies.end());
                const auto Percentile = [this](double Position) -> double
                {
                    const auto Index = static_cast<std::size_t>(
                        Position * static_cast<double>(Latencies.size() - 1));
                    return Latencies[Index];
                };
                Result.Report.LatencyAvg = std::accumulate(Latencies.begin(), Latencies.end(), 0.0)
                    / static_cast<double>(Latencies.size());
                Result.Report.LatencyP50 = Percentile(0.50);
                Result.Report.LatencyP95 = Percentile(0.95);
                Result.Report.LatencyP99 = Percentile(0.99);
                Result.Report.LatencyMin = Latencies.front();
                Result.Report.LatencyMax = Latencies.back();
                return std::move(Result);
            }
        };

        /**
         * @brief 执行 Prism typed 逐块往返测量并保留部分结果。
         * @tparam Writer 满足 PrismBenchTransport 的写入端。
         * @tparam Reader 满足 PrismBenchTransport 的读取端。
         * @param Write 写入载体。
         * @param Read 读取载体。
         * @param Options 总量与块大小。
         * @return 完整往返报告、实际上下行字节、耗时、延迟样本及唯一领域 Failure。
         */
        template <PrismBenchTransport Writer, PrismBenchTransport Reader>
        auto RunPrismBench(Writer &Write, Reader &Read, const BenchOptions &Options)
            -> Net::awaitable<PrismBenchResult>
        {
            PrismBenchMeasurement Measurement;
            if (Options.Block == 0)
            {
                if (Options.Total > 0)
                {
                    Measurement.Result.Failure = Fault::Failure{Fault::Code::InvalidArgument};
                }
                co_return Measurement.Finish();
            }

            std::vector<std::uint8_t> WriteBuffer(Options.Block, 0x5a);
            std::vector<std::uint8_t> ReadBuffer(Options.Block);
            Measurement.Latencies.reserve(Options.Total / Options.Block);
            while (Measurement.Result.Report.Bytes < Options.Total)
            {
                const auto Chunk = std::min(
                    Options.Block, Options.Total - Measurement.Result.Report.Bytes);
                const auto BlockStart = std::chrono::steady_clock::now();
                const auto WriteResult = co_await WritePrismBlock(
                    Write, std::span<const std::uint8_t>(WriteBuffer.data(), Chunk));
                if (WriteResult.Failure.Failed())
                {
                    Measurement.Result.BytesWritten += WriteResult.Bytes;
                    Measurement.Result.Failure = WriteResult.Failure;
                    break;
                }
                if (WriteResult.Bytes < Chunk)
                {
                    Measurement.Result.BytesWritten += WriteResult.Bytes;
                    Measurement.Result.Failure = Fault::Failure{Fault::Code::IoError};
                    break;
                }
                Measurement.Result.BytesWritten += WriteResult.Bytes;

                const auto ReadResult = co_await ReadPrismBlock(
                    Read, std::span<std::uint8_t>(ReadBuffer.data(), Chunk));
                Measurement.Result.BytesRead += ReadResult.Bytes;
                if (ReadResult.Failure.Failed())
                {
                    Measurement.Result.Failure = ReadResult.Failure;
                    break;
                }
                if (ReadResult.Bytes < Chunk)
                {
                    Measurement.Result.Failure = Fault::Failure{Fault::Code::IoError};
                    break;
                }

                Measurement.Result.Report.Bytes += Chunk;
                Measurement.Latencies.push_back(std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - BlockStart).count());
            }
            co_return Measurement.Finish();
        }
    } // namespace Detail

    /**
     * @brief 对 Prism typed 传输执行吞吐与往返延迟测量。
     * @tparam Writer 满足 PrismBenchTransport 的写入端类型。
     * @tparam Reader 满足 PrismBenchTransport 的读取端类型。
     * @param Write 写入端。
     * @param Read 读取端。
     * @param Options 总字节数与块大小。
     * @return Report.Bytes 统计完整往返字节；结果另存实际写入与回读字节及唯一 Failure。
     * @details 普通 I/O 失败作为 Failure 返回，不转成异常。
     */
    template <PrismBenchTransport Writer, PrismBenchTransport Reader>
    auto BenchPrismThroughput(Writer &Write, Reader &Read, const BenchOptions &Options)
        -> Net::awaitable<PrismBenchResult>
    {
        return Detail::RunPrismBench(Write, Read, Options);
    }
    /**
     * @brief 旧版 ReadSome/WriteAll 接口的吞吐与延迟测量入口。
     * @tparam S 满足 BenchStream 的旧版传输类型。
     * @param Write 写入端。
     * @param Read 读取端。
     * @param Options 测试选项。
     * @return 完整往返测量报告。
     */
    template <BenchStream S>
    auto BenchThroughput(S &Write, S &Read, const BenchOptions &Options) -> Net::awaitable<BenchReport>
    {
        return Detail::RunBench(
            Detail::BenchStreamWriteOperation<S>{Write},
            Detail::BenchStreamReadOperation<S>{Read},
            Options);
    }

    /**
     * @brief 旧版 async_* 接口的吞吐与延迟测量入口。
     * @tparam S 满足 BenchTx 的旧版传输类型。
     * @param Write 写入端。
     * @param Read 读取端。
     * @param Options 测试选项。
     * @return 完整往返测量报告。
     */
    template <BenchTx S>
    auto BenchThroughputTx(S &Write, S &Read, const BenchOptions &Options) -> Net::awaitable<BenchReport>
    {
        return Detail::RunBench(
            Detail::BenchTxWriteOperation<S>{Write},
            Detail::BenchTxReadOperation<S>{Read},
            Options);
    }

} // namespace Prism
