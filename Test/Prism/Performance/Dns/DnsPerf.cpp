/**
 * @file DnsPerf.cpp
 * @brief DNS benchmark cache、message、loopback 与 CLI 编排。
 */

#include "DnsPerfRuntime.hpp"

namespace Net = boost::asio;
using Prism::Network::Dns::Cache;
using Prism::Network::Dns::CacheOptions;
using Prism::Network::Dns::Message;
using Prism::Network::Dns::QType;
using DnsPerf::NowNs;

namespace DnsPerf
{
    [[nodiscard]] auto RunDnsPreflight() -> bool;
    [[nodiscard]] auto RunCoalescerCompare() -> int;

    [[nodiscard]] auto RunCacheBenchmark() -> bool
    {
        CacheOptions Options;
        Options.MaxEntries = 4096;
        Cache CacheValue(Options);
        constexpr std::size_t KeyCount = 1000;
        std::vector<std::string> Keys;
        Keys.reserve(KeyCount);
        for (std::size_t Index = 0; Index < KeyCount; ++Index)
        {
            auto Domain = "host" + std::to_string(Index) + ".example.com";
            Prism::Network::Dns::PutInput Input;
            Input.Domain = Domain;
            Input.QType = 1;
            Input.Ips.assign(1, Net::ip::make_address("10.0.0.1"));
            Input.Ttl = std::chrono::seconds(3600);
            CacheValue.Put(Input);
            Keys.push_back(std::move(Domain));
        }
        std::mt19937 RandomGenerator(1U);
        const auto ExpectedIp = Net::ip::make_address("10.0.0.1");
        constexpr std::size_t OperationCount = 200000;
        const auto Start = NowNs();
        std::uint64_t Hits = 0;
        for (std::size_t Index = 0; Index < OperationCount; ++Index)
        {
            const auto &Key = Keys[RandomGenerator() % KeyCount];
            if (auto Hit = CacheValue.Get(Key, 1))
            {
                ++Hits;
                if (!Hit->empty() && (*Hit)[0] != ExpectedIp)
                {
                    std::printf("[FAIL] 缓存值不一致\n");
                    return false;
                }
            }
        }
        const auto Nanoseconds = NowNs() - Start;
        if (Hits != OperationCount)
        {
            std::printf("[FAIL] 缓存命中率 < 100%%：%llu/%llu\n",
                        static_cast<unsigned long long>(Hits), OperationCount);
            return false;
        }
        std::printf("1. Cache 命中路径      : %8llu ns/op （%llu 次全命中）\n",
                    static_cast<unsigned long long>(Nanoseconds / OperationCount),
                    OperationCount);
        return true;
    }

    [[nodiscard]] auto RunAnswerScan(const std::vector<std::uint8_t> &Wire,
                                      const std::size_t OperationCount) -> std::uint64_t
    {
        Prism::Memory::BytePool Pool({.BlockSize = 64 * 1024, .BlockCount = 2});
        const auto Start = NowNs();
        std::expected<Prism::Network::Dns::AnswerSet, Prism::Fault::Failure> Last{
            std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::WouldBlock, {}})};
        for (std::size_t Index = 0; Index < OperationCount; ++Index)
        {
            Last = Prism::Network::Dns::ScanAnswers(Wire, {QType::A, Pool});
        }
        if (!Last || Last->Ips.Size() != 1 ||
            Last->Ips[0] != Net::ip::make_address("9.8.7.6"))
        {
            std::printf("[FAIL] Scan 提取地址不一致\n");
            std::exit(1);
        }
        return NowNs() - Start;
    }

    [[nodiscard]] auto RunMessageUnpack(const std::vector<std::uint8_t> &Wire,
                                         const std::size_t OperationCount) -> std::uint64_t
    {
        const auto Start = NowNs();
        std::optional<Prism::Network::Dns::Message> Last;
        for (std::size_t Index = 0; Index < OperationCount; ++Index)
        {
            Last = Prism::Network::Dns::Message::Unpack(Wire);
        }
        if (!Last || Prism::Network::Dns::ExtractIps(*Last).size() != 1)
        {
            std::printf("[FAIL] Unpack 提取地址不一致\n");
            std::exit(1);
        }
        return NowNs() - Start;
    }

    [[nodiscard]] auto RunMessageBenchmark() -> bool
    {
        Message Query = Message::MakeQuery(*Prism::Network::DomainName::Parse("bench.example.com"), QType::A);
        Query.Id = 0x1234;
        Query.Qr = true;
        Prism::Network::Dns::Record Answer;
        Answer.Name = "bench.example.com";
        Answer.Type = QType::A;
        Answer.Ttl = 60;
        Answer.Rdata = {9, 8, 7, 6};
        Query.Answers.push_back(Answer);
        const auto Wire = Query.Pack();
        constexpr std::size_t OperationCount = 50000;
        const auto ScanNanoseconds = RunAnswerScan(Wire, OperationCount);
        const auto UnpackNanoseconds = RunMessageUnpack(Wire, OperationCount);
        std::printf(
            "2. AnswerScan          : %8llu ns/op （Unpack 物化 %llu ns/op，加速 %.1fx）\n",
            static_cast<unsigned long long>(ScanNanoseconds / OperationCount),
            static_cast<unsigned long long>(UnpackNanoseconds / OperationCount),
            static_cast<double>(UnpackNanoseconds) / static_cast<double>(ScanNanoseconds));
        return true;
    }

    struct LoopbackQueryRequest final
    {
        Prism::Network::Dns::Resolver &Resolver;
        Net::io_context &IoContext;
        std::size_t Index{0};
        std::size_t QueryCount{0};
        std::size_t &Done;
        std::size_t &Succeeded;
    };

    auto RunLoopbackQuery(LoopbackQueryRequest Request) -> Net::awaitable<void>
    {
        const auto Addresses = co_await Request.Resolver.AsyncResolve(
            "q" + std::to_string(Request.Index) + ".perf.example.com");
        if (Addresses && Addresses->Size() == 1)
        {
            ++Request.Succeeded;
        }
        if (++Request.Done == Request.QueryCount)
        {
            Request.IoContext.stop();
        }
    }

    auto RecordLoopbackFailure(std::exception_ptr Failure,
                               std::exception_ptr &Observed) -> void
    {
        if (Failure)
        {
            Observed = std::move(Failure);
        }
    }

    auto CloseLoopbackServer(const std::shared_ptr<PerfDnsServer> &Server,
                             std::promise<void> &Closed) -> void
    {
        Server->Close();
        Closed.set_value();
    }

    [[nodiscard]] auto RunLoopbackBenchmark() -> bool
    {
        Net::io_context IoContext;
        Net::io_context ServerIoContext;
        auto Server = std::make_shared<PerfDnsServer>(ServerIoContext);
        Server->Start();
        std::thread ServerThread([&ServerIoContext] { ServerIoContext.run(); });

        Prism::Network::Dns::Config Config;
        Prism::Network::Dns::Server Upstream;
        Upstream.Address = "127.0.0.1";
        Upstream.Port = Server->Port();
        Upstream.TimeoutMs = 2000;
        Config.Servers.push_back(Upstream);
        Config.DisableIpv6 = true;
        Config.CacheEnabled = false;
        Prism::Network::Dns::Resolver Resolver(IoContext.get_executor(), Config);

        constexpr std::size_t QueryCount = 500;
        std::size_t Done = 0;
        std::size_t Succeeded = 0;
        std::exception_ptr Failure;
        const auto Start = NowNs();
        for (std::size_t Index = 0; Index < QueryCount; ++Index)
        {
            Net::co_spawn(
                IoContext,
                RunLoopbackQuery(LoopbackQueryRequest{
                    Resolver, IoContext, Index, QueryCount, Done, Succeeded}),
                [&Failure](std::exception_ptr Error) { RecordLoopbackFailure(Error, Failure); });
        }
        IoContext.run();

        std::promise<void> ClosePromise;
        auto CloseFuture = ClosePromise.get_future();
        Net::post(ServerIoContext, [Server, &ClosePromise]
        { CloseLoopbackServer(Server, ClosePromise); });
        CloseFuture.wait();
        ServerIoContext.stop();
        ServerThread.join();

        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
        const auto Nanoseconds = NowNs() - Start;
        if (Succeeded != QueryCount)
        {
            std::printf("[FAIL] E2E 成功率 < 100%%：%llu/%llu\n",
                        static_cast<unsigned long long>(Succeeded), QueryCount);
            return false;
        }
        const auto Qps = static_cast<double>(QueryCount) *
                         (1e9 / static_cast<double>(Nanoseconds));
        std::printf("3. 回环 E2E（并发 500） : %8.0f QPS （UDP 全链路，含本地 fake Server）\n", Qps);
        return true;
    }
}

auto main(int Argc, char **Argv) -> int
{
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("== preview DNS 性能基准 ==\n");
    if (Argc > 1 && std::strcmp(Argv[1], "--coalescer-compare") == 0)
    {
        return DnsPerf::RunCoalescerCompare();
    }
    if (!DnsPerf::RunDnsPreflight())
    {
        std::printf("[FAIL] DNS single-flight/cancel/cache preflight\n");
        return 1;
    }
    if (!DnsPerf::RunCacheBenchmark() || !DnsPerf::RunMessageBenchmark() ||
        !DnsPerf::RunLoopbackBenchmark())
    {
        return 1;
    }
    std::printf("== 门禁通过 ==\n");
    return 0;
}
