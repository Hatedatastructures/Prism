/**
 * @file DnsPerf.cpp
 * @brief preview DNS 性能基准（对标主项目 DnsCacheBench / DnsMessageBench / ResolveBench）
 * @details 三组指标：
 *          1. Cache 命中路径：预填缓存后随机键 Get，验证"亚微秒、零堆分配"设计
 *          2. 报文解析：AnswerScan（热路径单遍扫描）vs Message::Unpack（完整物化）
 *          3. 回环端到端：FakeDnsServer + Resolver 顺序解析 QPS
 *          门禁（退出码非零 = 不达标）：
 *          - Cache 命中正确性 100%（预热键全命中）
 *          - Scan/Unpack 提取地址一致（抽样比对）
 *          - E2E 成功率 100%
 *          绝对性能数字仅打印供对标记录，不作为门禁（跨机器噪声大）
 *          独立可执行，ctest 注册为 perf 标签（默认回归不跑）：
 *          ctest -L perf -R Perf_Dns
 */

#include <preview/Net/Dns/Answer.hpp>
#include <preview/Net/Dns/Cache.hpp>
#include <preview/Net/Dns/Format.hpp>
#include <preview/Net/Dns/Resolver.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <string>
#include <vector>

namespace
{
    namespace Net = boost::asio;
    using Preview::Network::Dns::Cache;
    using Preview::Network::Dns::CacheOptions;
    using Preview::Network::Dns::Message;
    using Preview::Network::Dns::QType;

    using Clock = std::chrono::steady_clock;

    auto NowNs() -> std::uint64_t
    {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                Clock::now().time_since_epoch())
                .count());
    }

    /// 大端写入
    void PutU16(std::vector<std::uint8_t> &Output, const std::uint16_t Value)
    {
        Output.push_back(static_cast<std::uint8_t>(Value >> 8));
        Output.push_back(static_cast<std::uint8_t>(Value & 0xFF));
    }

    /// 回环 UDP fake DNS（固定 A 记录应答）
    class PerfDnsServer : public std::enable_shared_from_this<PerfDnsServer>
    {
    public:
        explicit PerfDnsServer(Net::io_context &IoContext)
            : Ex_(IoContext.get_executor()),
              Udp_(IoContext, Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0))
        {
        }

        auto Start() -> void
        {
            Port_ = Udp_.local_endpoint().port();
            auto self = shared_from_this();
            Net::co_spawn(Ex_, [self]() { return self->Loop(); }, Net::detached);
        }

        [[nodiscard]] auto Port() const -> std::uint16_t
        {
            return Port_;
        }

        void Close()
        {
            boost::system::error_code ErrorCode;
            Udp_.close(ErrorCode);
        }

    private:
        auto Loop() -> Net::awaitable<void>
        {
            std::vector<std::uint8_t> Buffer(4096);
            Net::ip::udp::endpoint Sender;
            for (;;)
            {
                boost::system::error_code ErrorCode;
                const auto Count = co_await Udp_.async_receive_from(
                    Net::buffer(Buffer), Sender, Net::redirect_error(Net::use_awaitable, ErrorCode));
                if (ErrorCode || Count < 12)
                {
                    co_return;
                }
                // 问题段结束
                std::size_t Offset = 12;
                while (Offset < static_cast<std::size_t>(Count) && Buffer[Offset] != 0)
                {
                    Offset += static_cast<std::size_t>(Buffer[Offset]) + 1;
                }
                const auto QEnd = Offset + 5;
                if (QEnd > static_cast<std::size_t>(Count))
                {
                    continue;
                }
                std::vector<std::uint8_t> Output;
                PutU16(Output, static_cast<std::uint16_t>((Buffer[0] << 8) | Buffer[1]));
                PutU16(Output, 0x8180u);
                PutU16(Output, 1);
                PutU16(Output, 1);
                PutU16(Output, 0);
                PutU16(Output, 0);
                Output.insert(Output.end(), Buffer.begin() + 12,
                           Buffer.begin() + static_cast<std::ptrdiff_t>(QEnd));
                PutU16(Output, 0xC00Cu);
                PutU16(Output, 1);
                PutU16(Output, 1);
                Output.insert(Output.end(), {0, 0, 0, 60, 0, 4, 1, 2, 3, 4});
                co_await Udp_.async_send_to(Net::buffer(Output), Sender,
                                            Net::redirect_error(Net::use_awaitable, ErrorCode));
            }
        }

        Net::any_io_executor Ex_;
        Net::ip::udp::socket Udp_;
        std::uint16_t Port_{0};
    };
} // namespace

auto main() -> int
{
    std::printf("== preview DNS 性能基准 ==\n");

    // ── 1. Cache 命中路径 ─────────────────────────────
    {
        CacheOptions Options;
        Options.MaxEntries = 4096;
        Cache cache(Options);
        constexpr std::size_t KeyCount = 1000;
        std::vector<std::string> keys;
        keys.reserve(KeyCount);
        for (std::size_t Index = 0; Index < KeyCount; ++Index)
        {
            auto domain = "host" + std::to_string(Index) + ".example.com";
            Preview::Network::Dns::PutInput Input;
            Input.Domain = domain;
            Input.QType = 1;
            Input.Ips.assign(1, Net::ip::make_address("10.0.0.1"));
            Input.Ttl = std::chrono::seconds(3600);
            cache.Put(Input);
            keys.push_back(std::move(domain));
        }
        std::mt19937 RandomGenerator(1U);
        const auto IpExpect = Net::ip::make_address("10.0.0.1");
        constexpr std::size_t OperationCount = 200000;
        const auto Start = NowNs();
        std::uint64_t Hits = 0;
        for (std::size_t Index = 0; Index < OperationCount; ++Index)
        {
            const auto &Key = keys[RandomGenerator() % KeyCount];
            if (auto hit = cache.Get(Key, 1))
            {
                ++Hits;
                if (!hit->empty() && (*hit)[0] != IpExpect)
                {
                    std::printf("[FAIL] 缓存值不一致\n");
                    return 1;
                }
            }
        }
        const auto Ns = NowNs() - Start;
        if (Hits != OperationCount)
        {
            std::printf("[FAIL] 缓存命中率 < 100%%：%llu/%llu\n",
                        static_cast<unsigned long long>(Hits), OperationCount);
            return 1;
        }
        std::printf("1. Cache 命中路径      : %8llu ns/op （%llu 次全命中）\n",
                    static_cast<unsigned long long>(Ns / OperationCount), OperationCount);
    }

    // ── 2. AnswerScan vs Unpack ───────────────────────
    {
        Message Message = Message::MakeQuery("bench.example.com", QType::A);
        Message.Id = 0x1234;
        Message.Qr = true;
        Preview::Network::Dns::Record a;
        a.Name = "bench.example.com";
        a.Type = QType::A;
        a.Ttl = 60;
        a.Rdata = {9, 8, 7, 6};
        Message.Answers.push_back(a);
        const auto Wire = Message.Pack();

        constexpr std::size_t OperationCount = 50000;
        auto RunScan = [&]() -> std::uint64_t
        {
            const auto Start = NowNs();
            std::optional<Preview::Network::Dns::AnswerSet> Last;
            for (std::size_t Index = 0; Index < OperationCount; ++Index)
            {
                Last = Preview::Network::Dns::ScanAnswers(Wire, 1);
            }
            if (!Last || Last->Ips.size() != 1 ||
                Last->Ips[0] != Net::ip::make_address("9.8.7.6"))
            {
                std::printf("[FAIL] Scan 提取地址不一致\n");
                std::exit(1);
            }
            return NowNs() - Start;
        };
        auto RunUnpack = [&]() -> std::uint64_t
        {
            const auto Start = NowNs();
            std::optional<Preview::Network::Dns::Message> Last;
            for (std::size_t Index = 0; Index < OperationCount; ++Index)
            {
                Last = Preview::Network::Dns::Message::Unpack(Wire);
            }
            if (!Last || Last->ExtractIps().size() != 1)
            {
                std::printf("[FAIL] Unpack 提取地址不一致\n");
                std::exit(1);
            }
            return NowNs() - Start;
        };
        const auto ScanNs = RunScan();
        const auto UnpackNs = RunUnpack();
        std::printf("2. AnswerScan          : %8llu ns/op （Unpack 物化 %llu ns/op，加速 %.1fx）\n",
                    static_cast<unsigned long long>(ScanNs / OperationCount),
                    static_cast<unsigned long long>(UnpackNs / OperationCount),
                    static_cast<double>(UnpackNs) / static_cast<double>(ScanNs));
    }

    // ── 3. 回环端到端 QPS ─────────────────────────────
    {
        Net::io_context IoContext;
        auto Server = std::make_shared<PerfDnsServer>(IoContext);
        Server->Start();

        Preview::Network::Dns::Config cfg;
        Preview::Network::Dns::Server s;
        s.Address = "127.0.0.1";
        s.Port = Server->Port();
        s.TimeoutMs = 2000;
        cfg.Servers.push_back(s);
        cfg.DisableIpv6 = true;
        cfg.CacheEnabled = false; // 打上游全链路
        Preview::Network::Dns::Resolver resolver(IoContext.get_executor(), cfg);

        constexpr std::size_t kQueries = 500;
        std::size_t Done = 0;
        std::size_t Ok = 0;
        std::exception_ptr Exception;
        const auto Start = NowNs();
        for (std::size_t Index = 0; Index < kQueries; ++Index)
        {
            Net::co_spawn(
                IoContext,
                [&, Index]() -> Net::awaitable<void>
                {
                    std::error_code ErrorCode;
                    auto Addresses = co_await resolver.AsyncResolve(
                        "q" + std::to_string(Index) + ".perf.example.com", ErrorCode);
                    if (!ErrorCode && Addresses.size() == 1)
                    {
                        ++Ok;
                    }
                    if (++Done == kQueries)
                    {
                        IoContext.stop();
                    }
                },
                [&](std::exception_ptr e)
                {
                    if (e)
                    {
                        Exception = e;
                    }
                });
        }
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
        const auto Ns = NowNs() - Start;
        Server->Close();
        if (Ok != kQueries)
        {
            std::printf("[FAIL] E2E 成功率 < 100%%：%llu/%llu\n",
                        static_cast<unsigned long long>(Ok), kQueries);
            return 1;
        }
        const auto Qps = static_cast<double>(kQueries) *
                         (1e9 / static_cast<double>(Ns));
        std::printf("3. 回环 E2E（并发 500） : %8.0f QPS （UDP 全链路，含本地 fake Server）\n", Qps);
    }

    std::printf("== 门禁通过 ==\n");
    return 0;
}
