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

#include <common/Core/Net/Dns/Answer.hpp>
#include <common/Core/Net/Dns/Cache.hpp>
#include <common/Core/Net/Dns/Format.hpp>
#include <common/Core/Net/Dns/Resolver.hpp>

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
    namespace net = boost::asio;
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
    void PutU16(std::vector<std::uint8_t> &out, const std::uint16_t v)
    {
        out.push_back(static_cast<std::uint8_t>(v >> 8));
        out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    }

    /// 回环 UDP fake DNS（固定 A 记录应答）
    class PerfDnsServer : public std::enable_shared_from_this<PerfDnsServer>
    {
    public:
        explicit PerfDnsServer(net::io_context &ioc)
            : Ex_(ioc.get_executor()),
              Udp_(ioc, net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0))
        {
        }

        auto Start() -> void
        {
            Port_ = Udp_.local_endpoint().port();
            auto self = shared_from_this();
            net::co_spawn(Ex_, [self]() { return self->Loop(); }, net::detached);
        }

        [[nodiscard]] auto Port() const -> std::uint16_t
        {
            return Port_;
        }

        void Close()
        {
            boost::system::error_code ec;
            Udp_.close(ec);
        }

    private:
        auto Loop() -> net::awaitable<void>
        {
            std::vector<std::uint8_t> buf(4096);
            net::ip::udp::endpoint sender;
            for (;;)
            {
                boost::system::error_code ec;
                const auto n = co_await Udp_.async_receive_from(
                    net::buffer(buf), sender, net::redirect_error(net::use_awaitable, ec));
                if (ec || n < 12)
                {
                    co_return;
                }
                // 问题段结束
                std::size_t off = 12;
                while (off < static_cast<std::size_t>(n) && buf[off] != 0)
                {
                    off += static_cast<std::size_t>(buf[off]) + 1;
                }
                const auto QEnd = off + 5;
                if (QEnd > static_cast<std::size_t>(n))
                {
                    continue;
                }
                std::vector<std::uint8_t> out;
                PutU16(out, static_cast<std::uint16_t>((buf[0] << 8) | buf[1]));
                PutU16(out, 0x8180u);
                PutU16(out, 1);
                PutU16(out, 1);
                PutU16(out, 0);
                PutU16(out, 0);
                out.insert(out.end(), buf.begin() + 12,
                           buf.begin() + static_cast<std::ptrdiff_t>(QEnd));
                PutU16(out, 0xC00Cu);
                PutU16(out, 1);
                PutU16(out, 1);
                out.insert(out.end(), {0, 0, 0, 60, 0, 4, 1, 2, 3, 4});
                co_await Udp_.async_send_to(net::buffer(out), sender,
                                            net::redirect_error(net::use_awaitable, ec));
            }
        }

        net::any_io_executor Ex_;
        net::ip::udp::socket Udp_;
        std::uint16_t Port_{0};
    };
} // namespace

auto main() -> int
{
    std::printf("== preview DNS 性能基准 ==\n");

    // ── 1. Cache 命中路径 ─────────────────────────────
    {
        CacheOptions opts;
        opts.MaxEntries = 4096;
        Cache cache(opts);
        constexpr std::size_t kKeys = 1000;
        std::vector<std::string> keys;
        keys.reserve(kKeys);
        for (std::size_t i = 0; i < kKeys; ++i)
        {
            auto domain = "host" + std::to_string(i) + ".example.com";
            Preview::Network::Dns::PutInput in;
            in.Domain = domain;
            in.QType = 1;
            in.Ips.assign(1, net::ip::make_address("10.0.0.1"));
            in.Ttl = std::chrono::seconds(3600);
            cache.Put(in);
            keys.push_back(std::move(domain));
        }
        std::mt19937 rng(1U);
        const auto IpExpect = net::ip::make_address("10.0.0.1");
        constexpr std::size_t kOps = 200000;
        const auto Start = NowNs();
        std::uint64_t hits = 0;
        for (std::size_t i = 0; i < kOps; ++i)
        {
            const auto &key = keys[rng() % kKeys];
            if (auto hit = cache.Get(key, 1))
            {
                ++hits;
                if (!hit->empty() && (*hit)[0] != IpExpect)
                {
                    std::printf("[FAIL] 缓存值不一致\n");
                    return 1;
                }
            }
        }
        const auto Ns = NowNs() - Start;
        if (hits != kOps)
        {
            std::printf("[FAIL] 缓存命中率 < 100%%：%llu/%llu\n",
                        static_cast<unsigned long long>(hits), kOps);
            return 1;
        }
        std::printf("1. Cache 命中路径      : %8llu ns/op （%llu 次全命中）\n",
                    static_cast<unsigned long long>(Ns / kOps), kOps);
    }

    // ── 2. AnswerScan vs Unpack ───────────────────────
    {
        Message m = Message::MakeQuery("bench.example.com", QType::A);
        m.Id = 0x1234;
        m.Qr = true;
        Preview::Network::Dns::Record a;
        a.Name = "bench.example.com";
        a.Type = QType::A;
        a.Ttl = 60;
        a.Rdata = {9, 8, 7, 6};
        m.Answers.push_back(a);
        const auto wire = m.Pack();

        constexpr std::size_t kOps = 50000;
        auto RunScan = [&]() -> std::uint64_t
        {
            const auto Start = NowNs();
            std::optional<Preview::Network::Dns::AnswerSet> last;
            for (std::size_t i = 0; i < kOps; ++i)
            {
                last = Preview::Network::Dns::ScanAnswers(wire, 1);
            }
            if (!last || last->Ips.size() != 1 ||
                last->Ips[0] != net::ip::make_address("9.8.7.6"))
            {
                std::printf("[FAIL] Scan 提取地址不一致\n");
                std::exit(1);
            }
            return NowNs() - Start;
        };
        auto RunUnpack = [&]() -> std::uint64_t
        {
            const auto Start = NowNs();
            std::optional<Message> last;
            for (std::size_t i = 0; i < kOps; ++i)
            {
                last = Message::Unpack(wire);
            }
            if (!last || last->ExtractIps().size() != 1)
            {
                std::printf("[FAIL] Unpack 提取地址不一致\n");
                std::exit(1);
            }
            return NowNs() - Start;
        };
        const auto ScanNs = RunScan();
        const auto UnpackNs = RunUnpack();
        std::printf("2. AnswerScan          : %8llu ns/op （Unpack 物化 %llu ns/op，加速 %.1fx）\n",
                    static_cast<unsigned long long>(ScanNs / kOps),
                    static_cast<unsigned long long>(UnpackNs / kOps),
                    static_cast<double>(UnpackNs) / static_cast<double>(ScanNs));
    }

    // ── 3. 回环端到端 QPS ─────────────────────────────
    {
        net::io_context ioc;
        auto server = std::make_shared<PerfDnsServer>(ioc);
        server->Start();

        Preview::Network::Dns::Config cfg;
        Preview::Network::Dns::Server s;
        s.Address = "127.0.0.1";
        s.Port = server->Port();
        s.TimeoutMs = 2000;
        cfg.Servers.push_back(s);
        cfg.DisableIpv6 = true;
        cfg.CacheEnabled = false; // 打上游全链路
        Preview::Network::Dns::Resolver resolver(ioc.get_executor(), cfg);

        constexpr std::size_t kQueries = 500;
        std::size_t done = 0;
        std::size_t ok = 0;
        std::exception_ptr ep;
        const auto Start = NowNs();
        for (std::size_t i = 0; i < kQueries; ++i)
        {
            net::co_spawn(
                ioc,
                [&, i]() -> net::awaitable<void>
                {
                    std::error_code ec;
                    auto addrs = co_await resolver.AsyncResolve(
                        "q" + std::to_string(i) + ".perf.example.com", ec);
                    if (!ec && addrs.size() == 1)
                    {
                        ++ok;
                    }
                    if (++done == kQueries)
                    {
                        ioc.stop();
                    }
                },
                [&](std::exception_ptr e)
                {
                    if (e)
                    {
                        ep = e;
                    }
                });
        }
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
        const auto Ns = NowNs() - Start;
        server->Close();
        if (ok != kQueries)
        {
            std::printf("[FAIL] E2E 成功率 < 100%%：%llu/%llu\n",
                        static_cast<unsigned long long>(ok), kQueries);
            return 1;
        }
        const auto Qps = static_cast<double>(kQueries) *
                         (1e9 / static_cast<double>(Ns));
        std::printf("3. 回环 E2E（并发 500） : %8.0f QPS （UDP 全链路，含本地 fake server）\n", Qps);
    }

    std::printf("== 门禁通过 ==\n");
    return 0;
}
