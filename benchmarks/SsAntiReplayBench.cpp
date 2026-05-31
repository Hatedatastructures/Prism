/**
 * @file SsAntiReplayBench.cpp
 * @brief Shadowsocks 抗重放与会话管理基准测试
 * @details 测量 SS2022 UDP 抗重放组件性能：
 *          replay_window WireGuard 风格滑动窗口检查、
 *          salt_pool SIP022 salt 去重与 TTL 清理、
 *          session_tracker UDP 会话查找与创建。
 *          这些操作在每次 SS2022 UDP 包处理时被调用。
 */

#include <benchmark/benchmark.h>
#include <prism/protocol/shadowsocks/util/replay.hpp>
#include <prism/protocol/shadowsocks/util/salts.hpp>
#include <prism/protocol/shadowsocks/util/tracker.hpp>
#include <prism/memory/container.hpp>

#include <array>
#include <cstdint>
#include <random>
#include <thread>

namespace
{

namespace ss = psm::protocol::shadowsocks;
namespace net = boost::asio;

// ============================================================
// 测试辅助
// ============================================================

/// 生成 32 字节随机 salt
auto make_salt(std::uint64_t seed) -> std::array<std::uint8_t, 32>
{
    std::mt19937_64 rng(seed);
    std::array<std::uint8_t, 32> salt{};
    for (std::size_t i = 0; i < 32; ++i)
    {
        salt[i] = static_cast<std::uint8_t>(rng());
    }
    return salt;
}

/// 生成 8 字节 session_id
auto make_session_id(std::uint64_t seed) -> std::array<std::uint8_t, ss::session_id_len>
{
    std::mt19937_64 rng(seed);
    std::array<std::uint8_t, ss::session_id_len> id{};
    for (std::size_t i = 0; i < ss::session_id_len; ++i)
    {
        id[i] = static_cast<std::uint8_t>(rng());
    }
    return id;
}

/// 测试用 PSK（32 字节，chacha20-poly1305 密钥长度）
auto make_psk() -> psm::memory::vector<std::uint8_t>
{
    psm::memory::vector<std::uint8_t> psk(32, 0xAB);
    return psk;
}

const auto test_psk = make_psk();

/// 测试用客户端端点
const auto test_endpoint = net::ip::udp::endpoint(
    net::ip::make_address("127.0.0.1"), 12345);

// ============================================================
// replay_window 基准测试
// ============================================================

/// @brief 测量 WireGuard 风格滑动窗口单次重放检查性能
void BM_SsAntiReplay_WindowCheck(benchmark::State &state)
{
    ss::replay_window window;
    std::uint64_t packet_id = 1000;

    for (auto _ : state)
    {
        auto ok = window.check_and_update(packet_id++);
        benchmark::DoNotOptimize(ok);
    }
}
BENCHMARK(BM_SsAntiReplay_WindowCheck);

/// @brief 测量连续递增 packet_id 批量重放检查性能
void BM_SsAntiReplay_WindowSeq(benchmark::State &state)
{
    ss::replay_window window;
    std::uint64_t base = 1000;

    for (auto _ : state)
    {
        for (std::uint64_t i = 0; i < 64; ++i)
        {
            auto ok = window.check_and_update(base + i);
            benchmark::DoNotOptimize(ok);
        }
        base += 64;
    }
}
BENCHMARK(BM_SsAntiReplay_WindowSeq);

/// @brief 测量随机 packet_id 重放检查性能
void BM_SsAntiReplay_WindowRand(benchmark::State &state)
{
    ss::replay_window window;
    std::mt19937_64 rng(42);
    // 预生成随机 packet_id 序列（范围 1000~2000）
    psm::memory::vector<std::uint64_t> ids(256);
    for (auto &id : ids)
    {
        id = 1000 + (rng() % 1000);
    }

    std::size_t idx = 0;
    for (auto _ : state)
    {
        auto ok = window.check_and_update(ids[idx % ids.size()]);
        benchmark::DoNotOptimize(ok);
        ++idx;
    }
}
BENCHMARK(BM_SsAntiReplay_WindowRand);

// ============================================================
// salt_pool 基准测试
// ============================================================

/// @brief 测量 SIP022 salt 池单次检查与插入性能
void BM_SsAntiReplay_SaltCheck(benchmark::State &state)
{
    ss::salt_pool pool;
    std::uint64_t seed = 0;

    for (auto _ : state)
    {
        auto salt = make_salt(seed++);
        auto ok = pool.check_and_insert(salt);
        benchmark::DoNotOptimize(ok);
    }
}
BENCHMARK(BM_SsAntiReplay_SaltCheck);

/// @brief 测量 SIP022 salt 池过期清理性能
void BM_SsAntiReplay_SaltCleanup(benchmark::State &state)
{
    ss::salt_pool pool(1); // 1 秒 TTL，确保快速过期

    // 预填充 1000 个 salt
    for (std::uint64_t i = 0; i < 1000; ++i)
    {
        auto salt = make_salt(i);
        pool.check_and_insert(salt);
    }

    // 等待 TTL 过期
    std::this_thread::sleep_for(std::chrono::seconds(2));

    for (auto _ : state)
    {
        pool.cleanup();
        benchmark::DoNotOptimize(pool);
    }
}
BENCHMARK(BM_SsAntiReplay_SaltCleanup);

/// @brief 测量重复 salt 检测性能
void BM_SsAntiReplay_SaltDuplicate(benchmark::State &state)
{
    ss::salt_pool pool;
    const auto salt = make_salt(9999);

    // 先插入一次
    pool.check_and_insert(salt);

    for (auto _ : state)
    {
        auto ok = pool.check_and_insert(salt);
        benchmark::DoNotOptimize(ok);
    }
}
BENCHMARK(BM_SsAntiReplay_SaltDuplicate);

// ============================================================
// session_tracker 基准测试
// ============================================================

/// @brief 测量 UDP 会话创建性能
void BM_SsAntiReplay_SessionGetOrCreate(benchmark::State &state)
{
    ss::session_tracker tracker;
    std::uint64_t seed = 0;

    for (auto _ : state)
    {
        auto sid = make_session_id(seed++);
        ss::session_create_opts opts{
            sid, test_endpoint, test_psk,
            ss::cipher_method::chacha20_poly1305};
        auto session = tracker.get_or_create(opts);
        benchmark::DoNotOptimize(session);
    }
}
BENCHMARK(BM_SsAntiReplay_SessionGetOrCreate);

/// @brief 测量 UDP 会话查找性能
void BM_SsAntiReplay_SessionFind(benchmark::State &state)
{
    ss::session_tracker tracker;

    // 预创建会话
    const auto sid = make_session_id(12345);
    ss::session_create_opts opts{
        sid, test_endpoint, test_psk,
        ss::cipher_method::chacha20_poly1305};
    tracker.get_or_create(opts);

    for (auto _ : state)
    {
        auto session = tracker.find(sid);
        benchmark::DoNotOptimize(session);
    }
}
BENCHMARK(BM_SsAntiReplay_SessionFind);

/// @brief 测量已有会话的 get_or_create 性能
void BM_SsAntiReplay_SessionExisting(benchmark::State &state)
{
    ss::session_tracker tracker;

    // 预创建会话
    const auto sid = make_session_id(54321);
    ss::session_create_opts create_opts{
        sid, test_endpoint, test_psk,
        ss::cipher_method::chacha20_poly1305};
    tracker.get_or_create(create_opts);

    for (auto _ : state)
    {
        ss::session_create_opts lookup_opts{
            sid, test_endpoint, test_psk,
            ss::cipher_method::chacha20_poly1305};
        auto session = tracker.get_or_create(lookup_opts);
        benchmark::DoNotOptimize(session);
    }
}
BENCHMARK(BM_SsAntiReplay_SessionExisting);

// ============================================================
// 批量压力基准测试
// ============================================================

/// @brief 测量 10K packet_id 批量重放检查吞吐量
void BM_SsAntiReplay_WindowStress(benchmark::State &state)
{
    // 循环外准备数据
    psm::memory::vector<std::uint64_t> ids;
    ids.reserve(10000);
    for (std::uint64_t i = 0; i < 10000; ++i)
    {
        ids.push_back(1000 + i);
    }

    for (auto _ : state)
    {
        state.PauseTiming();
        ss::replay_window window;
        state.ResumeTiming();

        for (auto id : ids)
        {
            auto ok = window.check_and_update(id);
            benchmark::DoNotOptimize(ok);
        }
    }
}
BENCHMARK(BM_SsAntiReplay_WindowStress);

/// @brief 测量 1K salt 批量插入吞吐量
void BM_SsAntiReplay_SaltBatch(benchmark::State &state)
{
    // 循环外准备 1K 不同 salt
    psm::memory::vector<std::array<std::uint8_t, 32>> salts;
    salts.reserve(1000);
    for (std::uint64_t i = 0; i < 1000; ++i)
    {
        salts.push_back(make_salt(i));
    }

    for (auto _ : state)
    {
        state.PauseTiming();
        ss::salt_pool pool;
        state.ResumeTiming();

        for (const auto &salt : salts)
        {
            auto ok = pool.check_and_insert(salt);
            benchmark::DoNotOptimize(ok);
        }
    }
}
BENCHMARK(BM_SsAntiReplay_SaltBatch);

} // namespace

BENCHMARK_MAIN();
