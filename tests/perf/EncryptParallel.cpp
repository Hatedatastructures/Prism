// @file EncryptParallel.cpp
// @brief 加密并行性测试：N 线程并行 AES-128-GCM seal，验证 BoringSSL 是否可并行
// 用法：EncryptParallel [threads] [per_thread_mb]（默认 4 线程、每线程 2048MB）
#include <prism/crypto/aead.hpp>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <thread>
#include <vector>

namespace
{
    void worker(const std::size_t mb)
    {
        std::vector<std::uint8_t> key(16, 0xAB);
        psm::crypto::aead_context ctx(psm::crypto::aead_cipher::aes_128_gcm, key);
        std::vector<std::uint8_t> plain(65536, 0xCD);
        std::vector<std::uint8_t> enc(65536 + 16);
        const auto rounds = mb * 1024 * 1024 / plain.size();
        for (std::size_t i = 0; i < rounds; ++i)
        {
            ctx.seal(enc, plain);
        }
    }
} // namespace

auto main(int argc, char **argv) -> int
{
    const auto threads = argc > 1 ? std::stoi(argv[1]) : 4;
    const auto mb = argc > 2 ? std::stoi(argv[2]) : 2048;

    const auto start = std::chrono::steady_clock::now();
    std::vector<std::thread> pool;
    pool.reserve(threads);
    for (int i = 0; i < threads; ++i)
        pool.emplace_back([mb] { worker(mb); });
    for (auto &t : pool)
        t.join();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - start)
                        .count();

    const auto total_mb = static_cast<double>(threads) * mb;
    std::printf("%d threads: %.0f MB in %lld ms = %.0f MB/s\n",
                threads, total_mb, ms, total_mb * 1000.0 / ms);
    return 0;
}
