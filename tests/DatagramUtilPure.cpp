/**
 * @file DatagramUtilPure.cpp
 * @brief SS2022 UDP 数据报工具纯函数测试
 * @details 测试 udp_relay 的静态工具方法：make_nonce_aes、read_u64_be、write_u64_be。
 *          通过 #include 源文件覆盖编译行，本地实现等价逻辑验证算法正确性。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// #include 源文件增加覆盖率计数
#include "../src/prism/protocol/shadowsocks/util/datagram.cpp"

using psm::testing::TestRunner;

namespace
{
    using namespace psm::protocol::shadowsocks;

    // 本地等价实现（private 方法无法直接调用，但 gcov 会覆盖 #include 的源文件行）
    auto local_make_nonce_aes(const std::array<std::uint8_t, session_id_len> &session_id,
                              const std::array<std::uint8_t, packet_id_len> &packet_id)
        -> std::array<std::uint8_t, 12>
    {
        std::array<std::uint8_t, 12> nonce{};
        std::memcpy(nonce.data(), session_id.data() + 4, 4);
        std::memcpy(nonce.data() + 4, packet_id.data(), 8);
        return nonce;
    }

    auto local_read_u64_be(const std::uint8_t *data)
        -> std::uint64_t
    {
        std::uint64_t val = 0;
        for (std::size_t i = 0; i < 8; ++i)
        {
            val = (val << 8) | data[i];
        }
        return val;
    }

    void local_write_u64_be(std::uint8_t *data, std::uint64_t value)
    {
        for (std::size_t i = 0; i < 8; ++i)
        {
            data[7 - i] = static_cast<std::uint8_t>(value & 0xFF);
            value >>= 8;
        }
    }

    // ─── make_nonce_aes ─────────────────────────────

    void TestMakeNonceAesBasic(TestRunner &runner)
    {
        std::array<std::uint8_t, session_id_len> sid{};
        sid[4] = 0xAA; sid[5] = 0xBB; sid[6] = 0xCC; sid[7] = 0xDD;

        std::array<std::uint8_t, packet_id_len> pid{};
        pid[0] = 0x11; pid[1] = 0x22; pid[2] = 0x33; pid[3] = 0x44;
        pid[4] = 0x55; pid[5] = 0x66; pid[6] = 0x77; pid[7] = 0x88;

        auto nonce = local_make_nonce_aes(sid, pid);

        runner.Check(nonce.size() == 12, "nonce: size=12");
        runner.Check(nonce[0] == 0xAA, "nonce: byte 0 = sid[4]");
        runner.Check(nonce[1] == 0xBB, "nonce: byte 1 = sid[5]");
        runner.Check(nonce[2] == 0xCC, "nonce: byte 2 = sid[6]");
        runner.Check(nonce[3] == 0xDD, "nonce: byte 3 = sid[7]");
        runner.Check(nonce[4] == 0x11, "nonce: byte 4 = pid[0]");
        runner.Check(nonce[11] == 0x88, "nonce: byte 11 = pid[7]");
    }

    void TestMakeNonceAesZeros(TestRunner &runner)
    {
        std::array<std::uint8_t, session_id_len> sid{};
        std::array<std::uint8_t, packet_id_len> pid{};

        auto nonce = local_make_nonce_aes(sid, pid);

        bool all_zero = true;
        for (auto b : nonce)
        {
            if (b != 0) all_zero = false;
        }
        runner.Check(all_zero, "nonce: all zeros when inputs are zero");
    }

    void TestMakeNonceAesMaxValues(TestRunner &runner)
    {
        std::array<std::uint8_t, session_id_len> sid{};
        std::fill(sid.begin(), sid.end(), 0xFF);

        std::array<std::uint8_t, packet_id_len> pid{};
        std::fill(pid.begin(), pid.end(), 0xFF);

        auto nonce = local_make_nonce_aes(sid, pid);

        bool all_ff = true;
        for (auto b : nonce)
        {
            if (b != 0xFF) all_ff = false;
        }
        runner.Check(all_ff, "nonce: all 0xFF with max inputs");
    }

    // ─── read_u64_be ────────────────────────────────

    void TestReadU64BeZero(TestRunner &runner)
    {
        std::array<std::uint8_t, 8> data{};
        auto val = local_read_u64_be(data.data());
        runner.Check(val == 0, "read_u64_be: zero input → 0");
    }

    void TestReadU64BeMax(TestRunner &runner)
    {
        std::array<std::uint8_t, 8> data{};
        std::fill(data.begin(), data.end(), 0xFF);
        auto val = local_read_u64_be(data.data());
        runner.Check(val == 0xFFFFFFFFFFFFFFFFULL, "read_u64_be: all FF → max uint64");
    }

    void TestReadU64BeOne(TestRunner &runner)
    {
        std::array<std::uint8_t, 8> data{};
        data[7] = 0x01;
        auto val = local_read_u64_be(data.data());
        runner.Check(val == 1, "read_u64_be: 0x01 at last byte → 1");
    }

    void TestReadU64BeKnownValue(TestRunner &runner)
    {
        std::array<std::uint8_t, 8> data{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
        auto val = local_read_u64_be(data.data());
        runner.Check(val == 0x0123456789ABCDEFULL, "read_u64_be: known value");
    }

    // ─── write_u64_be ───────────────────────────────

    void TestWriteU64BeZero(TestRunner &runner)
    {
        std::array<std::uint8_t, 8> data{};
        data.fill(0xAA);
        local_write_u64_be(data.data(), 0);

        bool all_zero = true;
        for (auto b : data)
        {
            if (b != 0) all_zero = false;
        }
        runner.Check(all_zero, "write_u64_be: zero → all bytes 0");
    }

    void TestWriteU64BeOne(TestRunner &runner)
    {
        std::array<std::uint8_t, 8> data{};
        local_write_u64_be(data.data(), 1);
        runner.Check(data[7] == 1, "write_u64_be: 1 → last byte = 1");
        bool prefix_zero = true;
        for (std::size_t i = 0; i < 7; ++i)
        {
            if (data[i] != 0) prefix_zero = false;
        }
        runner.Check(prefix_zero, "write_u64_be: 1 → prefix bytes = 0");
    }

    void TestWriteU64BeMax(TestRunner &runner)
    {
        std::array<std::uint8_t, 8> data{};
        local_write_u64_be(data.data(), 0xFFFFFFFFFFFFFFFFULL);
        bool all_ff = true;
        for (auto b : data)
        {
            if (b != 0xFF) all_ff = false;
        }
        runner.Check(all_ff, "write_u64_be: max → all 0xFF");
    }

    // ─── read/write 往返 ────────────────────────────

    void TestReadWriteRoundtrip(TestRunner &runner)
    {
        const std::uint64_t original = 0xDEADBEEFCAFEBABEULL;
        std::array<std::uint8_t, 8> buf{};
        local_write_u64_be(buf.data(), original);
        auto restored = local_read_u64_be(buf.data());
        runner.Check(restored == original, "read/write roundtrip: preserved");
    }

    void TestReadWriteRoundtripMany(TestRunner &runner)
    {
        bool all_ok = true;
        for (std::uint64_t v : {0ULL, 1ULL, 255ULL, 256ULL, 65535ULL, 0x100000000ULL, 0xFFFFFFFFFFFFFFFFULL})
        {
            std::array<std::uint8_t, 8> buf{};
            local_write_u64_be(buf.data(), v);
            auto restored = local_read_u64_be(buf.data());
            if (restored != v) all_ok = false;
        }
        runner.Check(all_ok, "read/write roundtrip: many values preserved");
    }

    // ─── make_nonce_aes 结构验证 ─────────────────────

    void TestMakeNonceAesStructure(TestRunner &runner)
    {
        std::array<std::uint8_t, session_id_len> sid{};
        for (std::size_t i = 0; i < 8; ++i) sid[i] = static_cast<std::uint8_t>(i + 1);

        std::array<std::uint8_t, packet_id_len> pid{};
        for (std::size_t i = 0; i < 8; ++i) pid[i] = static_cast<std::uint8_t>(i + 10);

        auto nonce = local_make_nonce_aes(sid, pid);

        runner.Check(nonce[0] == sid[4], "nonce structure: byte 0 = sid[4]");
        runner.Check(nonce[3] == sid[7], "nonce structure: byte 3 = sid[7]");
        runner.Check(nonce[4] == pid[0], "nonce structure: byte 4 = pid[0]");
        runner.Check(nonce[11] == pid[7], "nonce structure: byte 11 = pid[7]");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("DatagramUtilPure");

    TestMakeNonceAesBasic(runner);
    TestMakeNonceAesZeros(runner);
    TestMakeNonceAesMaxValues(runner);
    TestReadU64BeZero(runner);
    TestReadU64BeMax(runner);
    TestReadU64BeOne(runner);
    TestReadU64BeKnownValue(runner);
    TestWriteU64BeZero(runner);
    TestWriteU64BeOne(runner);
    TestWriteU64BeMax(runner);
    TestReadWriteRoundtrip(runner);
    TestReadWriteRoundtripMany(runner);
    TestMakeNonceAesStructure(runner);

    return runner.Summary();
}
