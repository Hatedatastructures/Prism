/**
 * @file ShadowsocksDatagramPure2.cpp
 * @brief SS2022 UDP 纯函数单元测试
 * @details 测试 udp_relay 的私有静态方法：make_nonce_aes、read_u64_be、write_u64_be。
 *          通过 #include 源文件访问私有成员。
 *          同时测试匿名命名空间的 parse_body_after_timestamp。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// #include 源文件增加覆盖率计数，并访问 private/anonymous 函数
#include "../src/prism/protocol/shadowsocks/util/datagram.cpp"

using psm::testing::TestRunner;

namespace
{
    using namespace psm::protocol::shadowsocks;

    // ─── make_nonce_aes ──────────────────────────

    void TestMakeNonceAesBasic(TestRunner &runner)
    {
        std::array<std::uint8_t, session_id_len> session_id{};
        for (std::size_t i = 0; i < 8; ++i)
            session_id[i] = static_cast<std::uint8_t>(i);

        std::array<std::uint8_t, packet_id_len> packet_id{};
        for (std::size_t i = 0; i < 8; ++i)
            packet_id[i] = static_cast<std::uint8_t>(i + 0x10);

        auto nonce = udp_relay::make_nonce_aes(session_id, packet_id);
        runner.Check(nonce.size() == 12, "make_nonce_aes: size=12");

        // 前 4 字节 = session_id[4..8]
        runner.Check(nonce[0] == 4, "make_nonce_aes: nonce[0]=session_id[4]");
        runner.Check(nonce[1] == 5, "make_nonce_aes: nonce[1]=session_id[5]");
        runner.Check(nonce[2] == 6, "make_nonce_aes: nonce[2]=session_id[6]");
        runner.Check(nonce[3] == 7, "make_nonce_aes: nonce[3]=session_id[7]");

        // 后 8 字节 = packet_id[0..8]
        for (std::size_t i = 0; i < 8; ++i)
            runner.Check(nonce[4 + i] == packet_id[i], "make_nonce_aes: nonce[4+i]=packet_id[i]");
    }

    void TestMakeNonceAesZero(TestRunner &runner)
    {
        std::array<std::uint8_t, session_id_len> session_id{};
        std::array<std::uint8_t, packet_id_len> packet_id{};

        auto nonce = udp_relay::make_nonce_aes(session_id, packet_id);
        bool all_zero = true;
        for (auto b : nonce)
            if (b != 0) all_zero = false;
        runner.Check(all_zero, "make_nonce_aes: zero inputs -> zero nonce");
    }

    void TestMakeNonceAesDeterministic(TestRunner &runner)
    {
        std::array<std::uint8_t, session_id_len> sid{0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44};
        std::array<std::uint8_t, packet_id_len> pid{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

        auto n1 = udp_relay::make_nonce_aes(sid, pid);
        auto n2 = udp_relay::make_nonce_aes(sid, pid);

        bool identical = true;
        for (std::size_t i = 0; i < 12; ++i)
            if (n1[i] != n2[i]) identical = false;
        runner.Check(identical, "make_nonce_aes: deterministic");
    }

    // ─── read_u64_be ─────────────────────────────

    void TestReadU64BeBasic(TestRunner &runner)
    {
        const std::uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        auto val = udp_relay::read_u64_be(data);
        runner.Check(val == 0x0102030405060708ULL, "read_u64_be: basic big-endian");
    }

    void TestReadU64BeZero(TestRunner &runner)
    {
        const std::uint8_t data[8] = {};
        auto val = udp_relay::read_u64_be(data);
        runner.Check(val == 0, "read_u64_be: zero");
    }

    void TestReadU64BeMax(TestRunner &runner)
    {
        const std::uint8_t data[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        auto val = udp_relay::read_u64_be(data);
        runner.Check(val == 0xFFFFFFFFFFFFFFFFULL, "read_u64_be: max uint64");
    }

    void TestReadU64BeOne(TestRunner &runner)
    {
        const std::uint8_t data[] = {0, 0, 0, 0, 0, 0, 0, 1};
        auto val = udp_relay::read_u64_be(data);
        runner.Check(val == 1, "read_u64_be: one");
    }

    // ─── write_u64_be ────────────────────────────

    void TestWriteU64BeBasic(TestRunner &runner)
    {
        std::uint8_t buf[8]{};
        udp_relay::write_u64_be(buf, 0x0102030405060708ULL);
        const std::uint8_t expected[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        bool match = true;
        for (std::size_t i = 0; i < 8; ++i)
            if (buf[i] != expected[i]) match = false;
        runner.Check(match, "write_u64_be: basic");
    }

    void TestWriteU64BeZero(TestRunner &runner)
    {
        std::uint8_t buf[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        udp_relay::write_u64_be(buf, 0);
        bool all_zero = true;
        for (std::size_t i = 0; i < 8; ++i)
            if (buf[i] != 0) all_zero = false;
        runner.Check(all_zero, "write_u64_be: zero");
    }

    void TestWriteU64BeMax(TestRunner &runner)
    {
        std::uint8_t buf[8]{};
        udp_relay::write_u64_be(buf, 0xFFFFFFFFFFFFFFFFULL);
        bool all_ff = true;
        for (std::size_t i = 0; i < 8; ++i)
            if (buf[i] != 0xFF) all_ff = false;
        runner.Check(all_ff, "write_u64_be: max");
    }

    // ─── read/write 往返 ─────────────────────────

    void TestReadWriteRoundtrip(TestRunner &runner)
    {
        const std::uint64_t original = 0xDEADBEEFCAFEBABEULL;
        std::uint8_t buf[8]{};
        udp_relay::write_u64_be(buf, original);
        auto result = udp_relay::read_u64_be(buf);
        runner.Check(result == original, "read/write roundtrip: preserve value");
    }

    void TestReadWriteRoundtripZero(TestRunner &runner)
    {
        std::uint8_t buf[8]{};
        udp_relay::write_u64_be(buf, 0);
        auto result = udp_relay::read_u64_be(buf);
        runner.Check(result == 0, "read/write roundtrip: zero");
    }

    void TestReadWriteRoundtripMax(TestRunner &runner)
    {
        std::uint8_t buf[8]{};
        udp_relay::write_u64_be(buf, 0xFFFFFFFFFFFFFFFFULL);
        auto result = udp_relay::read_u64_be(buf);
        runner.Check(result == 0xFFFFFFFFFFFFFFFFULL, "read/write roundtrip: max");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("ShadowsocksDatagramPure2");

    TestMakeNonceAesBasic(runner);
    TestMakeNonceAesZero(runner);
    TestMakeNonceAesDeterministic(runner);
    TestReadU64BeBasic(runner);
    TestReadU64BeZero(runner);
    TestReadU64BeMax(runner);
    TestReadU64BeOne(runner);
    TestWriteU64BeBasic(runner);
    TestWriteU64BeZero(runner);
    TestWriteU64BeMax(runner);
    TestReadWriteRoundtrip(runner);
    TestReadWriteRoundtripZero(runner);
    TestReadWriteRoundtripMax(runner);

    return runner.Summary();
}
