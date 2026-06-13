/**
 * @file ShadowsocksDatagramPure.cpp
 * @brief SS2022 UDP relay 纯函数测试
 * @details 测试 make_nonce_aes, read_u64_be, write_u64_be 字节操作逻辑
 *          和 parse_body_after_timestamp 错误路径。
 *          由于 udp_relay 的静态方法是 private 且 #define private public
 *          会破坏标准库头文件，这里直接在匿名命名空间中实现相同逻辑
 *          的独立函数进行测试，覆盖核心字节操作的正确性。
 */

#include <prism/core/core.hpp>
#include <prism/proto/protocol/shadowsocks/constants.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/core/core.hpp>


#include <gtest/gtest.h>

// #include 源文件获取 parse_body_after_timestamp（匿名命名空间 -> 内部链接）
#include "../../src/prism/proto/protocol/shadowsocks/util/datagram.cpp"

namespace
{
    using psm::protocol::shadowsocks::session_id_len;
    using psm::protocol::shadowsocks::packet_id_len;

    // 与 udp_relay::make_nonce_aes 相同逻辑的本地副本
    auto make_nonce_aes_local(
        const std::array<std::uint8_t, session_id_len> &sid,
        const std::array<std::uint8_t, packet_id_len> &pid)
        -> std::array<std::uint8_t, 12>
    {
        std::array<std::uint8_t, 12> nonce{};
        std::copy_n(sid.begin() + 4, 4, nonce.begin());
        std::copy_n(pid.begin(), 8, nonce.begin() + 4);
        return nonce;
    }

    auto read_u64_be_local(const std::uint8_t *data) -> std::uint64_t
    {
        std::uint64_t val = 0;
        for (int i = 0; i < 8; ++i)
            val = (val << 8) | data[i];
        return val;
    }

    void write_u64_be_local(std::uint8_t *data, std::uint64_t value)
    {
        for (int i = 7; i >= 0; --i)
        {
            data[i] = static_cast<std::uint8_t>(value & 0xFF);
            value >>= 8;
        }
    }

    // ─── make_nonce_aes ───────────────────────────

    TEST(ShadowsocksDatagramPure, MakeNonceAesBasic)
    {
        std::array<std::uint8_t, session_id_len> sid{};
        sid[4] = 0xAA; sid[5] = 0xBB; sid[6] = 0xCC; sid[7] = 0xDD;
        std::array<std::uint8_t, packet_id_len> pid{};
        pid[0] = 0x11; pid[1] = 0x22; pid[2] = 0x33; pid[3] = 0x44;
        pid[4] = 0x55; pid[5] = 0x66; pid[6] = 0x77; pid[7] = 0x88;

        auto nonce = make_nonce_aes_local(sid, pid);
        EXPECT_TRUE(nonce.size() == 12) << "make_nonce_aes: 12 bytes";
        EXPECT_TRUE(nonce[0] == 0xAA) << "make_nonce_aes: nonce[0]=sid[4]";
        EXPECT_TRUE(nonce[1] == 0xBB) << "make_nonce_aes: nonce[1]=sid[5]";
        EXPECT_TRUE(nonce[2] == 0xCC) << "make_nonce_aes: nonce[2]=sid[6]";
        EXPECT_TRUE(nonce[3] == 0xDD) << "make_nonce_aes: nonce[3]=sid[7]";
        EXPECT_TRUE(nonce[4] == 0x11) << "make_nonce_aes: nonce[4]=pid[0]";
        EXPECT_TRUE(nonce[11] == 0x88) << "make_nonce_aes: nonce[11]=pid[7]";
    }

    TEST(ShadowsocksDatagramPure, MakeNonceAesZero)
    {
        std::array<std::uint8_t, session_id_len> sid{};
        std::array<std::uint8_t, packet_id_len> pid{};
        auto nonce = make_nonce_aes_local(sid, pid);
        for (std::size_t i = 0; i < 12; ++i)
        {
            EXPECT_TRUE(nonce[i] == 0) << "make_nonce_aes: all zero";
        }
    }

    TEST(ShadowsocksDatagramPure, MakeNonceAesMax)
    {
        std::array<std::uint8_t, session_id_len> sid;
        sid.fill(0xFF);
        std::array<std::uint8_t, packet_id_len> pid;
        pid.fill(0xFF);
        auto nonce = make_nonce_aes_local(sid, pid);
        for (std::size_t i = 0; i < 12; ++i)
        {
            EXPECT_TRUE(nonce[i] == 0xFF) << "make_nonce_aes: all 0xFF";
        }
    }

    // ─── read_u64_be ──────────────────────────────

    TEST(ShadowsocksDatagramPure, ReadU64BeBasic)
    {
        std::uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        auto val = read_u64_be_local(data);
        EXPECT_TRUE(val == 0x0102030405060708ULL) << "read_u64_be: basic";
    }

    TEST(ShadowsocksDatagramPure, ReadU64BeZero)
    {
        std::uint8_t data[8]{};
        auto val = read_u64_be_local(data);
        EXPECT_TRUE(val == 0) << "read_u64_be: zero";
    }

    TEST(ShadowsocksDatagramPure, ReadU64BeMax)
    {
        std::uint8_t data[8];
        std::fill_n(data, 8, 0xFF);
        auto val = read_u64_be_local(data);
        EXPECT_TRUE(val == 0xFFFFFFFFFFFFFFFFULL) << "read_u64_be: max";
    }

    TEST(ShadowsocksDatagramPure, ReadU64BeSingleByte)
    {
        std::uint8_t data[8]{};
        data[7] = 0x42;
        auto val = read_u64_be_local(data);
        EXPECT_TRUE(val == 0x42) << "read_u64_be: single byte at LSB";
    }

    // ─── write_u64_be ─────────────────────────────

    TEST(ShadowsocksDatagramPure, WriteU64BeBasic)
    {
        std::uint8_t data[8]{};
        write_u64_be_local(data, 0x0102030405060708ULL);
        EXPECT_TRUE(data[0] == 0x01) << "write_u64_be: data[0]=0x01";
        EXPECT_TRUE(data[1] == 0x02) << "write_u64_be: data[1]=0x02";
        EXPECT_TRUE(data[7] == 0x08) << "write_u64_be: data[7]=0x08";
    }

    TEST(ShadowsocksDatagramPure, WriteU64BeZero)
    {
        std::uint8_t data[8];
        std::fill_n(data, 8, 0xAA);
        write_u64_be_local(data, 0);
        for (std::size_t i = 0; i < 8; ++i)
        {
            EXPECT_TRUE(data[i] == 0) << "write_u64_be: zero";
        }
    }

    TEST(ShadowsocksDatagramPure, WriteU64BeMax)
    {
        std::uint8_t data[8]{};
        write_u64_be_local(data, 0xFFFFFFFFFFFFFFFFULL);
        for (std::size_t i = 0; i < 8; ++i)
        {
            EXPECT_TRUE(data[i] == 0xFF) << "write_u64_be: max";
        }
    }

    TEST(ShadowsocksDatagramPure, WriteU64BeRoundTrip)
    {
        const std::uint64_t original = 0xDEADBEEFCAFEBABEULL;
        std::uint8_t data[8]{};
        write_u64_be_local(data, original);
        auto restored = read_u64_be_local(data);
        EXPECT_TRUE(restored == original) << "write+read_u64_be: round trip";
    }

    // ─── parse_body_after_timestamp 错误路径 ──────

    TEST(ShadowsocksDatagramPure, ParseBodyTooShort)
    {
        psm::memory::vector<std::uint8_t> short_body(5, 0x00, psm::memory::current_resource());
        psm::protocol::shadowsocks::udp_dec_pkt result;
        auto ec = psm::protocol::shadowsocks::parse_body_after_timestamp(short_body, result);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "parse_body: too short -> bad_message";
    }

    TEST(ShadowsocksDatagramPure, ParseBodyWrongType)
    {
        psm::memory::vector<std::uint8_t> body(11, 0x00, psm::memory::current_resource());
        body[0] = 0x01; // response_type instead of request_type (0x00)
        psm::protocol::shadowsocks::udp_dec_pkt result;
        auto ec = psm::protocol::shadowsocks::parse_body_after_timestamp(body, result);
        EXPECT_TRUE(ec == psm::fault::code::bad_message) << "parse_body: wrong type -> bad_message";
    }

} // namespace
