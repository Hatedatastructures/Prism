/**
 * @file SmuxFrameDeep.cpp
 * @brief multiplex/smux/frame 深度覆盖测试
 * @details 通过 #include 源文件访问 frame.cpp 全部实现，
 *          测试 deserialization、parse_address、parse_dgram、parse_prefixed、
 *          build_dgram、build_prefixed 的所有分支路径。
 *          所有函数均为纯同步，无 I/O、无协程。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/protocol/multiplex/smux/frame.hpp>

#include <gtest/gtest.h>

namespace
{
    // ─── 辅助函数 ──────────────────────────────

    /// 构造有效 smux 帧头字节序列
    static auto make_header(std::uint8_t version, psm::multiplex::smux::command cmd,
                            std::uint16_t length, std::uint32_t stream_id)
        -> std::vector<std::byte>
    {
        std::vector<std::byte> buf(8);
        buf[0] = static_cast<std::byte>(version);
        buf[1] = static_cast<std::byte>(cmd);
        buf[2] = static_cast<std::byte>(length & 0xFF);
        buf[3] = static_cast<std::byte>((length >> 8) & 0xFF);
        buf[4] = static_cast<std::byte>(stream_id & 0xFF);
        buf[5] = static_cast<std::byte>((stream_id >> 8) & 0xFF);
        buf[6] = static_cast<std::byte>((stream_id >> 16) & 0xFF);
        buf[7] = static_cast<std::byte>((stream_id >> 24) & 0xFF);
        return buf;
    }

    /// 构造 parse_address 输入：[Flags 2B BE][ATYP 1B][Addr][Port 2B BE]
    static auto make_address_ipv4(std::uint16_t flags,
                                  std::uint8_t a, std::uint8_t b,
                                  std::uint8_t c, std::uint8_t d,
                                  std::uint16_t port)
        -> std::vector<std::byte>
    {
        std::vector<std::byte> buf;
        buf.push_back(static_cast<std::byte>((flags >> 8) & 0xFF));
        buf.push_back(static_cast<std::byte>(flags & 0xFF));
        buf.push_back(std::byte{0x01}); // IPv4
        buf.push_back(static_cast<std::byte>(a));
        buf.push_back(static_cast<std::byte>(b));
        buf.push_back(static_cast<std::byte>(c));
        buf.push_back(static_cast<std::byte>(d));
        buf.push_back(static_cast<std::byte>((port >> 8) & 0xFF));
        buf.push_back(static_cast<std::byte>(port & 0xFF));
        return buf;
    }

    static auto make_address_domain(std::uint16_t flags,
                                    const std::string &domain,
                                    std::uint16_t port)
        -> std::vector<std::byte>
    {
        std::vector<std::byte> buf;
        buf.push_back(static_cast<std::byte>((flags >> 8) & 0xFF));
        buf.push_back(static_cast<std::byte>(flags & 0xFF));
        buf.push_back(std::byte{0x03}); // domain
        buf.push_back(static_cast<std::byte>(domain.size()));
        for (auto ch : domain)
            buf.push_back(static_cast<std::byte>(ch));
        buf.push_back(static_cast<std::byte>((port >> 8) & 0xFF));
        buf.push_back(static_cast<std::byte>(port & 0xFF));
        return buf;
    }

    static auto make_address_ipv6(std::uint16_t flags,
                                  const std::array<std::uint8_t, 16> &addr,
                                  std::uint16_t port)
        -> std::vector<std::byte>
    {
        std::vector<std::byte> buf;
        buf.push_back(static_cast<std::byte>((flags >> 8) & 0xFF));
        buf.push_back(static_cast<std::byte>(flags & 0xFF));
        buf.push_back(std::byte{0x04}); // IPv6
        for (auto b : addr)
            buf.push_back(static_cast<std::byte>(b));
        buf.push_back(static_cast<std::byte>((port >> 8) & 0xFF));
        buf.push_back(static_cast<std::byte>(port & 0xFF));
        return buf;
    }

    /// 构造 parse_dgram 输入：[ATYP 1B][Addr][Port 2B BE][Length 2B BE][Payload]
    static auto make_dgram_ipv4(std::uint8_t a, std::uint8_t b,
                                std::uint8_t c, std::uint8_t d,
                                std::uint16_t port,
                                const std::vector<std::byte> &payload)
        -> std::vector<std::byte>
    {
        std::vector<std::byte> buf;
        buf.push_back(std::byte{0x01}); // IPv4
        buf.push_back(static_cast<std::byte>(a));
        buf.push_back(static_cast<std::byte>(b));
        buf.push_back(static_cast<std::byte>(c));
        buf.push_back(static_cast<std::byte>(d));
        buf.push_back(static_cast<std::byte>((port >> 8) & 0xFF));
        buf.push_back(static_cast<std::byte>(port & 0xFF));
        buf.push_back(static_cast<std::byte>((payload.size() >> 8) & 0xFF));
        buf.push_back(static_cast<std::byte>(payload.size() & 0xFF));
        for (auto b : payload)
            buf.push_back(b);
        return buf;
    }

    static auto make_dgram_domain(const std::string &domain,
                                  std::uint16_t port,
                                  const std::vector<std::byte> &payload)
        -> std::vector<std::byte>
    {
        std::vector<std::byte> buf;
        buf.push_back(std::byte{0x03}); // domain
        buf.push_back(static_cast<std::byte>(domain.size()));
        for (auto ch : domain)
            buf.push_back(static_cast<std::byte>(ch));
        buf.push_back(static_cast<std::byte>((port >> 8) & 0xFF));
        buf.push_back(static_cast<std::byte>(port & 0xFF));
        buf.push_back(static_cast<std::byte>((payload.size() >> 8) & 0xFF));
        buf.push_back(static_cast<std::byte>(payload.size() & 0xFF));
        for (auto b : payload)
            buf.push_back(b);
        return buf;
    }

    static auto make_dgram_ipv6(const std::array<std::uint8_t, 16> &addr,
                                std::uint16_t port,
                                const std::vector<std::byte> &payload)
        -> std::vector<std::byte>
    {
        std::vector<std::byte> buf;
        buf.push_back(std::byte{0x04}); // IPv6
        for (auto b : addr)
            buf.push_back(static_cast<std::byte>(b));
        buf.push_back(static_cast<std::byte>((port >> 8) & 0xFF));
        buf.push_back(static_cast<std::byte>(port & 0xFF));
        buf.push_back(static_cast<std::byte>((payload.size() >> 8) & 0xFF));
        buf.push_back(static_cast<std::byte>(payload.size() & 0xFF));
        for (auto b : payload)
            buf.push_back(b);
        return buf;
    }

} // namespace

// ─── deserialization 测试 ──────────────────

TEST(SmuxFrameDeep, DeserValidSyn)
{
    auto buf = make_header(0x01, psm::multiplex::smux::command::syn, 100, 42);
    auto r = psm::multiplex::smux::deserialization(buf);
    ASSERT_TRUE(!!r) << "deser: valid syn -> has value";
    EXPECT_TRUE(r->version == 0x01) << "deser: version = 1";
    EXPECT_TRUE(r->cmd == psm::multiplex::smux::command::syn) << "deser: cmd = syn";
    EXPECT_TRUE(r->length == 100) << "deser: length = 100";
    EXPECT_TRUE(r->stream_id == 42) << "deser: stream_id = 42";
}

TEST(SmuxFrameDeep, DeserValidFin)
{
    auto buf = make_header(0x01, psm::multiplex::smux::command::fin, 0, 1);
    auto r = psm::multiplex::smux::deserialization(buf);
    ASSERT_TRUE(!!r) << "deser: valid fin -> has value";
    EXPECT_TRUE(r->cmd == psm::multiplex::smux::command::fin) << "deser: cmd = fin";
}

TEST(SmuxFrameDeep, DeserValidPush)
{
    auto buf = make_header(0x01, psm::multiplex::smux::command::push, 500, 7);
    auto r = psm::multiplex::smux::deserialization(buf);
    ASSERT_TRUE(!!r) << "deser: valid push -> has value";
    EXPECT_TRUE(r->cmd == psm::multiplex::smux::command::push) << "deser: cmd = push";
}

TEST(SmuxFrameDeep, DeserValidNop)
{
    auto buf = make_header(0x01, psm::multiplex::smux::command::nop, 0, 0);
    auto r = psm::multiplex::smux::deserialization(buf);
    ASSERT_TRUE(!!r) << "deser: valid nop -> has value";
    EXPECT_TRUE(r->cmd == psm::multiplex::smux::command::nop) << "deser: cmd = nop";
}

TEST(SmuxFrameDeep, DeserTooShort)
{
    std::vector<std::byte> buf(7, std::byte{0x01});
    auto r = psm::multiplex::smux::deserialization(buf);
    EXPECT_TRUE(!r) << "deser: 7 bytes -> nullopt";
}

TEST(SmuxFrameDeep, DeserEmpty)
{
    std::vector<std::byte> buf;
    auto r = psm::multiplex::smux::deserialization(buf);
    EXPECT_TRUE(!r) << "deser: empty -> nullopt";
}

TEST(SmuxFrameDeep, DeserBadVersion)
{
    auto buf = make_header(0x02, psm::multiplex::smux::command::syn, 0, 1);
    auto r = psm::multiplex::smux::deserialization(buf);
    EXPECT_TRUE(!r) << "deser: version 2 -> nullopt";
}

TEST(SmuxFrameDeep, DeserBadCommand)
{
    auto buf = make_header(0x01, static_cast<psm::multiplex::smux::command>(99), 0, 1);
    auto r = psm::multiplex::smux::deserialization(buf);
    EXPECT_TRUE(!r) << "deser: bad command -> nullopt";
}

TEST(SmuxFrameDeep, DeserLengthMaxUint16)
{
    auto buf = make_header(0x01, psm::multiplex::smux::command::push, 65535, 1);
    auto r = psm::multiplex::smux::deserialization(buf);
    ASSERT_TRUE(!!r) << "deser: max uint16 length -> ok";
    EXPECT_TRUE(r->length == 65535) << "deser: max uint16 length preserved";
}

TEST(SmuxFrameDeep, DeserMaxLength)
{
    auto buf = make_header(0x01, psm::multiplex::smux::command::push, 65535, 1);
    auto r = psm::multiplex::smux::deserialization(buf);
    ASSERT_TRUE(!!r) << "deser: length 65535 = max -> ok";
    EXPECT_TRUE(r->length == 65535) << "deser: max length preserved";
}

TEST(SmuxFrameDeep, DeserZeroLength)
{
    auto buf = make_header(0x01, psm::multiplex::smux::command::nop, 0, 0);
    auto r = psm::multiplex::smux::deserialization(buf);
    ASSERT_TRUE(!!r) << "deser: zero length -> ok";
    EXPECT_TRUE(r->length == 0) << "deser: length = 0";
}

TEST(SmuxFrameDeep, DeserLargeStreamId)
{
    auto buf = make_header(0x01, psm::multiplex::smux::command::push, 10, 0x01020304);
    auto r = psm::multiplex::smux::deserialization(buf);
    ASSERT_TRUE(!!r) << "deser: large stream_id -> ok";
    EXPECT_TRUE(r->stream_id == 0x01020304) << "deser: stream_id = 0x01020304";
}

TEST(SmuxFrameDeep, DeserExact8Bytes)
{
    auto buf = make_header(0x01, psm::multiplex::smux::command::syn, 0, 0);
    EXPECT_TRUE(buf.size() == 8) << "deser: exact 8 bytes";
    auto r = psm::multiplex::smux::deserialization(buf);
    EXPECT_TRUE(!!r) << "deser: exact size -> ok";
}

TEST(SmuxFrameDeep, DeserMoreThan8)
{
    auto buf = make_header(0x01, psm::multiplex::smux::command::syn, 0, 0);
    buf.push_back(std::byte{0xFF}); // extra byte
    auto r = psm::multiplex::smux::deserialization(buf);
    EXPECT_TRUE(!!r) << "deser: 9 bytes -> ok (only reads first 8)";
}

// ─── parse_address IPv4 测试 ───────────────

TEST(SmuxFrameDeep, ParseAddrIpv4Basic)
{
    auto buf = make_address_ipv4(0, 127, 0, 0, 1, 443);
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "addr: IPv4 127.0.0.1:443 -> ok";
    EXPECT_TRUE(r->host == "127.0.0.1") << "addr: host = 127.0.0.1";
    EXPECT_TRUE(r->port == 443) << "addr: port = 443";
    EXPECT_TRUE(!r->is_udp) << "addr: not UDP";
    EXPECT_TRUE(r->offset == 9) << "addr: offset = 9";
}

TEST(SmuxFrameDeep, ParseAddrIpv4ZeroPort)
{
    auto buf = make_address_ipv4(0, 10, 0, 0, 1, 0);
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "addr: IPv4 port 0 -> ok";
    EXPECT_TRUE(r->port == 0) << "addr: port = 0";
}

TEST(SmuxFrameDeep, ParseAddrIpv4LargeOctets)
{
    auto buf = make_address_ipv4(0, 255, 255, 255, 255, 65535);
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "addr: 255.255.255.255:65535 -> ok";
    EXPECT_TRUE(r->host == "255.255.255.255") << "addr: host = 255.255.255.255";
    EXPECT_TRUE(r->port == 65535) << "addr: port = 65535";
}

TEST(SmuxFrameDeep, ParseAddrIpv4SmallOctets)
{
    auto buf = make_address_ipv4(0, 0, 0, 0, 0, 80);
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "addr: 0.0.0.0:80 -> ok";
    EXPECT_TRUE(r->host == "0.0.0.0") << "addr: host = 0.0.0.0";
}

TEST(SmuxFrameDeep, ParseAddrIpv4SingleDigit)
{
    auto buf = make_address_ipv4(0, 1, 2, 3, 4, 80);
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "addr: 1.2.3.4:80 -> ok";
    EXPECT_TRUE(r->host == "1.2.3.4") << "addr: host = 1.2.3.4";
}

TEST(SmuxFrameDeep, ParseAddrIpv4TwoDigit)
{
    auto buf = make_address_ipv4(0, 10, 20, 30, 40, 80);
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "addr: 10.20.30.40:80 -> ok";
    EXPECT_TRUE(r->host == "10.20.30.40") << "addr: host ok";
}

// ─── parse_address domain 测试 ─────────────

TEST(SmuxFrameDeep, ParseAddrDomainBasic)
{
    auto buf = make_address_domain(0, "example.com", 443);
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "addr: domain example.com:443 -> ok";
    EXPECT_TRUE(r->host == "example.com") << "addr: host = example.com";
    EXPECT_TRUE(r->port == 443) << "addr: port = 443";
    EXPECT_TRUE(r->offset == 3 + 1 + 11 + 2) << "addr: offset = 17";
}

TEST(SmuxFrameDeep, ParseAddrDomainShort)
{
    auto buf = make_address_domain(0, "a", 80);
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "addr: domain 'a':80 -> ok";
    EXPECT_TRUE(r->host == "a") << "addr: host = a";
}

TEST(SmuxFrameDeep, ParseAddrDomainLong)
{
    std::string domain(100, 'x');
    auto buf = make_address_domain(0, domain, 8080);
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "addr: long domain -> ok";
    EXPECT_TRUE(r->host == domain.c_str()) << "addr: host preserved";
}

// ─── parse_address IPv6 测试 ───────────────

TEST(SmuxFrameDeep, ParseAddrIpv6Loopback)
{
    std::array<std::uint8_t, 16> addr{};
    addr[15] = 1; // ::1
    auto buf = make_address_ipv6(0, addr, 443);
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "addr: IPv6 ::1 -> ok";
    EXPECT_TRUE(r->port == 443) << "addr: port = 443";
}

TEST(SmuxFrameDeep, ParseAddrIpv6Full)
{
    std::array<std::uint8_t, 16> addr{};
    for (int i = 0; i < 16; ++i)
        addr[i] = static_cast<std::uint8_t>(i + 1);
    auto buf = make_address_ipv6(0, addr, 8080);
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "addr: IPv6 full addr -> ok";
    EXPECT_TRUE(r->port == 8080) << "addr: port = 8080";
    EXPECT_TRUE(r->offset == 3 + 16 + 2) << "addr: offset = 21";
}

// ─── parse_address flags 测试 ──────────────

TEST(SmuxFrameDeep, ParseAddrUdpFlag)
{
    auto buf = make_address_ipv4(0x0001, 127, 0, 0, 1, 443);
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "addr: UDP flag -> ok";
    EXPECT_TRUE(r->is_udp) << "addr: is_udp = true";
    EXPECT_TRUE(r->addr == psm::multiplex::addr_mode::length_prefixed) << "addr: mode = length_prefixed";
}

TEST(SmuxFrameDeep, ParseAddrPacketAddrFlag)
{
    auto buf = make_address_ipv4(0x0002, 127, 0, 0, 1, 443);
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "addr: packet_addr flag -> ok";
    EXPECT_TRUE(!r->is_udp) << "addr: not UDP";
    EXPECT_TRUE(r->addr == psm::multiplex::addr_mode::packet_addr) << "addr: mode = packet_addr";
}

TEST(SmuxFrameDeep, ParseAddrBothFlags)
{
    auto buf = make_address_ipv4(0x0003, 127, 0, 0, 1, 443);
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "addr: both flags -> ok";
    EXPECT_TRUE(r->is_udp) << "addr: is_udp = true";
    EXPECT_TRUE(r->addr == psm::multiplex::addr_mode::packet_addr) << "addr: mode = packet_addr";
}

// ─── parse_address 错误路径 ────────────────

TEST(SmuxFrameDeep, ParseAddrTooShort)
{
    std::vector<std::byte> buf(2, std::byte{0x00});
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "addr: 2 bytes -> nullopt";
}

TEST(SmuxFrameDeep, ParseAddrEmpty)
{
    std::vector<std::byte> buf;
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "addr: empty -> nullopt";
}

TEST(SmuxFrameDeep, ParseAddrIpv4Truncated)
{
    // flags(2) + atype(1) + only 3 bytes of IPv4 (need 4+2)
    std::vector<std::byte> buf = {
        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x7F}, std::byte{0x00}, std::byte{0x00}};
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "addr: IPv4 truncated -> nullopt";
}

TEST(SmuxFrameDeep, ParseAddrIpv4NoPort)
{
    // flags(2) + atype(1) + IPv4(4) but no port
    std::vector<std::byte> buf = {
        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x7F}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}};
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "addr: IPv4 no port -> nullopt";
}

TEST(SmuxFrameDeep, ParseAddrIpv4OneBytePort)
{
    // flags(2) + atype(1) + IPv4(4) + only 1 byte of port
    std::vector<std::byte> buf = {
        std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x7F}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x01}};
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "addr: IPv4 1-byte port -> nullopt";
}

TEST(SmuxFrameDeep, ParseAddrDomainTruncated)
{
    // flags(2) + atype(1) + domain_len(1) but not enough domain bytes
    std::vector<std::byte> buf = {
        std::byte{0x00}, std::byte{0x00}, std::byte{0x03},
        std::byte{0x05}, std::byte{'a'}, std::byte{'b'}};
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "addr: domain truncated -> nullopt";
}

TEST(SmuxFrameDeep, ParseAddrDomainNoPort)
{
    // flags(2) + atype(1) + domain_len(1) + domain(3) but no port
    std::vector<std::byte> buf = {
        std::byte{0x00}, std::byte{0x00}, std::byte{0x03},
        std::byte{0x03}, std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "addr: domain no port -> nullopt";
}

TEST(SmuxFrameDeep, ParseAddrIpv6Truncated)
{
    // flags(2) + atype(1) + only 10 bytes of IPv6 (need 16+2)
    std::vector<std::byte> buf(13, std::byte{0x00});
    buf[2] = std::byte{0x04}; // IPv6
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "addr: IPv6 truncated -> nullopt";
}

TEST(SmuxFrameDeep, ParseAddrUnknownAtype)
{
    std::vector<std::byte> buf = {
        std::byte{0x00}, std::byte{0x00}, std::byte{0x05},
        std::byte{0x01}, std::byte{0x02}};
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "addr: unknown atype 0x05 -> nullopt";
}

TEST(SmuxFrameDeep, ParseAddrDomainLenZero)
{
    auto buf = make_address_domain(0, "", 80);
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "addr: empty domain -> ok";
    EXPECT_TRUE(r->host.empty()) << "addr: host is empty";
    EXPECT_TRUE(r->port == 80) << "addr: port = 80";
}

// ─── parse_dgram IPv4 测试 ─────────────────

TEST(SmuxFrameDeep, ParseDgramIpv4Basic)
{
    auto payload = std::vector<std::byte>{std::byte{0xAA}, std::byte{0xBB}};
    auto buf = make_dgram_ipv4(127, 0, 0, 1, 443, payload);
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "dgram: IPv4 basic -> ok";
    EXPECT_TRUE(r->host == "127.0.0.1") << "dgram: host = 127.0.0.1";
    EXPECT_TRUE(r->port == 443) << "dgram: port = 443";
    EXPECT_TRUE(r->payload.size() == 2) << "dgram: payload size = 2";
    EXPECT_TRUE(r->consumed == 1 + 4 + 2 + 2 + 2) << "dgram: consumed = 11";
}

TEST(SmuxFrameDeep, ParseDgramIpv4EmptyPayload)
{
    auto payload = std::vector<std::byte>{};
    auto buf = make_dgram_ipv4(10, 0, 0, 1, 80, payload);
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "dgram: IPv4 empty payload -> ok";
    EXPECT_TRUE(r->payload.empty()) << "dgram: payload empty";
}

TEST(SmuxFrameDeep, ParseDgramIpv4LargePayload)
{
    auto payload = std::vector<std::byte>(1000, std::byte{0xFF});
    auto buf = make_dgram_ipv4(192, 168, 1, 1, 8080, payload);
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "dgram: IPv4 large payload -> ok";
    EXPECT_TRUE(r->payload.size() == 1000) << "dgram: payload size = 1000";
}

// ─── parse_dgram domain 测试 ───────────────

TEST(SmuxFrameDeep, ParseDgramDomainBasic)
{
    auto payload = std::vector<std::byte>{std::byte{0x01}};
    auto buf = make_dgram_domain("example.com", 443, payload);
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "dgram: domain basic -> ok";
    EXPECT_TRUE(r->host == "example.com") << "dgram: host = example.com";
    EXPECT_TRUE(r->port == 443) << "dgram: port = 443";
    EXPECT_TRUE(r->payload.size() == 1) << "dgram: payload size = 1";
}

TEST(SmuxFrameDeep, ParseDgramDomainEmptyPayload)
{
    auto payload = std::vector<std::byte>{};
    auto buf = make_dgram_domain("test.org", 80, payload);
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "dgram: domain empty payload -> ok";
    EXPECT_TRUE(r->payload.empty()) << "dgram: payload empty";
}

// ─── parse_dgram IPv6 测试 ─────────────────

TEST(SmuxFrameDeep, ParseDgramIpv6Basic)
{
    std::array<std::uint8_t, 16> addr{};
    addr[15] = 1; // ::1
    auto payload = std::vector<std::byte>{std::byte{0xCC}};
    auto buf = make_dgram_ipv6(addr, 443, payload);
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "dgram: IPv6 basic -> ok";
    EXPECT_TRUE(r->port == 443) << "dgram: port = 443";
    EXPECT_TRUE(r->payload.size() == 1) << "dgram: payload size = 1";
}

TEST(SmuxFrameDeep, ParseDgramIpv6EmptyPayload)
{
    std::array<std::uint8_t, 16> addr{};
    auto payload = std::vector<std::byte>{};
    auto buf = make_dgram_ipv6(addr, 80, payload);
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    EXPECT_TRUE(!!r) << "dgram: IPv6 empty payload -> ok";
}

// ─── parse_dgram 错误路径 ──────────────────

TEST(SmuxFrameDeep, ParseDgramEmpty)
{
    std::vector<std::byte> buf;
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "dgram: empty -> nullopt";
}

TEST(SmuxFrameDeep, ParseDgramUnknownAtype)
{
    std::vector<std::byte> buf = {std::byte{0x05}, std::byte{0x01}};
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "dgram: unknown atype -> nullopt";
}

TEST(SmuxFrameDeep, ParseDgramIpv4Truncated)
{
    // atype(1) + only 2 bytes (need 4+2)
    std::vector<std::byte> buf = {std::byte{0x01}, std::byte{0x7F}, std::byte{0x00}};
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "dgram: IPv4 truncated -> nullopt";
}

TEST(SmuxFrameDeep, ParseDgramIpv4NoPort)
{
    // atype(1) + IPv4(4) but no port
    std::vector<std::byte> buf = {
        std::byte{0x01}, std::byte{0x7F}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x01}};
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "dgram: IPv4 no port -> nullopt";
}

TEST(SmuxFrameDeep, ParseDgramIpv4NoLength)
{
    // atype(1) + IPv4(4) + port(2) but no length prefix
    std::vector<std::byte> buf = {
        std::byte{0x01}, std::byte{0x7F}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x01}, std::byte{0xBB}};
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "dgram: IPv4 no length -> nullopt";
}

TEST(SmuxFrameDeep, ParseDgramIpv4PayloadTruncated)
{
    // atype(1) + IPv4(4) + port(2) + length(2) saying 100 bytes but only 1
    std::vector<std::byte> buf = {
        std::byte{0x01}, std::byte{0x7F}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x01}, std::byte{0x01}, std::byte{0xBB},
        std::byte{0x00}, std::byte{0x64},
        std::byte{0xFF}};
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "dgram: IPv4 payload truncated -> nullopt";
}

TEST(SmuxFrameDeep, ParseDgramDomainTruncated)
{
    // atype(1) + domain_len(1) but not enough domain bytes
    std::vector<std::byte> buf = {std::byte{0x03}, std::byte{0x05}, std::byte{'a'}};
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "dgram: domain truncated -> nullopt";
}

TEST(SmuxFrameDeep, ParseDgramDomainNoPort)
{
    // atype(1) + domain_len(1) + domain(3) but no port
    std::vector<std::byte> buf = {
        std::byte{0x03}, std::byte{0x03},
        std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "dgram: domain no port -> nullopt";
}

TEST(SmuxFrameDeep, ParseDgramIpv6Truncated)
{
    // atype(1) + only 5 bytes of IPv6
    std::vector<std::byte> buf(6, std::byte{0x00});
    buf[0] = std::byte{0x04};
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "dgram: IPv6 truncated -> nullopt";
}

// ─── parse_prefixed 测试 ───────────────────

TEST(SmuxFrameDeep, ParsePrefixedBasic)
{
    std::vector<std::byte> buf = {
        std::byte{0x00}, std::byte{0x03}, // length = 3
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    auto r = psm::multiplex::smux::parse_prefixed(buf);
    ASSERT_TRUE(!!r) << "prefixed: basic -> ok";
    EXPECT_TRUE(r->payload.size() == 3) << "prefixed: payload size = 3";
    EXPECT_TRUE(r->consumed == 5) << "prefixed: consumed = 5";
}

TEST(SmuxFrameDeep, ParsePrefixedEmpty)
{
    std::vector<std::byte> buf = {std::byte{0x00}, std::byte{0x00}};
    auto r = psm::multiplex::smux::parse_prefixed(buf);
    ASSERT_TRUE(!!r) << "prefixed: zero length -> ok";
    EXPECT_TRUE(r->payload.empty()) << "prefixed: payload empty";
    EXPECT_TRUE(r->consumed == 2) << "prefixed: consumed = 2";
}

TEST(SmuxFrameDeep, ParsePrefixedTooShort1)
{
    std::vector<std::byte> buf = {std::byte{0x00}};
    auto r = psm::multiplex::smux::parse_prefixed(buf);
    EXPECT_TRUE(!r) << "prefixed: 1 byte -> nullopt";
}

TEST(SmuxFrameDeep, ParsePrefixedTooShort0)
{
    std::vector<std::byte> buf;
    auto r = psm::multiplex::smux::parse_prefixed(buf);
    EXPECT_TRUE(!r) << "prefixed: empty -> nullopt";
}

TEST(SmuxFrameDeep, ParsePrefixedPayloadTruncated)
{
    std::vector<std::byte> buf = {
        std::byte{0x00}, std::byte{0x0A}, // length = 10
        std::byte{0x01}, std::byte{0x02}}; // only 2
    auto r = psm::multiplex::smux::parse_prefixed(buf);
    EXPECT_TRUE(!r) << "prefixed: payload truncated -> nullopt";
}

TEST(SmuxFrameDeep, ParsePrefixedLargeLength)
{
    std::vector<std::byte> buf = {
        std::byte{0xFF}, std::byte{0xFF}}; // length = 65535
    auto r = psm::multiplex::smux::parse_prefixed(buf);
    EXPECT_TRUE(!r) << "prefixed: length 65535 but no payload -> nullopt";
}

TEST(SmuxFrameDeep, ParsePrefixedExactMatch)
{
    std::vector<std::byte> buf = {
        std::byte{0x00}, std::byte{0x02},
        std::byte{0xAA}, std::byte{0xBB}};
    auto r = psm::multiplex::smux::parse_prefixed(buf);
    ASSERT_TRUE(!!r) << "prefixed: exact match -> ok";
    EXPECT_TRUE(r->payload.size() == 2) << "prefixed: payload size = 2";
}

// ─── build_dgram IPv4 测试 ─────────────────

TEST(SmuxFrameDeep, BuildDgramIpv4Basic)
{
    const std::string_view host = "127.0.0.1";
    std::vector<std::byte> payload = {std::byte{0xAA}, std::byte{0xBB}};
    psm::multiplex::smux::datagram_params params{host, 443, payload};
    auto buf = psm::multiplex::smux::build_dgram(params, psm::memory::current_resource());
    EXPECT_TRUE(buf.size() == 1 + 4 + 2 + 2 + 2) << "build_dgram: IPv4 size = 9+2";
    EXPECT_TRUE(buf[0] == std::byte{0x01}) << "build_dgram: atype = IPv4";
}

TEST(SmuxFrameDeep, BuildDgramIpv4EmptyPayload)
{
    const std::string_view host = "10.0.0.1";
    std::vector<std::byte> payload;
    psm::multiplex::smux::datagram_params params{host, 80, payload};
    auto buf = psm::multiplex::smux::build_dgram(params, psm::memory::current_resource());
    EXPECT_TRUE(buf.size() == 1 + 4 + 2 + 2) << "build_dgram: IPv4 empty payload size = 9";
}

TEST(SmuxFrameDeep, BuildDgramIpv4Roundtrip)
{
    const std::string_view host = "192.168.1.100";
    std::vector<std::byte> payload = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    psm::multiplex::smux::datagram_params params{host, 8080, payload};
    auto buf = psm::multiplex::smux::build_dgram(params, psm::memory::current_resource());

    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "build_dgram: IPv4 roundtrip parse -> ok";
    EXPECT_TRUE(r->host == host) << "build_dgram: roundtrip host match";
    EXPECT_TRUE(r->port == 8080) << "build_dgram: roundtrip port match";
    EXPECT_TRUE(r->payload.size() == 3) << "build_dgram: roundtrip payload size";
}

// ─── build_dgram IPv6 测试 ─────────────────

TEST(SmuxFrameDeep, BuildDgramIpv6Basic)
{
    const std::string_view host = "::1";
    std::vector<std::byte> payload = {std::byte{0xCC}};
    psm::multiplex::smux::datagram_params params{host, 443, payload};
    auto buf = psm::multiplex::smux::build_dgram(params, psm::memory::current_resource());
    EXPECT_TRUE(buf[0] == std::byte{0x04}) << "build_dgram: atype = IPv6";
}

TEST(SmuxFrameDeep, BuildDgramIpv6Roundtrip)
{
    const std::string_view host = "fe80::1";
    std::vector<std::byte> payload(50, std::byte{0xFF});
    psm::multiplex::smux::datagram_params params{host, 9090, payload};
    auto buf = psm::multiplex::smux::build_dgram(params, psm::memory::current_resource());

    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "build_dgram: IPv6 roundtrip parse -> ok";
    EXPECT_TRUE(r->port == 9090) << "build_dgram: roundtrip port match";
    EXPECT_TRUE(r->payload.size() == 50) << "build_dgram: roundtrip payload size";
}

// ─── build_dgram domain 测试 ───────────────

TEST(SmuxFrameDeep, BuildDgramDomainBasic)
{
    const std::string_view host = "example.com";
    std::vector<std::byte> payload = {std::byte{0xDD}};
    psm::multiplex::smux::datagram_params params{host, 443, payload};
    auto buf = psm::multiplex::smux::build_dgram(params, psm::memory::current_resource());
    EXPECT_TRUE(buf[0] == std::byte{0x03}) << "build_dgram: atype = domain";
}

TEST(SmuxFrameDeep, BuildDgramDomainRoundtrip)
{
    const std::string_view host = "test.example.org";
    std::vector<std::byte> payload = {std::byte{0x01}, std::byte{0x02}};
    psm::multiplex::smux::datagram_params params{host, 8080, payload};
    auto buf = psm::multiplex::smux::build_dgram(params, psm::memory::current_resource());

    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "build_dgram: domain roundtrip parse -> ok";
    EXPECT_TRUE(r->host == host) << "build_dgram: roundtrip host match";
    EXPECT_TRUE(r->port == 8080) << "build_dgram: roundtrip port match";
    EXPECT_TRUE(r->payload.size() == 2) << "build_dgram: roundtrip payload size";
}

TEST(SmuxFrameDeep, BuildDgramDomainEmptyPayload)
{
    const std::string_view host = "a.b";
    std::vector<std::byte> payload;
    psm::multiplex::smux::datagram_params params{host, 53, payload};
    auto buf = psm::multiplex::smux::build_dgram(params, psm::memory::current_resource());
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "build_dgram: domain empty payload roundtrip -> ok";
    EXPECT_TRUE(r->payload.empty()) << "build_dgram: roundtrip payload empty";
}

// ─── build_prefixed 测试 ───────────────────

TEST(SmuxFrameDeep, BuildPrefixedBasic)
{
    std::vector<std::byte> payload = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    auto buf = psm::multiplex::smux::build_prefixed(payload, psm::memory::current_resource());
    EXPECT_TRUE(buf.size() == 5) << "build_prefixed: size = 5";
    EXPECT_TRUE(buf[0] == std::byte{0x00}) << "build_prefixed: length high byte";
    EXPECT_TRUE(buf[1] == std::byte{0x03}) << "build_prefixed: length low byte";
}

TEST(SmuxFrameDeep, BuildPrefixedEmpty)
{
    std::vector<std::byte> payload;
    auto buf = psm::multiplex::smux::build_prefixed(payload, psm::memory::current_resource());
    EXPECT_TRUE(buf.size() == 2) << "build_prefixed: empty payload size = 2";
    EXPECT_TRUE(buf[0] == std::byte{0x00} && buf[1] == std::byte{0x00})
        << "build_prefixed: length = 0";
}

TEST(SmuxFrameDeep, BuildPrefixedRoundtrip)
{
    std::vector<std::byte> payload = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};
    auto buf = psm::multiplex::smux::build_prefixed(payload, psm::memory::current_resource());
    auto r = psm::multiplex::smux::parse_prefixed(buf);
    ASSERT_TRUE(!!r) << "build_prefixed: roundtrip parse -> ok";
    EXPECT_TRUE(r->payload.size() == 4) << "build_prefixed: roundtrip payload size = 4";
    EXPECT_TRUE(r->consumed == 6) << "build_prefixed: roundtrip consumed = 6";
}

TEST(SmuxFrameDeep, BuildPrefixedLargeLength)
{
    // 测试大端编码：256 字节 -> 0x01 0x00
    std::vector<std::byte> payload(256, std::byte{0xFF});
    auto buf = psm::multiplex::smux::build_prefixed(payload, psm::memory::current_resource());
    EXPECT_TRUE(buf[0] == std::byte{0x01}) << "build_prefixed: length high = 1";
    EXPECT_TRUE(buf[1] == std::byte{0x00}) << "build_prefixed: length low = 0";
    EXPECT_TRUE(buf.size() == 258) << "build_prefixed: total size = 258";
}

// ─── build_dgram 往返测试（完整 roundtrip）──

TEST(SmuxFrameDeep, BuildParseDgramIpv4FullRoundtrip)
{
    const std::string_view host = "8.8.8.8";
    std::vector<std::byte> payload(100, std::byte{0x42});
    psm::multiplex::smux::datagram_params params{host, 53, payload};
    auto buf = psm::multiplex::smux::build_dgram(params, psm::memory::current_resource());
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());

    ASSERT_TRUE(!!r) << "full roundtrip: parse ok";
    EXPECT_TRUE(r->host == host) << "full roundtrip: host match";
    EXPECT_TRUE(r->port == 53) << "full roundtrip: port match";
    EXPECT_TRUE(r->payload.size() == 100) << "full roundtrip: payload size = 100";
    EXPECT_TRUE(r->consumed == buf.size()) << "full roundtrip: consumed = buf size";

    // 验证 payload 内容
    bool all_match = true;
    for (std::size_t i = 0; i < r->payload.size(); ++i)
    {
        if (r->payload[i] != std::byte{0x42})
        {
            all_match = false;
            break;
        }
    }
    EXPECT_TRUE(all_match) << "full roundtrip: all payload bytes match";
}

TEST(SmuxFrameDeep, BuildParseDgramDomainFullRoundtrip)
{
    const std::string_view host = "dns.google";
    std::vector<std::byte> payload = {std::byte{0x01}, std::byte{0x02}};
    psm::multiplex::smux::datagram_params params{host, 853, payload};
    auto buf = psm::multiplex::smux::build_dgram(params, psm::memory::current_resource());
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());

    ASSERT_TRUE(!!r) << "domain full roundtrip: parse ok";
    EXPECT_TRUE(r->host == host) << "domain full roundtrip: host match";
    EXPECT_TRUE(r->port == 853) << "domain full roundtrip: port match";
    EXPECT_TRUE(r->consumed == buf.size()) << "domain full roundtrip: consumed = buf size";
}

TEST(SmuxFrameDeep, BuildParseDgramIpv6FullRoundtrip)
{
    const std::string_view host = "2001:4860:4860::8888";
    std::vector<std::byte> payload = {std::byte{0xAA}};
    psm::multiplex::smux::datagram_params params{host, 53, payload};
    auto buf = psm::multiplex::smux::build_dgram(params, psm::memory::current_resource());
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());

    ASSERT_TRUE(!!r) << "IPv6 full roundtrip: parse ok";
    EXPECT_TRUE(r->port == 53) << "IPv6 full roundtrip: port match";
    EXPECT_TRUE(r->payload.size() == 1) << "IPv6 full roundtrip: payload size = 1";
    EXPECT_TRUE(r->consumed == buf.size()) << "IPv6 full roundtrip: consumed = buf size";
}

// ─── build_prefixed 往返测试 ───────────────

TEST(SmuxFrameDeep, BuildParsePrefixedFullRoundtrip)
{
    std::vector<std::byte> payload(500, std::byte{0x77});
    auto buf = psm::multiplex::smux::build_prefixed(payload, psm::memory::current_resource());
    auto r = psm::multiplex::smux::parse_prefixed(buf);

    ASSERT_TRUE(!!r) << "prefixed full roundtrip: parse ok";
    EXPECT_TRUE(r->payload.size() == 500) << "prefixed full roundtrip: payload size = 500";
    EXPECT_TRUE(r->consumed == buf.size()) << "prefixed full roundtrip: consumed = buf size";
}

// ─── format_ipv4 间接测试（通过 parse_address 验证）──

TEST(SmuxFrameDeep, FormatIpv4AllRanges)
{
    // 0-9 (1 digit)
    {
        auto buf = make_address_ipv4(0, 5, 0, 0, 0, 80);
        auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
        EXPECT_TRUE(!!r && r->host == "5.0.0.0") << "format_ipv4: 1-digit octet";
    }
    // 10-99 (2 digits)
    {
        auto buf = make_address_ipv4(0, 50, 0, 0, 0, 80);
        auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
        EXPECT_TRUE(!!r && r->host == "50.0.0.0") << "format_ipv4: 2-digit octet";
    }
    // 100-255 (3 digits)
    {
        auto buf = make_address_ipv4(0, 200, 100, 10, 1, 80);
        auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
        EXPECT_TRUE(!!r && r->host == "200.100.10.1") << "format_ipv4: 3-digit octets";
    }
}

TEST(SmuxFrameDeep, FormatIpv4Boundary)
{
    // 0 (special: all 1-digit)
    {
        auto buf = make_address_ipv4(0, 0, 0, 0, 0, 1);
        auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
        EXPECT_TRUE(!!r && r->host == "0.0.0.0") << "format_ipv4: all zeros";
    }
    // 255 (all 3-digit)
    {
        auto buf = make_address_ipv4(0, 255, 255, 255, 255, 1);
        auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
        EXPECT_TRUE(!!r && r->host == "255.255.255.255") << "format_ipv4: all 255";
    }
}

// ─── 边界值测试 ──────────────────────────────

TEST(SmuxFrameDeep, DeserCommandBoundaryValues)
{
    // command value 0 = syn
    {
        auto buf = make_header(0x01, static_cast<psm::multiplex::smux::command>(0), 0, 1);
        auto r = psm::multiplex::smux::deserialization(buf);
        EXPECT_TRUE(!!r && r->cmd == psm::multiplex::smux::command::syn) << "deser: cmd 0 = syn";
    }
    // command value 3 = nop
    {
        auto buf = make_header(0x01, static_cast<psm::multiplex::smux::command>(3), 0, 1);
        auto r = psm::multiplex::smux::deserialization(buf);
        EXPECT_TRUE(!!r && r->cmd == psm::multiplex::smux::command::nop) << "deser: cmd 3 = nop";
    }
    // command value 4 = invalid
    {
        auto buf = make_header(0x01, static_cast<psm::multiplex::smux::command>(4), 0, 1);
        auto r = psm::multiplex::smux::deserialization(buf);
        EXPECT_TRUE(!r) << "deser: cmd 4 = invalid";
    }
    // command value 255 = invalid
    {
        auto buf = make_header(0x01, static_cast<psm::multiplex::smux::command>(255), 0, 1);
        auto r = psm::multiplex::smux::deserialization(buf);
        EXPECT_TRUE(!r) << "deser: cmd 255 = invalid";
    }
}

TEST(SmuxFrameDeep, ParseDgramIpv4PortZero)
{
    auto payload = std::vector<std::byte>{std::byte{0x01}};
    auto buf = make_dgram_ipv4(127, 0, 0, 1, 0, payload);
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "dgram: port 0 -> ok";
    EXPECT_TRUE(r->port == 0) << "dgram: port = 0";
}

TEST(SmuxFrameDeep, ParseDgramIpv4PortMax)
{
    auto payload = std::vector<std::byte>{std::byte{0x01}};
    auto buf = make_dgram_ipv4(127, 0, 0, 1, 65535, payload);
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "dgram: port 65535 -> ok";
    EXPECT_TRUE(r->port == 65535) << "dgram: port = 65535";
}

TEST(SmuxFrameDeep, ParseAddrDomainExtraData)
{
    // flags(2) + atype(1) + domain_len(1) + domain(3) + port(2) + extra
    auto buf = make_address_domain(0, "abc", 80);
    buf.push_back(std::byte{0xFF});
    buf.push_back(std::byte{0xFF});
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "addr: extra data -> ok";
    EXPECT_TRUE(r->offset == 9) << "addr: offset ignores extra";
}

TEST(SmuxFrameDeep, ParseDgramIpv4ExtraData)
{
    auto payload = std::vector<std::byte>{std::byte{0x01}};
    auto buf = make_dgram_ipv4(127, 0, 0, 1, 443, payload);
    buf.push_back(std::byte{0xFF}); // extra
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "dgram: extra data -> ok";
    EXPECT_TRUE(r->consumed == buf.size() - 1) << "dgram: consumed ignores extra";
}

TEST(SmuxFrameDeep, ParsePrefixedExtraData)
{
    std::vector<std::byte> buf = {
        std::byte{0x00}, std::byte{0x02},
        std::byte{0xAA}, std::byte{0xBB},
        std::byte{0xCC}}; // extra
    auto r = psm::multiplex::smux::parse_prefixed(buf);
    ASSERT_TRUE(!!r) << "prefixed: extra data -> ok";
    EXPECT_TRUE(r->consumed == 4) << "prefixed: consumed ignores extra";
}

// ─── parse_dgram domain 边界 ───────────────

TEST(SmuxFrameDeep, ParseDgramDomainLenZero)
{
    auto payload = std::vector<std::byte>{std::byte{0x01}};
    auto buf = make_dgram_domain("", 80, payload);
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "dgram: empty domain -> ok";
    EXPECT_TRUE(r->host.empty()) << "dgram: host empty";
    EXPECT_TRUE(r->port == 80) << "dgram: port = 80";
}

TEST(SmuxFrameDeep, ParseDgramDomainNoLength)
{
    // atype(1) + domain_len(1) + domain(3) + port(2) but no length prefix
    std::vector<std::byte> buf = {
        std::byte{0x03}, std::byte{0x03},
        std::byte{'a'}, std::byte{'b'}, std::byte{'c'},
        std::byte{0x01}, std::byte{0xBB}};
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "dgram: domain no length -> nullopt";
}

TEST(SmuxFrameDeep, ParseDgramDomainPayloadTruncated)
{
    // atype(1) + domain_len(1) + domain(3) + port(2) + length(2) saying 10 but only 1
    std::vector<std::byte> buf = {
        std::byte{0x03}, std::byte{0x03},
        std::byte{'a'}, std::byte{'b'}, std::byte{'c'},
        std::byte{0x01}, std::byte{0xBB},
        std::byte{0x00}, std::byte{0x0A},
        std::byte{0xFF}};
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "dgram: domain payload truncated -> nullopt";
}

// ─── build_dgram 边界值 ────────────────────

TEST(SmuxFrameDeep, BuildDgramIpv4ZeroPort)
{
    const std::string_view host = "0.0.0.0";
    std::vector<std::byte> payload;
    psm::multiplex::smux::datagram_params params{host, 0, payload};
    auto buf = psm::multiplex::smux::build_dgram(params, psm::memory::current_resource());
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "build_dgram: zero port roundtrip -> ok";
    EXPECT_TRUE(r->port == 0) << "build_dgram: port = 0";
}

TEST(SmuxFrameDeep, BuildDgramIpv4MaxPort)
{
    const std::string_view host = "1.2.3.4";
    std::vector<std::byte> payload;
    psm::multiplex::smux::datagram_params params{host, 65535, payload};
    auto buf = psm::multiplex::smux::build_dgram(params, psm::memory::current_resource());
    auto r = psm::multiplex::smux::parse_dgram(buf, psm::memory::current_resource());
    ASSERT_TRUE(!!r) << "build_dgram: max port roundtrip -> ok";
    EXPECT_TRUE(r->port == 65535) << "build_dgram: port = 65535";
}

// ─── parse_address 截断端口的最后一个字节 ───

TEST(SmuxFrameDeep, ParseAddrIpv6NoPort)
{
    std::array<std::uint8_t, 16> addr{};
    addr[15] = 1;
    // flags(2) + atype(1) + IPv6(16) but no port
    std::vector<std::byte> buf(19, std::byte{0x00});
    buf[2] = std::byte{0x04}; // IPv6
    buf[18] = std::byte{0x01};
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "addr: IPv6 no port -> nullopt";
}

TEST(SmuxFrameDeep, ParseAddrIpv6OneBytePort)
{
    std::array<std::uint8_t, 16> addr{};
    // flags(2) + atype(1) + IPv6(16) + only 1 byte of port
    std::vector<std::byte> buf(20, std::byte{0x00});
    buf[2] = std::byte{0x04}; // IPv6
    auto r = psm::multiplex::smux::parse_address(buf, psm::memory::current_resource());
    EXPECT_TRUE(!r) << "addr: IPv6 1-byte port -> nullopt";
}

// #include 源文件以覆盖 frame.cpp 全部实现
#include "../../src/prism/protocol/multiplex/smux/frame.cpp"
