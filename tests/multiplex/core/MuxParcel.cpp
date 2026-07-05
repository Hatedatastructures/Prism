/**
 * @file MuxParcel.cpp
 * @brief multiplex parcel 缓冲区重组单元测试
 * @details 测试 parcel 缓冲区管理和数据报重组逻辑：
 * 跨帧拆分重组、单帧多数据报分离、溢出保护等场景。
 * 直接使用 smux 帧编解码函数模拟 parcel::process_buffer 的缓冲区累积和流式解析行为，
 * 无需构造完整的 core/router 协程环境。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/proto/multiplex/smux/frame.hpp>

#include <gtest/gtest.h>

#include <cstring>

using namespace psm::multiplex::smux;

namespace
{
    // ---------- helpers ----------

    /**
     * @brief 模拟 parcel::on_data 的缓冲区累积行为
     * @param accumulated 累积缓冲区（对应 parcel::mux_buffer_）
     * @param incoming 新到达的帧数据
     * @return 累积后缓冲区是否包含可解析的完整数据报
     */
    [[nodiscard]] auto accumulate_and_try_parse_packet_addr(
        psm::memory::vector<std::byte> &accumulated,
        std::span<const std::byte> incoming) -> bool
    {
        accumulated.insert(accumulated.end(), incoming.begin(), incoming.end());
        return parse_dgram(accumulated, psm::memory::current_resource()).has_value();
    }

    /**
     * @brief 模拟 parcel::on_data 的缓冲区累积行为（length-prefixed 模式）
     */
    [[nodiscard]] auto accumulate_and_try_parse_length_prefixed(
        psm::memory::vector<std::byte> &accumulated,
        std::span<const std::byte> incoming) -> bool
    {
        accumulated.insert(accumulated.end(), incoming.begin(), incoming.end());
        return parse_prefixed(accumulated).has_value();
    }

    // ---------- 跨帧拆分：PacketAddr 模式（IPv4）----------

    /**
     * @brief 测试跨帧拆分 - IPv4 PacketAddr 模式
     * @details 一个完整的 UDP 数据报被拆分为 3 个帧片段，
     * 模拟 parcel::process_buffer 逐帧累积后流式解析的过程。
     * IPv4 PacketAddr 格式：[ATYP 1B][Addr 4B][Port 2B][Length 2B BE][Payload]
     */
    TEST(MuxParcel, CrossFrameSplitPacketAddrIPv4)
    {
        // 构建完整数据报：ATYP(1)+Addr(4)+Port(2)+Len(2)+Payload(4) = 13 bytes
        const std::byte payload[] = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
        auto full = build_dgram({"127.0.0.1", 9090, payload}, psm::memory::current_resource());

        // 拆分为 3 个帧片段：[0,3) + [3,8) + [8,13)
        const auto frag1 = std::span<const std::byte>(full.data(), 3);
        const auto frag2 = std::span<const std::byte>(full.data() + 3, 5);
        const auto frag3 = std::span<const std::byte>(full.data() + 8, full.size() - 8);

        psm::memory::vector<std::byte> buf;

        // 帧 1：仅 ATYP + 2 字节地址，不完整
        const bool ok1 = accumulate_and_try_parse_packet_addr(buf, frag1);
        EXPECT_TRUE(!ok1) << "cross-frame IPv4: frame 1 incomplete";

        // 帧 2：地址+端口完整，但缺少 Length+Payload
        const bool ok2 = accumulate_and_try_parse_packet_addr(buf, frag2);
        EXPECT_TRUE(!ok2) << "cross-frame IPv4: frame 2 incomplete";

        // 帧 3：Length+Payload 到达，数据报完整
        const bool ok3 = accumulate_and_try_parse_packet_addr(buf, frag3);
        EXPECT_TRUE(ok3) << "cross-frame IPv4: frame 3 complete";

        if (ok3)
        {
            auto result = parse_dgram(buf, psm::memory::current_resource());
            EXPECT_TRUE(result.has_value()) << "cross-frame IPv4: final parse valid";
            if (result)
            {
                EXPECT_TRUE(result->host == "127.0.0.1") << "cross-frame IPv4: host matches";
                EXPECT_TRUE(result->port == 9090) << "cross-frame IPv4: port matches";
                EXPECT_TRUE(result->payload.size() == 4) << "cross-frame IPv4: payload size matches";
                EXPECT_TRUE(result->consumed == full.size()) << "cross-frame IPv4: consumed equals full size";
            }
        }
    }

    // ---------- 跨帧拆分：PacketAddr 模式（域名）----------

    /**
     * @brief 测试跨帧拆分 - 域名 PacketAddr 模式
     * @details 在域名中间拆帧，验证缓冲区累积后能正确重组。
     * 域名 PacketAddr 格式：[ATYP 1B][Len 1B][Domain][Port 2B][Length 2B BE][Payload]
     */
    TEST(MuxParcel, CrossFrameSplitPacketAddrDomain)
    {
        const std::byte payload[] = {std::byte{0x42}};
        auto full = build_dgram({"example.com", 443, payload}, psm::memory::current_resource());

        // 在域名中间拆帧
        const auto frag1 = std::span<const std::byte>(full.data(), 4);
        const auto frag2 = std::span<const std::byte>(full.data() + 4, full.size() - 4);

        psm::memory::vector<std::byte> buf;

        const bool ok1 = accumulate_and_try_parse_packet_addr(buf, frag1);
        EXPECT_TRUE(!ok1) << "cross-frame domain: frame 1 incomplete";

        const bool ok2 = accumulate_and_try_parse_packet_addr(buf, frag2);
        EXPECT_TRUE(ok2) << "cross-frame domain: frame 2 complete";

        if (ok2)
        {
            auto result = parse_dgram(buf, psm::memory::current_resource());
            EXPECT_TRUE(result.has_value()) << "cross-frame domain: final parse valid";
            if (result)
            {
                EXPECT_TRUE(result->host == "example.com") << "cross-frame domain: host matches";
                EXPECT_TRUE(result->port == 443) << "cross-frame domain: port matches";
                EXPECT_TRUE(result->payload.size() == 1) << "cross-frame domain: payload size matches";
                EXPECT_TRUE(result->consumed == full.size()) << "cross-frame domain: consumed equals full size";
            }
        }
    }

    // ---------- 跨帧拆分：Length-prefixed 模式 ----------

    /**
     * @brief 测试跨帧拆分 - length-prefixed 模式
     * @details Length header (2B) 和 Payload 在不同帧到达。
     * Length-prefixed 格式：[Length 2B BE][Payload]
     */
    TEST(MuxParcel, CrossFrameSplitLengthPrefixed)
    {
        const std::byte payload[] = {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}};
        auto full = build_prefixed(payload, psm::memory::current_resource());

        // 帧 1：仅 Length header (2B)，无 payload
        const auto frag1 = std::span<const std::byte>(full.data(), 2);
        // 帧 2：Payload
        const auto frag2 = std::span<const std::byte>(full.data() + 2, full.size() - 2);

        psm::memory::vector<std::byte> buf;

        const bool ok1 = accumulate_and_try_parse_length_prefixed(buf, frag1);
        EXPECT_TRUE(!ok1) << "cross-frame LP: header only incomplete";

        const bool ok2 = accumulate_and_try_parse_length_prefixed(buf, frag2);
        EXPECT_TRUE(ok2) << "cross-frame LP: payload arrived complete";

        if (ok2)
        {
            auto result = parse_prefixed(buf);
            EXPECT_TRUE(result.has_value()) << "cross-frame LP: final parse valid";
            if (result)
            {
                EXPECT_TRUE(result->payload.size() == 3) << "cross-frame LP: payload size matches";
                EXPECT_TRUE(result->consumed == full.size()) << "cross-frame LP: consumed equals full size";
                EXPECT_TRUE(result->payload[0] == std::byte{0x11}) << "cross-frame LP: payload content byte 0";
                EXPECT_TRUE(result->payload[2] == std::byte{0x33}) << "cross-frame LP: payload content byte 2";
            }
        }
    }

    // ---------- 单帧多数据报：PacketAddr 模式 ----------

    /**
     * @brief 测试单帧包含多个 PacketAddr 数据报
     * @details 3 个独立的 UDP 数据报被编码后拼接在同一帧中，
     * 模拟 parcel::process_buffer 使用 consumed 字段逐个提取。
     */
    TEST(MuxParcel, SingleFrameMultipleDatagrams)
    {
        const std::byte payload1[] = {std::byte{0xAA}};
        const std::byte payload2[] = {std::byte{0xBB}, std::byte{0xCC}};
        const std::byte payload3[] = {std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}};

        auto enc1 = build_dgram({"10.0.0.1", 1001, payload1}, psm::memory::current_resource());
        auto enc2 = build_dgram({"10.0.0.2", 1002, payload2}, psm::memory::current_resource());
        auto enc3 = build_dgram({"10.0.0.3", 1003, payload3}, psm::memory::current_resource());

        // 拼接到同一缓冲区
        psm::memory::vector<std::byte> combined;
        combined.insert(combined.end(), enc1.begin(), enc1.end());
        combined.insert(combined.end(), enc2.begin(), enc2.end());
        combined.insert(combined.end(), enc3.begin(), enc3.end());

        // 使用 consumed 逐个流式解析，模拟 process_buffer 中的 while 循环
        std::size_t offset = 0;

        // 数据报 1
        auto span1 = std::span<const std::byte>(combined.data() + offset, combined.size() - offset);
        auto r1 = parse_dgram(span1, psm::memory::current_resource());
        EXPECT_TRUE(r1.has_value()) << "multi-dgram: datagram 1 parsed";
        if (r1)
        {
            EXPECT_TRUE(r1->host == "10.0.0.1") << "multi-dgram: datagram 1 host";
            EXPECT_TRUE(r1->port == 1001) << "multi-dgram: datagram 1 port";
            EXPECT_TRUE(r1->payload.size() == 1) << "multi-dgram: datagram 1 payload size";
            offset += r1->consumed;
        }

        // 数据报 2
        auto span2 = std::span<const std::byte>(combined.data() + offset, combined.size() - offset);
        auto r2 = parse_dgram(span2, psm::memory::current_resource());
        EXPECT_TRUE(r2.has_value()) << "multi-dgram: datagram 2 parsed";
        if (r2)
        {
            EXPECT_TRUE(r2->host == "10.0.0.2") << "multi-dgram: datagram 2 host";
            EXPECT_TRUE(r2->port == 1002) << "multi-dgram: datagram 2 port";
            EXPECT_TRUE(r2->payload.size() == 2) << "multi-dgram: datagram 2 payload size";
            offset += r2->consumed;
        }

        // 数据报 3
        auto span3 = std::span<const std::byte>(combined.data() + offset, combined.size() - offset);
        auto r3 = parse_dgram(span3, psm::memory::current_resource());
        EXPECT_TRUE(r3.has_value()) << "multi-dgram: datagram 3 parsed";
        if (r3)
        {
            EXPECT_TRUE(r3->host == "10.0.0.3") << "multi-dgram: datagram 3 host";
            EXPECT_TRUE(r3->port == 1003) << "multi-dgram: datagram 3 port";
            EXPECT_TRUE(r3->payload.size() == 3) << "multi-dgram: datagram 3 payload size";
            offset += r3->consumed;
        }

        // 所有字节已消费
        EXPECT_TRUE(offset == combined.size()) << "multi-dgram: all bytes consumed";
    }

    // ---------- 单帧多数据报：Length-prefixed 模式 ----------

    /**
     * @brief 测试单帧包含多个 length-prefixed 数据报
     */
    TEST(MuxParcel, SingleFrameMultipleLengthPrefixed)
    {
        const std::byte p1[] = {std::byte{0x01}};
        const std::byte p2[] = {std::byte{0x02}, std::byte{0x03}};
        const std::byte p3[] = {std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07}};

        auto enc1 = build_prefixed(p1, psm::memory::current_resource());
        auto enc2 = build_prefixed(p2, psm::memory::current_resource());
        auto enc3 = build_prefixed(p3, psm::memory::current_resource());

        psm::memory::vector<std::byte> combined;
        combined.insert(combined.end(), enc1.begin(), enc1.end());
        combined.insert(combined.end(), enc2.begin(), enc2.end());
        combined.insert(combined.end(), enc3.begin(), enc3.end());

        std::size_t offset = 0;

        auto span1 = std::span<const std::byte>(combined.data(), combined.size());
        auto r1 = parse_prefixed(span1);
        EXPECT_TRUE(r1.has_value()) << "multi-LP: datagram 1 parsed";
        if (r1)
        {
            EXPECT_TRUE(r1->payload.size() == 1) << "multi-LP: datagram 1 payload size";
            EXPECT_TRUE(r1->payload[0] == std::byte{0x01}) << "multi-LP: datagram 1 payload content";
            offset += r1->consumed;
        }

        auto span2 = std::span<const std::byte>(combined.data() + offset, combined.size() - offset);
        auto r2 = parse_prefixed(span2);
        EXPECT_TRUE(r2.has_value()) << "multi-LP: datagram 2 parsed";
        if (r2)
        {
            EXPECT_TRUE(r2->payload.size() == 2) << "multi-LP: datagram 2 payload size";
            offset += r2->consumed;
        }

        auto span3 = std::span<const std::byte>(combined.data() + offset, combined.size() - offset);
        auto r3 = parse_prefixed(span3);
        EXPECT_TRUE(r3.has_value()) << "multi-LP: datagram 3 parsed";
        if (r3)
        {
            EXPECT_TRUE(r3->payload.size() == 4) << "multi-LP: datagram 3 payload size";
            offset += r3->consumed;
        }

        EXPECT_TRUE(offset == combined.size()) << "multi-LP: all bytes consumed";
    }

    // ---------- 部分完成 + 新数据到达（process_buffer 核心模式）----------

    /**
     * @brief 测试完整数据报 + 不完整数据报共存于缓冲区
     * @details 模拟 process_buffer 的核心场景：缓冲区中第一个数据报完整可解析，
     * 第二个数据报不完整需要等待后续帧。解析第一个后保留剩余数据，
     * 新数据到达后第二个数据报可解析。
     */
    TEST(MuxParcel, PartialThenComplete)
    {
        const std::byte p1[] = {std::byte{0x01}, std::byte{0x02}};
        const std::byte p2[] = {std::byte{0x03}, std::byte{0x04}, std::byte{0x05}};

        auto enc1 = build_dgram({"10.0.0.1", 1111, p1}, psm::memory::current_resource());
        auto enc2 = build_dgram({"10.0.0.2", 2222, p2}, psm::memory::current_resource());

        // 缓冲区：完整数据报 1 + 不完整数据报 2（前 3 字节）
        psm::memory::vector<std::byte> buf;
        buf.insert(buf.end(), enc1.begin(), enc1.end());
        buf.insert(buf.end(), enc2.begin(), enc2.begin() + 3);

        // 解析数据报 1
        auto span = std::span<const std::byte>(buf.data(), buf.size());
        auto r1 = parse_dgram(span, psm::memory::current_resource());
        EXPECT_TRUE(r1.has_value()) << "partial: datagram 1 complete";

        if (r1)
        {
            const auto offset = r1->consumed;
            EXPECT_TRUE(r1->host == "10.0.0.1") << "partial: datagram 1 host";
            EXPECT_TRUE(r1->port == 1111) << "partial: datagram 1 port";
            EXPECT_TRUE(r1->payload.size() == 2) << "partial: datagram 1 payload size";

            // 数据报 2 不完整
            auto remaining = std::span<const std::byte>(buf.data() + offset, buf.size() - offset);
            auto r2 = parse_dgram(remaining, psm::memory::current_resource());
            EXPECT_TRUE(!r2.has_value()) << "partial: datagram 2 incomplete";

            // 模拟后续帧到达，补充数据报 2 剩余数据
            buf.insert(buf.end(), enc2.begin() + 3, enc2.end());

            auto full_remaining = std::span<const std::byte>(buf.data() + offset, buf.size() - offset);
            auto r3 = parse_dgram(full_remaining, psm::memory::current_resource());
            EXPECT_TRUE(r3.has_value()) << "partial: datagram 2 now complete";
            if (r3)
            {
                EXPECT_TRUE(r3->host == "10.0.0.2") << "partial: datagram 2 host";
                EXPECT_TRUE(r3->port == 2222) << "partial: datagram 2 port";
                EXPECT_TRUE(r3->payload.size() == 3) << "partial: datagram 2 payload size";
                EXPECT_TRUE(r3->consumed == enc2.size()) << "partial: datagram 2 consumed correct";
            }
        }
    }

    // ---------- 溢出保护 ----------

    /**
     * @brief 测试缓冲区溢出保护
     * @details 模拟 parcel::on_data 中的溢出检查逻辑：
     * if (mux_buffer_.size() > udp_max_datagram_) { close(); }
     * 当累积数据超过最大数据报大小时，parcel 应关闭管道丢弃数据。
     */
    TEST(MuxParcel, OverflowProtection)
    {
        // 使用小阈值模拟 udp_max_datagram_ 限制
        constexpr std::uint32_t udp_max_dg = 64;

        // 构建合规数据报（IPv4: 9 + payload）
        psm::memory::vector<std::byte> small_payload;
        small_payload.resize(10, std::byte{0xAB});
        auto enc_small = build_dgram({"127.0.0.1", 80, small_payload}, psm::memory::current_resource());

        EXPECT_TRUE(enc_small.size() <= udp_max_dg) << "overflow: small datagram within limit";

        // 构建超限数据报
        psm::memory::vector<std::byte> large_payload;
        large_payload.resize(128, std::byte{0xCD});
        auto enc_large = build_dgram({"127.0.0.1", 80, large_payload}, psm::memory::current_resource());

        EXPECT_TRUE(enc_large.size() > udp_max_dg) << "overflow: large datagram exceeds limit";

        // 模拟 parcel::mux_buffer_ 累积
        psm::memory::vector<std::byte> mux_buffer;
        mux_buffer.insert(mux_buffer.end(), enc_small.begin(), enc_small.end());

        bool overflow_before = mux_buffer.size() > udp_max_dg;
        EXPECT_TRUE(!overflow_before) << "overflow: buffer OK after small datagram";

        // 累积超限数据，触发 parcel::on_data 中的溢出检查
        mux_buffer.insert(mux_buffer.end(), enc_large.begin(), enc_large.end());

        bool overflow_after = mux_buffer.size() > udp_max_dg;
        EXPECT_TRUE(overflow_after) << "overflow: buffer exceeds max after accumulation";

        // 解析层：溢出后第一个数据报仍然可正确解析
        // （在 parcel 实际逻辑中，溢出时直接 close 不会到达 parse）
        auto result = parse_dgram(mux_buffer, psm::memory::current_resource());
        EXPECT_TRUE(result.has_value()) << "overflow: first datagram still parseable";
        if (result)
        {
            EXPECT_TRUE(result->payload.size() == 10) << "overflow: first datagram payload correct";
        }

        // Length-prefixed 模式的溢出保护同样适用
        psm::memory::vector<std::byte> lp_large;
        lp_large.resize(100, std::byte{0xEE});
        auto enc_lp = build_prefixed(lp_large, psm::memory::current_resource());

        EXPECT_TRUE(enc_lp.size() > udp_max_dg) << "overflow: LP datagram exceeds limit";

        psm::memory::vector<std::byte> lp_buf;
        lp_buf.insert(lp_buf.end(), enc_lp.begin(), enc_lp.end());

        EXPECT_TRUE(lp_buf.size() > udp_max_dg) << "overflow: LP buffer exceeds max";
    }

    // ---------- 空数据 / 边界情况 ----------

    /**
     * @brief 测试空帧数据和零长度 payload
     */
    TEST(MuxParcel, EmptyAndZeroPayload)
    {
        // 空数据
        psm::memory::vector<std::byte> empty_buf;
        auto r1 = parse_dgram(empty_buf, psm::memory::current_resource());
        EXPECT_TRUE(!r1.has_value()) << "empty: empty data returns nullopt";

        auto r2 = parse_prefixed(empty_buf);
        EXPECT_TRUE(!r2.has_value()) << "empty: LP empty data returns nullopt";

        // 零长度 payload（PacketAddr IPv4: 9 + 0 = 9 字节）
        const auto zero_span = std::span<const std::byte>{};
        auto enc_zero = build_dgram({"127.0.0.1", 1234, zero_span}, psm::memory::current_resource());
        EXPECT_TRUE(enc_zero.size() == 9) << "zero-payload: IPv4 header is 9 bytes";

        auto r3 = parse_dgram(enc_zero, psm::memory::current_resource());
        EXPECT_TRUE(r3.has_value()) << "zero-payload: parse succeeds";
        if (r3)
        {
            EXPECT_TRUE(r3->payload.empty()) << "zero-payload: payload is empty";
            EXPECT_TRUE(r3->consumed == 9) << "zero-payload: consumed is header size only";
        }

        // 零长度 payload（Length-prefixed: 2 字节 header only）
        auto enc_lp_zero = build_prefixed(zero_span, psm::memory::current_resource());
        EXPECT_TRUE(enc_lp_zero.size() == 2) << "zero-payload: LP header is 2 bytes";

        auto r4 = parse_prefixed(enc_lp_zero);
        EXPECT_TRUE(r4.has_value()) << "zero-payload: LP parse succeeds";
        if (r4)
        {
            EXPECT_TRUE(r4->payload.empty()) << "zero-payload: LP payload is empty";
            EXPECT_TRUE(r4->consumed == 2) << "zero-payload: LP consumed is header size only";
        }
    }

} // namespace
