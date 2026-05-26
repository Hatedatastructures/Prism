/**
 * @file YamuxCraft.cpp
 * @brief yamux 多路复用帧构建（craft）单元测试
 * @details 验证 psm::multiplex::yamux 模块的 Data/SYN/FIN 帧构建功能，
 * 覆盖以下场景：
 * 1. build_data() 帧头与载荷编码正确性
 * 2. build_syn() SYN 标志与载荷编码正确性
 * 3. build_fin() FIN 标志与零载荷编码正确性
 * 4. 帧头解析往返一致性
 * 5. 边界情况（空载荷、大 stream_id、多字节载荷）
 */

#include <prism/multiplex/yamux/frame.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <span>
#include <string_view>
#include <vector>

#include "common/TestRunner.hpp"

/**
 * @brief 测试 build_data() 编码正确性
 * @details 使用非空载荷验证帧头 type=0、flag=none、stream_id 和
 * length 字段正确，且 header 后紧跟完整的 payload 字节。
 */
void TestYamuxCraftDataFrame(psm::testing::TestRunner &runner)
{
    namespace yamux = psm::multiplex::yamux;

    // 构造 8 字节测试载荷
    const std::array<std::byte, 8> raw_payload = {
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
        std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}};

    auto frame = yamux::build_data(yamux::flags::none, 42, raw_payload);

    // 解析帧头验证各字段
    const auto hdr = yamux::parse_header(frame.header);
    runner.Check(hdr.has_value(), "build_data: header parse succeeded");

    if (hdr)
    {
        runner.Check(hdr->version == yamux::protocol_version,
                      "build_data: version == 0");
        runner.Check(hdr->type == yamux::message_type::data,
                      "build_data: type == data");
        runner.Check(hdr->flag == yamux::flags::none,
                      "build_data: flag == none");
        runner.Check(hdr->stream_id == 42,
                      std::format("build_data: stream_id == 42 (got {})", hdr->stream_id).c_str());
        runner.Check(hdr->length == 8,
                      std::format("build_data: length == 8 (got {})", hdr->length).c_str());
    }

    // 验证载荷内容逐字节一致
    bool payload_match = (frame.payload.size() == raw_payload.size());
    if (payload_match)
    {
        for (std::size_t i = 0; i < raw_payload.size(); ++i)
        {
            if (frame.payload[i] != raw_payload[i])
            {
                payload_match = false;
                break;
            }
        }
    }
    runner.Check(payload_match, "build_data: payload content matches");

    // 空载荷场景
    auto empty_frame = yamux::build_data(yamux::flags::none, 1, {});
    const auto empty_hdr = yamux::parse_header(empty_frame.header);
    runner.Check(empty_hdr.has_value(), "build_data(empty): header parse succeeded");
    if (empty_hdr)
    {
        runner.Check(empty_hdr->length == 0, "build_data(empty): length == 0");
        runner.Check(empty_frame.payload.empty(), "build_data(empty): payload is empty");
    }

    runner.LogPass("YamuxCraftDataFrame");
}

/**
 * @brief 测试 build_syn() 编码正确性
 * @details 验证 SYN 标志位正确设置，stream_id 和载荷编码一致，
 * 帧头解析后 type==data 且 flag==syn。
 */
void TestYamuxCraftSynFrame(psm::testing::TestRunner &runner)
{
    namespace yamux = psm::multiplex::yamux;

    // 构造携带地址数据的 SYN 帧载荷（模拟 sing-mux StreamRequest）
    const std::array<std::byte, 12> raw_payload = {
        std::byte{0x01}, // IPv4
        std::byte{0x00}, std::byte{0x50}, // port 80 (big-endian)
        std::byte{0xC0}, std::byte{0xA8}, std::byte{0x01}, std::byte{0x01}, // 192.168.1.1
        std::byte{0x48}, std::byte{0x45}, std::byte{0x4C}, std::byte{0x4C}, // "HELL" 前置数据
        std::byte{0x4F}}; // "O"

    auto frame = yamux::build_syn(7, raw_payload);

    // 解析帧头验证
    const auto hdr = yamux::parse_header(frame.header);
    runner.Check(hdr.has_value(), "build_syn: header parse succeeded");

    if (hdr)
    {
        runner.Check(hdr->type == yamux::message_type::data,
                      "build_syn: type == data");
        runner.Check(hdr->flag == yamux::flags::syn,
                      "build_syn: flag == syn");
        runner.Check(hdr->stream_id == 7,
                      std::format("build_syn: stream_id == 7 (got {})", hdr->stream_id).c_str());
        runner.Check(hdr->length == 12,
                      std::format("build_syn: length == 12 (got {})", hdr->length).c_str());
    }

    // 验证载荷内容
    bool payload_match = (frame.payload.size() == raw_payload.size());
    if (payload_match)
    {
        for (std::size_t i = 0; i < raw_payload.size(); ++i)
        {
            if (frame.payload[i] != raw_payload[i])
            {
                payload_match = false;
                break;
            }
        }
    }
    runner.Check(payload_match, "build_syn: payload content matches");

    // 空载荷 SYN 帧
    auto empty_syn = yamux::build_syn(1, {});
    const auto empty_syn_hdr = yamux::parse_header(empty_syn.header);
    runner.Check(empty_syn_hdr.has_value(), "build_syn(empty): header parse succeeded");
    if (empty_syn_hdr)
    {
        runner.Check(empty_syn_hdr->flag == yamux::flags::syn,
                      "build_syn(empty): flag == syn");
        runner.Check(empty_syn_hdr->length == 0,
                      "build_syn(empty): length == 0");
    }

    runner.LogPass("YamuxCraftSynFrame");
}

/**
 * @brief 测试 build_fin() 编码正确性
 * @details 验证 FIN 标志位正确设置，stream_id 正确，
 * 帧头解析后 type==data、flag==fin、length==0（无载荷）。
 */
void TestYamuxCraftFinFrame(psm::testing::TestRunner &runner)
{
    namespace yamux = psm::multiplex::yamux;

    // 基础 FIN 帧测试
    auto fin_hdr_bytes = yamux::build_fin(99);
    const auto hdr = yamux::parse_header(fin_hdr_bytes);

    runner.Check(hdr.has_value(), "build_fin: header parse succeeded");

    if (hdr)
    {
        runner.Check(hdr->version == yamux::protocol_version,
                      "build_fin: version == 0");
        runner.Check(hdr->type == yamux::message_type::data,
                      "build_fin: type == data");
        runner.Check(hdr->flag == yamux::flags::fin,
                      "build_fin: flag == fin");
        runner.Check(hdr->stream_id == 99,
                      std::format("build_fin: stream_id == 99 (got {})", hdr->stream_id).c_str());
        runner.Check(hdr->length == 0,
                      std::format("build_fin: length == 0 (got {})", hdr->length).c_str());
    }

    // 不同 stream_id 的 FIN 帧
    auto fin2 = yamux::build_fin(1);
    const auto hdr2 = yamux::parse_header(fin2);
    runner.Check(hdr2.has_value(), "build_fin(1): header parse succeeded");
    if (hdr2)
    {
        runner.Check(hdr2->stream_id == 1,
                      "build_fin(1): stream_id == 1");
    }

    // 最大 stream_id 的 FIN 帧
    constexpr std::uint32_t max_sid = 0xFFFFFFFF;
    auto fin3 = yamux::build_fin(max_sid);
    const auto hdr3 = yamux::parse_header(fin3);
    runner.Check(hdr3.has_value(), "build_fin(max_sid): header parse succeeded");
    if (hdr3)
    {
        runner.Check(hdr3->stream_id == max_sid,
                      "build_fin(max_sid): stream_id == 0xFFFFFFFF");
    }

    // 验证 FIN 帧为大端字节序编码（stream_id=99 → 0x00000063）
    runner.Check(fin_hdr_bytes[4] == std::byte{0x00} &&
                  fin_hdr_bytes[5] == std::byte{0x00} &&
                  fin_hdr_bytes[6] == std::byte{0x00} &&
                  fin_hdr_bytes[7] == std::byte{0x63},
                  "build_fin: stream_id big-endian bytes correct");

    // 验证 FIN 帧长度恰好为 12 字节（无载荷）
    runner.Check(fin_hdr_bytes.size() == yamux::frame_hdrsize,
                  "build_fin: output size == frame_hdrsize (12)");

    runner.LogPass("YamuxCraftFinFrame");
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，运行 Data/SYN/FIN 帧构建测试，
 * 验证帧头编码、载荷传递、标志位设置和大端字节序。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    psm::testing::TestRunner runner("YamuxCraft");

    runner.LogInfo("Starting yamux craft tests...");

    TestYamuxCraftDataFrame(runner);
    TestYamuxCraftSynFrame(runner);
    TestYamuxCraftFinFrame(runner);

    runner.LogInfo("YamuxCraft tests completed.");

    return runner.Summary();
}
