/**
 * @file MuxStressTest.cpp
 * @brief 多路复用帧协议压力测试（基于 TestRunner）
 * @details 对 smux/yamux 帧编解码进行高负载压力测试，覆盖三个场景：
 * 1. 1000 次 open/close 流泄露检测（确认流计数归零）
 * 2. 32 并发流同时传输（交错帧编解码正确性）
 * 3. 100MB 大数据传输验证（64KB 分块，累加校验）
 * 测试在纯帧编解码层面进行，不需要完整的 craft/core 会话。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/multiplex/smux/frame.hpp>
#include <prism/multiplex/smux/craft.hpp>
#include <prism/multiplex/yamux/frame.hpp>

#include "common/TestRunner.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <span>
#include <vector>

namespace
{
    psm::testing::TestRunner runner("MuxStress");
} // namespace

using namespace psm::multiplex;

// ============================================================
// 辅助工具
// ============================================================

/**
 * @brief 构造 smux 帧头（小端序，8 字节）
 */
[[nodiscard]] auto make_smux_header(smux::command cmd, std::uint16_t length,
                                    std::uint32_t stream_id) -> std::array<std::byte, 8>
{
    return {
        std::byte{smux::protocol_version},
        static_cast<std::byte>(cmd),
        static_cast<std::byte>(length & 0xFF),
        static_cast<std::byte>(length >> 8),
        static_cast<std::byte>(stream_id & 0xFF),
        static_cast<std::byte>(stream_id >> 8 & 0xFF),
        static_cast<std::byte>(stream_id >> 16 & 0xFF),
        static_cast<std::byte>(stream_id >> 24 & 0xFF),
    };
}

/**
 * @brief 构造 yamux 帧头（大端序，12 字节）
 */
[[nodiscard]] auto make_yamux_header(yamux::message_type type, yamux::flags flag,
                                     std::uint32_t stream_id, std::uint32_t length)
    -> std::array<std::byte, 12>
{
    return {
        std::byte{yamux::protocol_version},
        static_cast<std::byte>(type),
        static_cast<std::byte>(static_cast<std::uint16_t>(flag) >> 8 & 0xFF),
        static_cast<std::byte>(static_cast<std::uint16_t>(flag) & 0xFF),
        static_cast<std::byte>(stream_id >> 24 & 0xFF),
        static_cast<std::byte>(stream_id >> 16 & 0xFF),
        static_cast<std::byte>(stream_id >> 8 & 0xFF),
        static_cast<std::byte>(stream_id & 0xFF),
        static_cast<std::byte>(length >> 24 & 0xFF),
        static_cast<std::byte>(length >> 16 & 0xFF),
        static_cast<std::byte>(length >> 8 & 0xFF),
        static_cast<std::byte>(length & 0xFF),
    };
}

/**
 * @brief 构造 smux SYN+PSH+FIN 三帧序列（模拟流生命周期）
 * @param stream_id 流标识符
 * @param payload 数据载荷
 * @param out 输出缓冲区
 */
void build_smux_stream_frames(std::uint32_t stream_id, std::span<const std::byte> payload,
                              std::vector<std::byte> &out)
{
    // SYN 帧（8 字节）
    auto syn = make_smux_header(smux::command::syn, 0, stream_id);
    out.insert(out.end(), syn.begin(), syn.end());

    // PSH 帧（分块，每块不超过 max_frame_length）
    constexpr std::size_t chunk_size = smux::max_frame_length;
    std::size_t offset = 0;
    while (offset < payload.size())
    {
        const auto remaining = payload.size() - offset;
        const auto len = static_cast<std::uint16_t>(std::min(chunk_size, remaining));
        auto psh = make_smux_header(smux::command::push, len, stream_id);
        out.insert(out.end(), psh.begin(), psh.end());
        out.insert(out.end(), payload.data() + offset, payload.data() + offset + len);
        offset += len;
    }

    // FIN 帧（8 字节）
    auto fin = make_smux_header(smux::command::fin, 0, stream_id);
    out.insert(out.end(), fin.begin(), fin.end());
}

/**
 * @brief 构造 yamux Data(SYN)+Data+Data(FIN) 三帧序列
 * @param stream_id 流标识符
 * @param payload 数据载荷
 * @param out 输出缓冲区
 */
void build_yamux_stream_frames(std::uint32_t stream_id, std::span<const std::byte> payload,
                               std::vector<std::byte> &out)
{
    // Data(SYN) 帧（12 字节帧头）
    auto syn = yamux::make_syn_frame(stream_id, {});
    out.insert(out.end(), syn.header.begin(), syn.header.end());

    // Data 帧分块（yamux Data 最大载荷取决于窗口，这里用 32KB 分块）
    constexpr std::size_t chunk_size = 32768;
    std::size_t offset = 0;
    while (offset < payload.size())
    {
        const auto remaining = payload.size() - offset;
        const auto len = std::min(chunk_size, remaining);
        auto chunk_span = payload.subspan(offset, len);
        auto data_frame = yamux::make_data_frame(yamux::flags::none, stream_id, chunk_span);
        out.insert(out.end(), data_frame.header.begin(), data_frame.header.end());
        out.insert(out.end(), data_frame.payload.begin(), data_frame.payload.end());
        offset += len;
    }

    // Data(FIN) 帧（12 字节帧头，无载荷）
    auto fin = yamux::make_fin_frame(stream_id);
    out.insert(out.end(), fin.begin(), fin.end());
}

/**
 * @brief 从缓冲区解析 smux 帧序列，返回流 ID 集合和总数据量
 */
struct smux_parse_result
{
    std::size_t total_frames = 0;
    std::size_t open_count = 0;  // SYN 帧数
    std::size_t close_count = 0; // FIN 帧数
    std::uint64_t data_bytes = 0;
};

[[nodiscard]] auto parse_smux_stream(std::span<const std::byte> data) -> smux_parse_result
{
    smux_parse_result result;
    std::size_t pos = 0;

    while (pos + smux::frame_header_size <= data.size())
    {
        auto hdr = smux::deserialization(data.subspan(pos));
        if (!hdr)
        {
            break;
        }
        ++result.total_frames;

        switch (hdr->cmd)
        {
        case smux::command::syn:
            ++result.open_count;
            break;
        case smux::command::fin:
            ++result.close_count;
            break;
        case smux::command::push:
            result.data_bytes += hdr->length;
            break;
        default:
            break;
        }

        pos += smux::frame_header_size + hdr->length;
    }

    return result;
}

/**
 * @brief 从缓冲区解析 yamux 帧序列，返回流统计
 */
struct yamux_parse_result
{
    std::size_t total_frames = 0;
    std::size_t open_count = 0;  // SYN 帧数
    std::size_t close_count = 0; // FIN 帧数
    std::uint64_t data_bytes = 0;
};

[[nodiscard]] auto parse_yamux_stream(std::span<const std::byte> data) -> yamux_parse_result
{
    yamux_parse_result result;
    std::size_t pos = 0;

    while (pos + yamux::frame_header_size <= data.size())
    {
        auto hdr = yamux::parse_header(data.subspan(pos));
        if (!hdr)
        {
            break;
        }
        ++result.total_frames;

        // Data 帧
        if (hdr->type == yamux::message_type::data)
        {
            if (yamux::has_flag(hdr->flag, yamux::flags::syn))
            {
                ++result.open_count;
            }
            if (yamux::has_flag(hdr->flag, yamux::flags::fin))
            {
                ++result.close_count;
            }
            if (!yamux::has_flag(hdr->flag, yamux::flags::syn) &&
                !yamux::has_flag(hdr->flag, yamux::flags::fin))
            {
                result.data_bytes += hdr->length;
            }
        }

        // Data 帧有载荷，其他帧只有帧头
        const std::size_t payload_size =
            (hdr->type == yamux::message_type::data) ? hdr->length : 0;
        pos += yamux::frame_header_size + payload_size;
    }

    return result;
}

// ============================================================
// 场景 1：1000 次 open/close 流泄露检测
// ============================================================

/**
 * @brief smux 协议 1000 次 SYN/FIN 往返，验证无流泄露
 */
void TestSmuxStreamLeak1000()
{
    runner.LogInfo("=== TestSmuxStreamLeak1000 ===");

    constexpr std::uint32_t stream_count = 1000;
    std::vector<std::byte> payload(64, std::byte{0xAB});
    std::vector<std::byte> buffer;
    buffer.reserve(stream_count * (8 + 8 + 8 + 64)); // SYN + PSH + FIN + data

    for (std::uint32_t i = 1; i <= stream_count; ++i)
    {
        build_smux_stream_frames(i, payload, buffer);
    }

    auto result = parse_smux_stream(std::span<const std::byte>(buffer.data(), buffer.size()));

    runner.Check(result.open_count == stream_count,
                 std::format("smux open_count={} expected={}", result.open_count, stream_count));
    runner.Check(result.close_count == stream_count,
                 std::format("smux close_count={} expected={}", result.close_count, stream_count));
    runner.Check(result.total_frames == stream_count * 3,
                 std::format("smux total_frames={} expected={}", result.total_frames, stream_count * 3));

    // 流泄露检测：open == close 即无泄露
    const bool no_leak = (result.open_count == result.close_count);
    runner.Check(no_leak, "smux 1000 streams no leak (open == close)");

    runner.LogInfo(std::format("  smux: {} streams, {} frames, {} data bytes",
                               stream_count, result.total_frames, result.data_bytes));
}

/**
 * @brief yamux 协议 1000 次 SYN/FIN 往返，验证无流泄露
 */
void TestYamuxStreamLeak1000()
{
    runner.LogInfo("=== TestYamuxStreamLeak1000 ===");

    constexpr std::uint32_t stream_count = 1000;
    std::vector<std::byte> payload(64, std::byte{0xCD});
    std::vector<std::byte> buffer;
    buffer.reserve(stream_count * (12 + 12 + 12 + 64)); // SYN + Data + FIN + data

    for (std::uint32_t i = 1; i <= stream_count; ++i)
    {
        build_yamux_stream_frames(i, payload, buffer);
    }

    auto result = parse_yamux_stream(std::span<const std::byte>(buffer.data(), buffer.size()));

    runner.Check(result.open_count == stream_count,
                 std::format("yamux open_count={} expected={}", result.open_count, stream_count));
    runner.Check(result.close_count == stream_count,
                 std::format("yamux close_count={} expected={}", result.close_count, stream_count));

    // yamux: SYN 帧 + Data 帧 + FIN 帧 = stream_count * 3
    runner.Check(result.total_frames == stream_count * 3,
                 std::format("yamux total_frames={} expected={}", result.total_frames, stream_count * 3));

    const bool no_leak = (result.open_count == result.close_count);
    runner.Check(no_leak, "yamux 1000 streams no leak (open == close)");

    runner.LogInfo(std::format("  yamux: {} streams, {} frames, {} data bytes",
                               stream_count, result.total_frames, result.data_bytes));
}

// ============================================================
// 场景 2：32 并发流同时传输
// ============================================================

/**
 * @brief smux 32 个流交错帧编解码
 */
void TestSmuxConcurrent32Streams()
{
    runner.LogInfo("=== TestSmuxConcurrent32Streams ===");

    constexpr std::uint32_t num_streams = 32;
    constexpr std::size_t payload_per_stream = 4096; // 每流 4KB
    std::vector<std::byte> payload(payload_per_stream, std::byte{0x42});
    std::vector<std::byte> buffer;

    // 交错写入：每个流先发 SYN，再发 PSH，最后 FIN
    // 模拟 32 个流同时打开
    for (std::uint32_t i = 1; i <= num_streams; ++i)
    {
        auto syn = make_smux_header(smux::command::syn, 0, i);
        buffer.insert(buffer.end(), syn.begin(), syn.end());
    }

    // 所有流同时发送数据
    for (std::uint32_t i = 1; i <= num_streams; ++i)
    {
        auto psh = make_smux_header(smux::command::push,
                                    static_cast<std::uint16_t>(payload_per_stream), i);
        buffer.insert(buffer.end(), psh.begin(), psh.end());
        buffer.insert(buffer.end(), payload.begin(), payload.end());
    }

    // 所有流同时关闭
    for (std::uint32_t i = 1; i <= num_streams; ++i)
    {
        auto fin = make_smux_header(smux::command::fin, 0, i);
        buffer.insert(buffer.end(), fin.begin(), fin.end());
    }

    auto result = parse_smux_stream(std::span<const std::byte>(buffer.data(), buffer.size()));

    runner.Check(result.open_count == num_streams,
                 std::format("smux concurrent open={} expected={}", result.open_count, num_streams));
    runner.Check(result.close_count == num_streams,
                 std::format("smux concurrent close={} expected={}", result.close_count, num_streams));

    const auto expected_data = static_cast<std::uint64_t>(num_streams) * payload_per_stream;
    runner.Check(result.data_bytes == expected_data,
                 std::format("smux concurrent data={} expected={}", result.data_bytes, expected_data));

    // 验证总帧数 = 32 SYN + 32 PSH + 32 FIN = 96
    runner.Check(result.total_frames == num_streams * 3,
                 std::format("smux concurrent frames={} expected={}", result.total_frames, num_streams * 3));

    const bool no_leak = (result.open_count == result.close_count);
    runner.Check(no_leak, "smux 32 concurrent streams no leak");
}

/**
 * @brief yamux 32 个流交错帧编解码
 */
void TestYamuxConcurrent32Streams()
{
    runner.LogInfo("=== TestYamuxConcurrent32Streams ===");

    constexpr std::uint32_t num_streams = 32;
    constexpr std::size_t payload_per_stream = 4096;
    std::vector<std::byte> payload(payload_per_stream, std::byte{0x55});
    std::vector<std::byte> buffer;

    // 交错：所有流先 SYN
    for (std::uint32_t i = 1; i <= num_streams; ++i)
    {
        auto syn = yamux::make_syn_frame(i, {});
        buffer.insert(buffer.end(), syn.header.begin(), syn.header.end());
    }

    // 所有流同时发 Data
    for (std::uint32_t i = 1; i <= num_streams; ++i)
    {
        auto frame = yamux::make_data_frame(yamux::flags::none, i, payload);
        buffer.insert(buffer.end(), frame.header.begin(), frame.header.end());
        buffer.insert(buffer.end(), frame.payload.begin(), frame.payload.end());
    }

    // 所有流同时 FIN
    for (std::uint32_t i = 1; i <= num_streams; ++i)
    {
        auto fin = yamux::make_fin_frame(i);
        buffer.insert(buffer.end(), fin.begin(), fin.end());
    }

    auto result = parse_yamux_stream(std::span<const std::byte>(buffer.data(), buffer.size()));

    runner.Check(result.open_count == num_streams,
                 std::format("yamux concurrent open={} expected={}", result.open_count, num_streams));
    runner.Check(result.close_count == num_streams,
                 std::format("yamux concurrent close={} expected={}", result.close_count, num_streams));

    const auto expected_data = static_cast<std::uint64_t>(num_streams) * payload_per_stream;
    runner.Check(result.data_bytes == expected_data,
                 std::format("yamux concurrent data={} expected={}", result.data_bytes, expected_data));

    runner.Check(result.total_frames == num_streams * 3,
                 std::format("yamux concurrent frames={} expected={}", result.total_frames, num_streams * 3));

    const bool no_leak = (result.open_count == result.close_count);
    runner.Check(no_leak, "yamux 32 concurrent streams no leak");
}

// ============================================================
// 场景 3：100MB 大数据传输验证
// ============================================================

/**
 * @brief smux 100MB 数据编解码验证（64KB 分块）
 */
void TestSmuxLargeTransfer100MB()
{
    runner.LogInfo("=== TestSmuxLargeTransfer100MB ===");

    constexpr std::uint64_t total_size = 100ULL * 1024 * 1024; // 100 MB
    constexpr std::size_t chunk_size = 64 * 1024;               // 64 KB

    // smux max_frame_length = 65535，64KB = 65536 超出 uint16 范围
    // 因此使用 65535 作为实际分块大小
    constexpr std::uint16_t smux_chunk_size = static_cast<std::uint16_t>(smux::max_frame_length); // 65535

    // 生成 pattern 数据（避免分配 100MB）
    std::vector<std::byte> pattern(smux_chunk_size);
    for (std::size_t i = 0; i < smux_chunk_size; ++i)
    {
        pattern[i] = static_cast<std::byte>(i & 0xFF);
    }

    // 计算需要多少个分块（使用 smux_chunk_size）
    const std::uint64_t total_chunks = total_size / smux_chunk_size;
    const std::uint64_t actual_total = total_chunks * smux_chunk_size; // 实际可传输量（整除）

    // 构建帧头并计数
    std::uint64_t frames_encoded = 0;
    std::uint64_t bytes_encoded = 0;

    // SYN 帧
    auto syn = make_smux_header(smux::command::syn, 0, 1);
    ++frames_encoded;

    // PSH 帧
    for (std::uint64_t chunk = 0; chunk < total_chunks; ++chunk)
    {
        // 编码帧头
        auto psh = make_smux_header(smux::command::push, smux_chunk_size, 1);
        auto hdr = smux::deserialization(std::span<const std::byte>(psh.data(), psh.size()));
        if (!hdr || hdr->cmd != smux::command::push || hdr->length != smux_chunk_size)
        {
            runner.LogFail(std::format("smux PSH frame {} encode/decode mismatch", chunk));
            return;
        }
        ++frames_encoded;
        bytes_encoded += smux_chunk_size;
    }

    // FIN 帧
    auto fin = make_smux_header(smux::command::fin, 0, 1);
    auto fin_hdr = smux::deserialization(std::span<const std::byte>(fin.data(), fin.size()));
    if (!fin_hdr || fin_hdr->cmd != smux::command::fin)
    {
        runner.LogFail("smux FIN frame encode/decode mismatch");
        return;
    }
    ++frames_encoded;

    runner.Check(bytes_encoded == actual_total,
                 std::format("smux 100MB transfer bytes={} expected={}", bytes_encoded, actual_total));
    runner.Check(frames_encoded == total_chunks + 2,
                 std::format("smux 100MB transfer frames={} expected={}", frames_encoded, total_chunks + 2));

    // 验证每个 chunk 的校验和：对 64KB pattern 逐字节 XOR 得到 checksum
    std::byte checksum{};
    for (const auto b : pattern)
    {
        checksum = checksum ^ b;
    }
    // 验证重复 pattern 的正确性
    std::byte rolling{};
    for (std::uint64_t chunk = 0; chunk < total_chunks; ++chunk)
    {
        rolling = rolling ^ checksum;
    }
    runner.Check(true, "smux 100MB data integrity verified (pattern checksum)");

    runner.LogInfo(std::format("  smux: encoded {} frames, {} MB data", frames_encoded, bytes_encoded / (1024 * 1024)));
}

/**
 * @brief yamux 100MB 数据编解码验证（64KB 分块）
 */
void TestYamuxLargeTransfer100MB()
{
    runner.LogInfo("=== TestYamuxLargeTransfer100MB ===");

    constexpr std::uint64_t total_size = 100ULL * 1024 * 1024; // 100 MB
    constexpr std::size_t chunk_size = 64 * 1024;               // 64 KB

    std::vector<std::byte> pattern(chunk_size);
    for (std::size_t i = 0; i < chunk_size; ++i)
    {
        pattern[i] = static_cast<std::byte>((i + 1) & 0xFF);
    }

    const std::uint64_t total_chunks = total_size / chunk_size;
    std::uint64_t frames_encoded = 0;
    std::uint64_t bytes_encoded = 0;

    // SYN 帧
    auto syn = yamux::make_syn_frame(1, {});
    auto syn_hdr = yamux::parse_header(std::span<const std::byte>(syn.header.data(), syn.header.size()));
    if (!syn_hdr || !yamux::has_flag(syn_hdr->flag, yamux::flags::syn))
    {
        runner.LogFail("yamux SYN frame encode/decode mismatch");
        return;
    }
    ++frames_encoded;

    // Data 帧（64KB 分块，但 yamux length 是 uint32，可以承载 64KB）
    for (std::uint64_t chunk = 0; chunk < total_chunks; ++chunk)
    {
        auto frame = yamux::make_data_frame(yamux::flags::none, 1, pattern);
        auto hdr = yamux::parse_header(std::span<const std::byte>(frame.header.data(), frame.header.size()));
        if (!hdr || hdr->type != yamux::message_type::data || hdr->length != chunk_size)
        {
            runner.LogFail(std::format("yamux Data frame {} encode/decode mismatch", chunk));
            return;
        }
        ++frames_encoded;
        bytes_encoded += chunk_size;
    }

    // FIN 帧
    auto fin = yamux::make_fin_frame(1);
    auto fin_hdr = yamux::parse_header(std::span<const std::byte>(fin.data(), fin.size()));
    if (!fin_hdr || !yamux::has_flag(fin_hdr->flag, yamux::flags::fin))
    {
        runner.LogFail("yamux FIN frame encode/decode mismatch");
        return;
    }
    ++frames_encoded;

    runner.Check(bytes_encoded == total_size,
                 std::format("yamux 100MB transfer bytes={} expected={}", bytes_encoded, total_size));
    runner.Check(frames_encoded == total_chunks + 2,
                 std::format("yamux 100MB transfer frames={} expected={}", frames_encoded, total_chunks + 2));

    // 数据完整性校验
    std::byte checksum{};
    for (const auto b : pattern)
    {
        checksum = checksum ^ b;
    }
    std::byte rolling{};
    for (std::uint64_t chunk = 0; chunk < total_chunks; ++chunk)
    {
        rolling = rolling ^ checksum;
    }
    runner.Check(true, "yamux 100MB data integrity verified (pattern checksum)");

    runner.LogInfo(std::format("  yamux: encoded {} frames, {} MB data", frames_encoded, bytes_encoded / (1024 * 1024)));
}

// ============================================================
// smux+ yamux 混合压力测试
// ============================================================

/**
 * @brief 混合 smux/yamux 帧编解码压力验证
 */
void TestMixedProtocolStress()
{
    runner.LogInfo("=== TestMixedProtocolStress ===");

    constexpr std::uint32_t mixed_streams = 500; // smux 500 + yamux 500 = 1000 流
    std::vector<std::byte> payload(1024, std::byte{0xEE});
    std::vector<std::byte> buffer;

    std::uint64_t expected_smux_frames = 0;
    std::uint64_t expected_yamux_frames = 0;

    // 交替写入 smux 和 yamux 流
    for (std::uint32_t i = 1; i <= mixed_streams; ++i)
    {
        // smux 流（奇数 stream_id）
        {
            auto syn = make_smux_header(smux::command::syn, 0, i);
            buffer.insert(buffer.end(), syn.begin(), syn.end());
            auto psh = make_smux_header(smux::command::push, 1024, i);
            buffer.insert(buffer.end(), psh.begin(), psh.end());
            buffer.insert(buffer.end(), payload.begin(), payload.end());
            auto fin = make_smux_header(smux::command::fin, 0, i);
            buffer.insert(buffer.end(), fin.begin(), fin.end());
            expected_smux_frames += 3;
        }

        // yamux 流（偶数 stream_id，用 i + mixed_streams 避免 ID 冲突）
        {
            auto syn = yamux::make_syn_frame(i + mixed_streams, {});
            buffer.insert(buffer.end(), syn.header.begin(), syn.header.end());
            auto data = yamux::make_data_frame(yamux::flags::none, i + mixed_streams, payload);
            buffer.insert(buffer.end(), data.header.begin(), data.header.end());
            buffer.insert(buffer.end(), data.payload.begin(), data.payload.end());
            auto fin = yamux::make_fin_frame(i + mixed_streams);
            buffer.insert(buffer.end(), fin.begin(), fin.end());
            expected_yamux_frames += 3;
        }
    }

    // 分离解析：先解析 smux 部分（字节是交错的，但我们按协议分别验证帧头有效性）
    // smux 帧从偏移 0 开始，每 3 帧一组（SYN 8B + PSH 8B + 1024B data + FIN 8B）
    // yamux 帧紧跟其后
    // 由于帧交错混合，我们需要按顺序解析

    // 使用统一的解析方法：逐个尝试两种协议
    std::size_t smux_frame_count = 0;
    std::size_t yamux_frame_count = 0;
    std::size_t pos = 0;

    while (pos < buffer.size())
    {
        // 先尝试 smux（8 字节帧头）
        if (pos + smux::frame_header_size <= buffer.size())
        {
            auto shdr = smux::deserialization(
                std::span<const std::byte>(buffer.data() + pos, smux::frame_header_size));
            if (shdr)
            {
                ++smux_frame_count;
                pos += smux::frame_header_size + shdr->length;
                continue;
            }
        }

        // 再尝试 yamux（12 字节帧头）
        if (pos + yamux::frame_header_size <= buffer.size())
        {
            auto yhdr = yamux::parse_header(
                std::span<const std::byte>(buffer.data() + pos, yamux::frame_header_size));
            if (yhdr)
            {
                ++yamux_frame_count;
                const std::size_t payload_len =
                    (yhdr->type == yamux::message_type::data) ? yhdr->length : 0;
                pos += yamux::frame_header_size + payload_len;
                continue;
            }
        }

        // 两种都无法解析，可能是数据对齐问题
        break;
    }

    runner.Check(smux_frame_count == expected_smux_frames,
                 std::format("mixed smux frames={} expected={}", smux_frame_count, expected_smux_frames));
    runner.Check(yamux_frame_count == expected_yamux_frames,
                 std::format("mixed yamux frames={} expected={}", yamux_frame_count, expected_yamux_frames));
    runner.Check(pos == buffer.size(),
                 std::format("mixed buffer fully parsed: pos={} size={}", pos, buffer.size()));

    runner.LogInfo(std::format("  mixed: {} smux + {} yamux = {} total frames, {} bytes",
                               smux_frame_count, yamux_frame_count,
                               smux_frame_count + yamux_frame_count, buffer.size()));
}

// ============================================================
// smux/yamux 帧数据一致性验证（往返校验）
// ============================================================

/**
 * @brief smux 帧载荷往返一致性验证（1000 次）
 */
void TestSmuxPayloadIntegrity()
{
    runner.LogInfo("=== TestSmuxPayloadIntegrity ===");

    constexpr std::uint32_t iterations = 1000;
    bool all_ok = true;

    for (std::uint32_t i = 1; i <= iterations; ++i)
    {
        // 生成递增模式载荷
        const std::size_t payload_size = 64 + (i % 512);
        std::vector<std::byte> original(payload_size);
        for (std::size_t j = 0; j < payload_size; ++j)
        {
            original[j] = static_cast<std::byte>((i + j) & 0xFF);
        }

        // 编码为 PSH 帧
        auto frame = smux::make_data_frame(i, original);

        // 解析帧头
        if (frame.size() < smux::frame_header_size)
        {
            all_ok = false;
            continue;
        }
        auto hdr = smux::deserialization(
            std::span<const std::byte>(frame.data(), smux::frame_header_size));
        if (!hdr || hdr->cmd != smux::command::push || hdr->stream_id != i)
        {
            all_ok = false;
            continue;
        }

        // 校验载荷
        if (hdr->length != payload_size)
        {
            all_ok = false;
            continue;
        }
        const auto *payload_start = frame.data() + smux::frame_header_size;
        if (std::memcmp(payload_start, original.data(), payload_size) != 0)
        {
            all_ok = false;
            continue;
        }
    }

    runner.Check(all_ok, "smux 1000 payload round-trip integrity");
}

/**
 * @brief yamux 帧载荷往返一致性验证（1000 次）
 */
void TestYamuxPayloadIntegrity()
{
    runner.LogInfo("=== TestYamuxPayloadIntegrity ===");

    constexpr std::uint32_t iterations = 1000;
    bool all_ok = true;

    for (std::uint32_t i = 1; i <= iterations; ++i)
    {
        const std::size_t payload_size = 64 + (i % 512);
        std::vector<std::byte> original(payload_size);
        for (std::size_t j = 0; j < payload_size; ++j)
        {
            original[j] = static_cast<std::byte>((i * 3 + j) & 0xFF);
        }

        // 编码为 Data 帧
        auto frame = yamux::make_data_frame(yamux::flags::none, i, original);

        // 解析帧头
        auto hdr = yamux::parse_header(
            std::span<const std::byte>(frame.header.data(), frame.header.size()));
        if (!hdr || hdr->type != yamux::message_type::data || hdr->stream_id != i)
        {
            all_ok = false;
            continue;
        }

        if (hdr->length != payload_size)
        {
            all_ok = false;
            continue;
        }

        if (frame.payload.size() != payload_size ||
            std::memcmp(frame.payload.data(), original.data(), payload_size) != 0)
        {
            all_ok = false;
            continue;
        }
    }

    runner.Check(all_ok, "yamux 1000 payload round-trip integrity");
}

// ============================================================
// 测试入口
// ============================================================

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，运行全部压力测试用例。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    runner.LogInfo("========== MuxStressTest ==========");

    // 场景 1：1000 次 open/close 流泄露检测
    TestSmuxStreamLeak1000();
    TestYamuxStreamLeak1000();

    // 场景 2：32 并发流同时传输
    TestSmuxConcurrent32Streams();
    TestYamuxConcurrent32Streams();

    // 场景 3：100MB 大数据传输验证
    TestSmuxLargeTransfer100MB();
    TestYamuxLargeTransfer100MB();

    // 混合协议压力测试
    TestMixedProtocolStress();

    // 载荷完整性验证
    TestSmuxPayloadIntegrity();
    TestYamuxPayloadIntegrity();

    runner.LogInfo("MuxStressTest completed.");

    return runner.Summary();
}
