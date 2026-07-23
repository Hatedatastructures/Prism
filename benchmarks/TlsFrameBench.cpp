/**
 * @file TlsFrameBench.cpp
 * @brief TLS 记录层序列化原语基准测试
 * @details 测量 TLS 记录帧操作性能：
 *          write_u8/u16/u24 写入原语、record 序列化与构建、
 *          ClientHello 解析与特征转换。
 *          这些操作在每次 TLS 读写时被调用。
 */

#include <benchmark/benchmark.h>
#include <prism/foundation/memory/container.hpp>
#include <prism/protocol/tls/hello.hpp>
#include <prism/protocol/tls/record.hpp>
#include <prism/protocol/tls/types.hpp>

#include <cstdint>

namespace
{

// ============================================================
// 测试数据：最小合法 ClientHello 字节流
// ============================================================

/**
 * @brief 构造最小合法 ClientHello 字节流
 * @details 布局：
 *   TLS record header  (5):  16 03 01 00 2F
 *   Handshake type     (1):  01
 *   Handshake length   (3):  00 00 2A
 *   ClientVersion      (2):  03 03
 *   Random            (32):  全零
 *   session_id_len     (1):  00
 *   cipher_suites_len  (2):  00 02
 *   cipher_suite       (2):  13 01  (TLS_AES_128_GCM_SHA256)
 *   comp_methods_len   (1):  01
 *   comp_method        (1):  00
 *   extensions_len     (2):  00 00
 * 总计 52 字节
 */
auto make_minimal_ch() -> psm::memory::vector<std::uint8_t>
{
    psm::memory::vector<std::uint8_t> buf;

    // TLS record header
    buf.push_back(0x16); // content_type = handshake
    buf.push_back(0x03); // version high
    buf.push_back(0x01); // version low
    buf.push_back(0x00); // length high
    buf.push_back(0x2F); // length low  (47 字节载荷)

    // Handshake header
    buf.push_back(0x01); // ClientHello
    buf.push_back(0x00); // length byte 0
    buf.push_back(0x00); // length byte 1
    buf.push_back(0x2A); // length byte 2 (42 字节)

    // ClientVersion
    buf.push_back(0x03);
    buf.push_back(0x03);

    // Random (32 字节全零)
    for (int i = 0; i < 32; ++i)
    {
        buf.push_back(0x00);
    }

    // session_id_len = 0
    buf.push_back(0x00);

    // cipher_suites: 长度 2, 一个套件 TLS_AES_128_GCM_SHA256
    buf.push_back(0x00);
    buf.push_back(0x02);
    buf.push_back(0x13);
    buf.push_back(0x01);

    // compression_methods: 长度 1, null
    buf.push_back(0x01);
    buf.push_back(0x00);

    // extensions_len = 0
    buf.push_back(0x00);
    buf.push_back(0x00);

    return buf;
}

const auto g_ch_bytes = make_minimal_ch();

/// 预构建 record 对象，用于 from(record) 测试
auto make_ch_record() -> psm::tls::record
{
    auto payload_span = std::span<const std::byte>(
        reinterpret_cast<const std::byte *>(g_ch_bytes.data() + psm::protocol::tls::RECORD_HDR_LEN),
        g_ch_bytes.size() - psm::protocol::tls::RECORD_HDR_LEN);

    return psm::tls::record::builder{}
        .type(psm::protocol::tls::CT_HANDSHAKE)
        .version(0x0301)
        .payload(payload_span)
        .build();
}

const auto g_ch_record = make_ch_record();

/// 预构建含 payload 的 record 用于序列化测试
auto make_test_record() -> psm::tls::record
{
    // 构造 64 字节载荷
    psm::memory::vector<std::byte> payload(64, std::byte{0xAB});
    auto span = std::span<const std::byte>(payload.data(), payload.size());
    return psm::tls::record::builder{}
        .type(psm::protocol::tls::CT_APPLICATION_DATA)
        .version(psm::protocol::tls::VERSION_TLS12)
        .payload(span)
        .build();
}

const auto g_test_record = make_test_record();

/// 短数据（< 44 字节），from_bytes 应返回 recorderr
const psm::memory::vector<std::uint8_t> g_short_data = {0x16, 0x03, 0x01};

/// 非 ClientHello 类型（content_type = application_data）
auto make_invalid_type_bytes() -> psm::memory::vector<std::uint8_t>
{
    auto bytes = g_ch_bytes;
    bytes[0] = psm::protocol::tls::CT_APPLICATION_DATA; // 0x17
    return bytes;
}

const auto g_invalid_type_bytes = make_invalid_type_bytes();

// ============================================================
// 1. write_u8 写入原语
// ============================================================

/// @brief 测量 TLS 记录层 write_u8 写入原语性能
void BM_TlsFrame_WriteU8(benchmark::State &state)
{
    for (auto _ : state)
    {
        psm::memory::vector<std::uint8_t> buf;
        buf.reserve(1);
        psm::protocol::tls::write_u8(buf, 0x16);
        benchmark::DoNotOptimize(buf.data());
    }
}
BENCHMARK(BM_TlsFrame_WriteU8);

// ============================================================
// 2. write_u16 写入原语
// ============================================================

/// @brief 测量 TLS 记录层 write_u16 写入原语性能
void BM_TlsFrame_WriteU16(benchmark::State &state)
{
    for (auto _ : state)
    {
        psm::memory::vector<std::uint8_t> buf;
        buf.reserve(2);
        psm::protocol::tls::write_u16(buf, 0x0303);
        benchmark::DoNotOptimize(buf.data());
    }
}
BENCHMARK(BM_TlsFrame_WriteU16);

// ============================================================
// 3. write_u24 写入原语
// ============================================================

/// @brief 测量 TLS 记录层 write_u24 写入原语性能
void BM_TlsFrame_WriteU24(benchmark::State &state)
{
    for (auto _ : state)
    {
        psm::memory::vector<std::uint8_t> buf;
        buf.reserve(3);
        psm::protocol::tls::write_u24(buf, 0x000100);
        benchmark::DoNotOptimize(buf.data());
    }
}
BENCHMARK(BM_TlsFrame_WriteU24);

// ============================================================
// 4. record::serialize()
// ============================================================

/// @brief 测量 TLS record 序列化为字节流性能
void BM_TlsFrame_RecordSerialize(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto bytes = g_test_record.serialize();
        benchmark::DoNotOptimize(bytes.data());
    }
}
BENCHMARK(BM_TlsFrame_RecordSerialize);

// ============================================================
// 5. builder 链式构建
// ============================================================

/// @brief 测量 TLS record builder 链式构建性能
void BM_TlsFrame_RecordBuilderBuild(benchmark::State &state)
{
    const psm::memory::vector<std::byte> payload(64, std::byte{0xAB});
    const auto span = std::span<const std::byte>(payload.data(), payload.size());

    for (auto _ : state)
    {
        auto rec = psm::tls::record::builder{}
                       .type(psm::protocol::tls::CT_APPLICATION_DATA)
                       .version(psm::protocol::tls::VERSION_TLS12)
                       .payload(span)
                       .build();
        benchmark::DoNotOptimize(rec.size());
    }
}
BENCHMARK(BM_TlsFrame_RecordBuilderBuild);

// ============================================================
// 6. header()/payload()/size() 访问器
// ============================================================

/// @brief 测量 TLS record 访问器（header/payload/size）性能
void BM_TlsFrame_RecordAccess(benchmark::State &state)
{
    for (auto _ : state)
    {
        const auto &hdr = g_test_record.header();
        const auto pl = g_test_record.payload();
        const auto sz = g_test_record.size();
        benchmark::DoNotOptimize(hdr.content_type);
        benchmark::DoNotOptimize(pl.data());
        benchmark::DoNotOptimize(sz);
    }
}
BENCHMARK(BM_TlsFrame_RecordAccess);

// ============================================================
// 7. client_hello::from_bytes() 解析
// ============================================================

/// @brief 测量 ClientHello 字节流解析性能
void BM_TlsFrame_ChParse(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto [code, ch] = psm::tls::client_hello::from_bytes(g_ch_bytes);
        benchmark::DoNotOptimize(code);
    }
}
BENCHMARK(BM_TlsFrame_ChParse);

// ============================================================
// 8. client_hello::from(record) 解析
// ============================================================

/// @brief 测量 ClientHello 从 record 对象解析性能
void BM_TlsFrame_ChFromRecord(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto [code, ch] = psm::tls::client_hello::from(g_ch_record);
        benchmark::DoNotOptimize(code);
    }
}
BENCHMARK(BM_TlsFrame_ChFromRecord);

// ============================================================
// 9. to_features() 转换
// ============================================================

/// @brief 测量 ClientHello 特征转换性能
void BM_TlsFrame_ChToFeatures(benchmark::State &state)
{
    auto [code, ch] = psm::tls::client_hello::from_bytes(g_ch_bytes);

    for (auto _ : state)
    {
        auto feat = ch.to_features();
        benchmark::DoNotOptimize(feat.server_name.data());
    }
}
BENCHMARK(BM_TlsFrame_ChToFeatures);

// ============================================================
// 10. from_bytes -> to_features 完整管道
// ============================================================

/// @brief 测量 ClientHello 解析到特征转换完整管道性能
void BM_TlsFrame_ChRoundtrip(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto [code, ch] = psm::tls::client_hello::from_bytes(g_ch_bytes);
        auto feat = ch.to_features();
        benchmark::DoNotOptimize(feat.server_name.data());
    }
}
BENCHMARK(BM_TlsFrame_ChRoundtrip);

// ============================================================
// 11. 多种 content_type 批量序列化
// ============================================================

/// @brief 测量多种 content_type 批量 TLS record 序列化性能
void BM_TlsFrame_RecordSerializeBatch(benchmark::State &state)
{
    const psm::memory::vector<std::byte> payload(32, std::byte{0x42});
    const auto span = std::span<const std::byte>(payload.data(), payload.size());

    const std::uint8_t types[] = {
        psm::protocol::tls::CT_CHANGE_CIPHER_SPEC,
        psm::protocol::tls::CT_ALERT,
        psm::protocol::tls::CT_HANDSHAKE,
        psm::protocol::tls::CT_APPLICATION_DATA,
    };

    for (auto _ : state)
    {
        for (const auto t : types)
        {
            auto rec = psm::tls::record::builder{}
                           .type(t)
                           .version(psm::protocol::tls::VERSION_TLS12)
                           .payload(span)
                           .build();
            auto bytes = rec.serialize();
            benchmark::DoNotOptimize(bytes.data());
        }
    }
}
BENCHMARK(BM_TlsFrame_RecordSerializeBatch);

// ============================================================
// 12. 短数据非法输入
// ============================================================

/// @brief 测量短数据非法输入的 ClientHello 解析性能
void BM_TlsFrame_ChParse_InvalidShort(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto [code, ch] = psm::tls::client_hello::from_bytes(g_short_data);
        benchmark::DoNotOptimize(code);
    }
}
BENCHMARK(BM_TlsFrame_ChParse_InvalidShort);

// ============================================================
// 13. 非 ClientHello 类型非法输入
// ============================================================

/// @brief 测量非 ClientHello 类型非法输入的解析性能
void BM_TlsFrame_ChParse_InvalidType(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto [code, ch] = psm::tls::client_hello::from_bytes(g_invalid_type_bytes);
        benchmark::DoNotOptimize(code);
    }
}
BENCHMARK(BM_TlsFrame_ChParse_InvalidType);

// ============================================================
// 14. 循环内 100 次 write_u16
// ============================================================

/// @brief 测量连续 100 次 write_u16 吞吐量
void BM_TlsFrame_WriteU16_Repeated(benchmark::State &state)
{
    for (auto _ : state)
    {
        psm::memory::vector<std::uint8_t> buf;
        buf.reserve(200);
        for (int i = 0; i < 100; ++i)
        {
            psm::protocol::tls::write_u16(buf, static_cast<std::uint16_t>(i));
        }
        benchmark::DoNotOptimize(buf.data());
    }
}
BENCHMARK(BM_TlsFrame_WriteU16_Repeated);

// ============================================================
// 15. 循环内 100 次 write_u24
// ============================================================

/// @brief 测量连续 100 次 write_u24 吞吐量
void BM_TlsFrame_WriteU24_Repeated(benchmark::State &state)
{
    for (auto _ : state)
    {
        psm::memory::vector<std::uint8_t> buf;
        buf.reserve(300);
        for (int i = 0; i < 100; ++i)
        {
            psm::protocol::tls::write_u24(buf, static_cast<std::size_t>(i * 65536));
        }
        benchmark::DoNotOptimize(buf.data());
    }
}
BENCHMARK(BM_TlsFrame_WriteU24_Repeated);

} // namespace

BENCHMARK_MAIN();
