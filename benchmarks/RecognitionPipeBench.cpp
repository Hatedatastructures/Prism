/**
 * @file RecognitionPipeBench.cpp
 * @brief 识别管道辅助操作基准测试
 * @details 测量协议识别管道中辅助操作的性能：
 *          TLS 特征位图构建与查询（build_bitmap, has_feature, has_all）、
 *          目标地址解析（parse, resolve）。
 *          特征位图在每次 TLS ClientHello 分析时构建，
 *          目标地址解析在每条新连接的协议处理阶段调用。
 */

#include <benchmark/benchmark.h>
#include <prism/stealth/recognition/tls/features.hpp>
#include <prism/stealth/recognition/target.hpp>
#include <prism/foundation/memory/container.hpp>

#include <cstdint>
#include <string>
#include <string_view>

namespace
{

namespace rectls = psm::recognition::tls;
namespace rec = psm::recognition;
namespace mem = psm::memory;

// ============================================================
// 测试数据
// ============================================================

/// 全特征：server_name + x25519 + 32 字节 session_id + reality 标记 + alpn + versions
auto make_feat_full() -> rectls::hello_features
{
    rectls::hello_features f;
    f.server_name = mem::string("www.example.com");
    f.has_x25519 = true;
    f.session_id_len = 32;
    f.session_id.resize(32, 0x01);
    f.session_id[0] = 0x01;
    f.session_id[1] = 0x08;
    f.session_id[2] = 0x02;
    f.has_alpn = true;
    f.versions.push_back(0x0304);
    f.versions.push_back(0x0303);
    return f;
}

/// 最小特征：仅 server_name
auto make_feat_minimal() -> rectls::hello_features
{
    rectls::hello_features f;
    f.server_name = mem::string("test.com");
    return f;
}

/// 丰富特征：所有 bool 字段为 true
auto make_feat_rich() -> rectls::hello_features
{
    rectls::hello_features f;
    f.server_name = mem::string("rich.example.com");
    f.has_x25519 = true;
    f.session_id_len = 32;
    f.session_id.resize(32, 0xAA);
    f.has_alpn = true;
    f.has_psk = true;
    f.has_ech = true;
    f.has_esni = true;
    f.greased_extensions = true;
    f.has_sig_algos = true;
    f.keyshare_multi = true;
    f.early_data = true;
    f.versions.push_back(0x0304);
    return f;
}

const auto feat_full = make_feat_full();
const auto feat_minimal = make_feat_minimal();
const auto feat_rich = make_feat_rich();

/// 预计算位图
const auto bitmap_full = rectls::build_bitmap(feat_full);
const auto bitmap_minimal = rectls::build_bitmap(feat_minimal);

/// 批量测试特征组合
const rectls::hello_features feat_batch[] = {
    feat_full,
    feat_minimal,
    feat_rich,
};

// ============================================================
// TLS 特征位图基准测试
// ============================================================

/// @brief 测量 TLS 特征位图构建性能
void BM_RecPipe_BuildBitmap(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto bm = rectls::build_bitmap(feat_full);
        benchmark::DoNotOptimize(bm);
    }
}
BENCHMARK(BM_RecPipe_BuildBitmap);

/// @brief 测量 TLS 特征位图单项查询性能
void BM_RecPipe_HasFeature(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = rectls::has_feature(bitmap_full, rectls::feature_bit::has_x25519);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_RecPipe_HasFeature);

/// @brief 测量 TLS 特征位图多特征组合查询性能
void BM_RecPipe_HasAll(benchmark::State &state)
{
    const auto mask = rectls::feature_bit::has_sni
        | rectls::feature_bit::has_x25519
        | rectls::feature_bit::full_session;
    for (auto _ : state)
    {
        auto r = rectls::has_all(bitmap_full, mask);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_RecPipe_HasAll);

/// @brief 测量不存在的特征位查询性能（miss 路径）
void BM_RecPipe_HasFeature_Miss(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto r = rectls::has_feature(bitmap_minimal, rectls::feature_bit::has_x25519);
        benchmark::DoNotOptimize(r);
    }
}
BENCHMARK(BM_RecPipe_HasFeature_Miss);

// ============================================================
// 目标地址解析基准测试
// ============================================================

/// @brief 测量目标地址解析性能（域名+端口）
void BM_RecPipe_TargetParse(benchmark::State &state)
{
    for (auto _ : state)
    {
        mem::string host;
        mem::string port;
        rec::parse("example.com:443", host, port);
        benchmark::DoNotOptimize(host.data());
        benchmark::DoNotOptimize(port.data());
    }
}
BENCHMARK(BM_RecPipe_TargetParse);

/// @brief 测量目标地址解析并构建返回值性能
void BM_RecPipe_TargetResolve(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto t = rec::resolve(std::string_view("example.com:443"));
        benchmark::DoNotOptimize(t.host.data());
        benchmark::DoNotOptimize(t.port.data());
    }
}
BENCHMARK(BM_RecPipe_TargetResolve);

/// @brief 测量 IP 地址+端口的目标地址解析性能
void BM_RecPipe_TargetParse_IP(benchmark::State &state)
{
    for (auto _ : state)
    {
        mem::string host;
        mem::string port;
        rec::parse("192.168.1.1:8080", host, port);
        benchmark::DoNotOptimize(host.data());
        benchmark::DoNotOptimize(port.data());
    }
}
BENCHMARK(BM_RecPipe_TargetParse_IP);

/// @brief 测量无端口的目标地址解析性能
void BM_RecPipe_TargetParse_NoPort(benchmark::State &state)
{
    for (auto _ : state)
    {
        mem::string host;
        mem::string port;
        rec::parse("example.com", host, port);
        benchmark::DoNotOptimize(host.data());
        benchmark::DoNotOptimize(port.data());
    }
}
BENCHMARK(BM_RecPipe_TargetParse_NoPort);

/// @brief 测量 IPv6 地址+端口的目标地址解析性能
void BM_RecPipe_TargetParse_IPv6(benchmark::State &state)
{
    for (auto _ : state)
    {
        mem::string host;
        mem::string port;
        rec::parse("[2001:db8::1]:443", host, port);
        benchmark::DoNotOptimize(host.data());
        benchmark::DoNotOptimize(port.data());
    }
}
BENCHMARK(BM_RecPipe_TargetParse_IPv6);

// ============================================================
// 批量位图构建基准测试
// ============================================================

/// @brief 测量多种特征组合批量位图构建性能
void BM_RecPipe_BitmapBatch(benchmark::State &state)
{
    for (auto _ : state)
    {
        for (const auto &feat : feat_batch)
        {
            auto bm = rectls::build_bitmap(feat);
            benchmark::DoNotOptimize(bm);
        }
    }
}
BENCHMARK(BM_RecPipe_BitmapBatch);

} // namespace

BENCHMARK_MAIN();
