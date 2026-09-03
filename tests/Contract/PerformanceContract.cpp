/**
 * @file PerformanceContract.cpp
 * @brief Production/Preview 同一编解码输入的性能对拍
 * @details 使用同一 payload、预热次数、迭代次数和三次采样，分别测量
 *          VLESS 请求解析、SS2022 会话密钥派生和 SOCKS5 地址解析。
 *          结果写入 PRISM_PERF_OUTPUT 指定的 JSON 文件。
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <prism/crypto/blake3.hpp>
#include <prism/foundation/fault/code.hpp>
#include <prism/protocol/shadowsocks/constants.hpp>
#include <prism/protocol/shadowsocks/codec/framing.hpp>
#include <prism/protocol/vless/codec/framing.hpp>

#include <preview/Protocols/Shadowsocks2022/KeyDerivation.hpp>
#include <preview/Protocols/Socks5/Codec.hpp>
#include <preview/Protocols/Vless/Codec.hpp>

namespace
{

    using Clock = std::chrono::steady_clock;

    struct Metric
    {
        std::string Name;
        std::string Implementation;
        double MedianNanoseconds{0};
    };

    template <typename Function>
    [[nodiscard]] auto Measure(Function &&Fn, const std::size_t Warmup,
                                const std::size_t Iterations) -> double
    {
        for (std::size_t Index = 0; Index < Warmup; ++Index)
        {
            Fn();
        }
        const auto Start = Clock::now();
        for (std::size_t Index = 0; Index < Iterations; ++Index)
        {
            Fn();
        }
        const auto End = Clock::now();
        return std::chrono::duration<double, std::nano>(End - Start).count() /
               static_cast<double>(Iterations);
    }

    [[nodiscard]] auto Median(std::array<double, 3> Values) -> double
    {
        std::sort(Values.begin(), Values.end());
        return Values[1];
    }

    [[nodiscard]] auto OutputPath() -> std::string
    {
        if (const auto *Path = std::getenv("PRISM_PERF_OUTPUT"); Path && *Path)
        {
            return Path;
        }
        return "preview-production-perf.json";
    }

    [[nodiscard]] auto BuildVlessWire() -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Wire{0x00};
        Wire.insert(Wire.end(), 16, 0x11);
        Wire.insert(Wire.end(), {0x00, 0x01, 0x01, 0xBB, 0x02,
                                 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e'});
        return Wire;
    }

    [[nodiscard]] auto BuildSocksWire() -> std::vector<std::uint8_t>
    {
        return {0x01, 8, 8, 8, 8, 0x00, 0x35};
    }

    [[nodiscard]] auto WriteMetrics(const std::vector<Metric> &Metrics) -> bool
    {
        std::ofstream Output(OutputPath(), std::ios::binary | std::ios::trunc);
        if (!Output)
        {
            return false;
        }
        Output << "{\n  \"schema\": \"prism.perf-contract.v1\",\n"
               << "  \"warmup\": 100,\n  \"iterations\": 10000,\n"
               << "  \"repetitions\": 3,\n  \"metrics\": [\n";
        for (std::size_t Index = 0; Index < Metrics.size(); ++Index)
        {
            const auto &MetricValue = Metrics[Index];
            Output << "    {\"metric\": \"" << MetricValue.Name
                   << "\", \"implementation\": \"" << MetricValue.Implementation
                   << "\", \"median_ns\": " << std::setprecision(12)
                   << MetricValue.MedianNanoseconds << "}";
            if (Index + 1 != Metrics.size())
            {
                Output << ',';
            }
            Output << "\n";
        }
        Output << "  ]\n}\n";
        return static_cast<bool>(Output);
    }

    TEST(PerformanceContract, WritesComparableCodecMetrics)
    {
        constexpr std::size_t Warmup = 100;
        constexpr std::size_t Iterations = 10000;
        const auto VlessWire = BuildVlessWire();
        const auto SocksWire = BuildSocksWire();
        constexpr std::array<std::uint8_t, 16> Psk{
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        constexpr std::array<std::uint8_t, 16> Salt{
            0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
            0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F};

        std::array<double, 3> ProductionVless{};
        std::array<double, 3> PreviewVless{};
        std::array<double, 3> ProductionSs{};
        std::array<double, 3> PreviewSs{};
        std::array<double, 3> ProductionSocks{};
        std::array<double, 3> PreviewSocks{};

        for (std::size_t Repetition = 0; Repetition < 3; ++Repetition)
        {
            ProductionVless[Repetition] = Measure(
                [&]
                {
                    const auto Parsed = psm::protocol::vless::format::parse_request(VlessWire);
                    EXPECT_TRUE(Parsed.has_value());
                },
                Warmup, Iterations);
            PreviewVless[Repetition] = Measure(
                [&]
                {
                    Preview::Vless::RequestHeader Parsed;
                    std::size_t Consumed = 0;
                    EXPECT_EQ(Preview::Vless::ParseRequest(VlessWire, Parsed, Consumed), Preview::Error::None);
                },
                Warmup, Iterations);
            ProductionSs[Repetition] = Measure(
                [&]
                {
                    std::array<std::uint8_t, 16> Output{};
                    psm::crypto::derive_key(psm::protocol::shadowsocks::kdf_context,
                                            std::span<const std::uint8_t>(Psk.data(), Psk.size()),
                                            Output);
                },
                Warmup, Iterations);
            PreviewSs[Repetition] = Measure(
                [&]
                {
                    const auto Output = Preview::Shadowsocks2022::SessionKey(Psk, Salt, 16);
                    EXPECT_EQ(Output.size(), 16u);
                },
                Warmup, Iterations);
            ProductionSocks[Repetition] = Measure(
                [&]
                {
                    const auto Parsed = psm::protocol::shadowsocks::format::parse_addr_port(SocksWire);
                    EXPECT_EQ(Parsed.first, psm::fault::code::success);
                },
                Warmup, Iterations);
            PreviewSocks[Repetition] = Measure(
                [&]
                {
                    Preview::Socks5::Address Parsed;
                    std::size_t Consumed = 0;
                    EXPECT_EQ(Preview::Socks5::ParseAddress(SocksWire, Parsed, Consumed), Preview::Error::None);
                },
                Warmup, Iterations);
        }

        const std::vector<Metric> Metrics{
            {"vless.parse_request", "production", Median(ProductionVless)},
            {"vless.parse_request", "preview", Median(PreviewVless)},
            {"ss2022.session_key", "production", Median(ProductionSs)},
            {"ss2022.session_key", "preview", Median(PreviewSs)},
            {"socks5.parse_addr_port", "production", Median(ProductionSocks)},
            {"socks5.parse_addr_port", "preview", Median(PreviewSocks)},
        };
        for (const auto &MetricValue : Metrics)
        {
            EXPECT_GT(MetricValue.MedianNanoseconds, 0.0);
        }
        ASSERT_TRUE(WriteMetrics(Metrics));
    }

} // namespace
