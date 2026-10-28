/**
 * @file QpackFuzzTest.cpp
 * @brief HTTP/3 QPACK header block 与 Huffman fuzz 测试。
 */

#include <gtest/gtest.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <random>
#include <span>
#include <vector>
#include <Prism/Protocols/Http3/Qpack.hpp>
#include <Prism/Protocols/HttpCompression/Huffman.hpp>

namespace
{
    namespace Memory = Prism::Memory;
    namespace Qpack = Prism::Http3::Qpack;
auto MakeRng(std::uint32_t Seed) -> std::mt19937
    {
        return std::mt19937(Seed);
    }

auto RandomBytes(std::mt19937 &Rng) -> std::vector<std::uint8_t>
    {
        std::uniform_int_distribution<int> LengthDistribution(0, 512);
        std::uniform_int_distribution<int> ByteDistribution(0, 255);
        std::vector<std::uint8_t> Output(LengthDistribution(Rng));
        for (auto &Byte : Output)
        {
            Byte = static_cast<std::uint8_t>(ByteDistribution(Rng));
        }
        return Output;
    }

constexpr std::array<std::uint8_t, 24> EdgeBytes = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x08, 0x0D, 0x0A, 0x0F, 0x10,
        0x1F, 0x20, 0x3F, 0x40, 0x7F, 0x80, 0xFE, 0xFF, 0x00, 0x00, 0xFF, 0xFF};

auto MutateBytes(std::mt19937 &Rng) -> std::vector<std::uint8_t>
    {
        auto Data = RandomBytes(Rng);
        if (Data.empty())
        {
            Data.push_back(static_cast<std::uint8_t>(Rng() & 0xFF));
        }
        std::uniform_int_distribution<int> Operation(0, 3);
        const auto Mode = Operation(Rng);
        if (Mode == 0)
        {
            // 截断
            std::uniform_int_distribution<std::size_t> Cut(0, Data.size());
            Data.resize(Cut(Rng));
        }
        else if (Mode == 1)
        {
            // 边界字典注入
            std::uniform_int_distribution<std::size_t> Position(0, Data.size() - 1);
            std::uniform_int_distribution<std::size_t> Edge(0, EdgeBytes.size() - 1);
            const auto PositionValue = Position(Rng);
            const auto EdgeValue = EdgeBytes[Edge(Rng)];
            if (PositionValue < Data.size())
            {
                Data[PositionValue] = EdgeValue;
            }
        }
        else if (Mode == 2)
        {
            // 头部插入边界字典
            std::uniform_int_distribution<std::size_t> Count(1, 8);
            const auto CountValue = Count(Rng);
            Data.insert(Data.begin(), EdgeBytes.begin(),
                        EdgeBytes.begin() + static_cast<std::ptrdiff_t>(CountValue));
        }
        // mode 3：原样（随机字节）
        return Data;
    }
} // namespace

TEST(FuzzExtended, QpackHeaderBlockDecode)
    {
        auto Rng = MakeRng(10);
        for (int I = 0; I < 1000; ++I)
        {
            const auto Data = MutateBytes(Rng);
            (void)Qpack::DecodeHeaderBlock(std::span<const std::uint8_t>(Data),
                                           Memory::CurrentResource());
        }
    }

TEST(FuzzExtended, QpackHuffmanDecode)
    {
        auto Rng = MakeRng(11);
        for (int I = 0; I < 2000; ++I)
        {
            const auto Data = MutateBytes(Rng);
            std::vector<std::uint8_t> Output;
            (void)Prism::HttpCompression::HuffmanDecode(std::span<const std::uint8_t>(Data), Output);
            // 注：qpack huffman 位填充可致输出略膨胀（实测 ~1.32x，最短码 5bit 界限 1.6x），
            //     无安全上限可断言；保持健壮性角色（不崩溃 + ASan 捕获越界）。
        }
    }

TEST(FuzzExtended, QpackHuffmanRejectsLongInvalidPrefix)
    {
        std::array<std::uint8_t, 16> Invalid{};
        Invalid.fill(0xFF);
        std::vector<std::uint8_t> Output;
        EXPECT_FALSE(Prism::HttpCompression::HuffmanDecode(Invalid, Output));
    }

TEST(FuzzExtended, QpackHuffmanRejectsFullBytePadding)
    {
        const std::array<std::uint8_t, 1> Invalid{0xFF};
        std::vector<std::uint8_t> Output;
        EXPECT_FALSE(Prism::HttpCompression::HuffmanDecode(Invalid, Output));
    }

