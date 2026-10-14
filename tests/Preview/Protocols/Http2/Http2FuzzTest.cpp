/**
 * @file Http2FuzzTest.cpp
 * @brief HTTP/2 帧、varint 和 HPACK 结构化 fuzz 测试。
 */

#include <gtest/gtest.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <random>
#include <span>
#include <vector>
#include <Preview/Protocols/Http2/Detail/Codec.hpp>
#include <Preview/Protocols/Http2/Detail/Frame.hpp>

namespace
{
    namespace Http2 = Preview::Http2;
    using Preview::Error;

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

TEST(FuzzExtended, Http2FrameHeaderParse)
    {
        auto Rng = MakeRng(7);
        for (int I = 0; I < 2000; ++I)
        {
            const auto Data = MutateBytes(Rng);
            if (Data.size() >= 9)
            {
                if (const auto FrameHeader = Http2::Detail::ParseFrameHeader(std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(Data.data()), 9)))
                {
                    // HTTP/2 帧长 24-bit：解析不得越界
                    EXPECT_LE(FrameHeader->Length, 0xFFFFFFu);
                }
            }
            if (const auto Settings = Http2::Detail::DecodeSettings(std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(Data.data()), Data.size())))
            {
                // SETTINGS 每项至少 6 字节：条目数受输入长度约束
                EXPECT_LE(Settings->size(), Data.size() / 6 + 1);
            }
        }
    }

TEST(FuzzExtended, Http2VarintDecode)
    {
        auto Rng = MakeRng(8);
        std::array<std::byte, 8> Buffer{};
        for (int I = 0; I < 2000; ++I)
        {
            const auto Data = MutateBytes(Rng);
            const auto Count = (std::min)(Data.size(), Buffer.size());
            for (std::size_t J = 0; J < Count; ++J)
            {
                Buffer[J] = static_cast<std::byte>(Data[J]);
            }
            std::size_t Offset = 0;
            (void)Http2::Detail::DecodeInt(std::span<const std::byte>(Buffer.data(), Count), 7, Offset);
            EXPECT_LE(Offset, Count); // 解析游标不得越过输入
            std::size_t Offset2 = 0;
            (void)Http2::Detail::DecodeString(std::span<const std::byte>(Buffer.data(), Count), Offset2);
            EXPECT_LE(Offset2, Count);
        }
    }

TEST(FuzzExtended, Http2HpackDecode)
    {
        auto Rng = MakeRng(9);
        for (int I = 0; I < 1000; ++I)
        {
            const auto Data = MutateBytes(Rng);
            std::size_t Offset = 0;
            (void)Http2::Detail::DecodeInt(std::span<const std::byte>(
                                        reinterpret_cast<const std::byte *>(Data.data()), Data.size()),
                                    7, Offset);
            EXPECT_LE(Offset, Data.size()); // 解析游标不得越过输入
            std::size_t Offset2 = 0;
            (void)Http2::Detail::DecodeString(std::span<const std::byte>(
                                           reinterpret_cast<const std::byte *>(Data.data()),
                                           Data.size()),
                                       Offset2);
            EXPECT_LE(Offset2, Data.size());
        }
    }

