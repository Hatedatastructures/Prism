/**
 * @file ChunkOwnerTest.cpp
 * @brief VMess chunk ending ownership audit。
 */
#include <gtest/gtest.h>
#include <array>
#include <string>
#include <span>
#include <Prism/Protocols/Vmess/ChunkCodec.hpp>
#include <Prism/Protocols/Vmess/Types.hpp>
TEST(OwnershipAudit, VmessChunkStreamEndBlock)
    {
        Prism::Vmess::ChunkStream ChunkStream;
        std::array<std::uint8_t, 16> Key{};
        Key[0] = 0x11;
        std::array<std::uint8_t, 16> Iv{};
        Iv[0] = 0x22;
        ChunkStream.Init(Key, Iv);

        /** @brief 先加密一个数据块推进 nonce，再加密结束块。 */
        const std::array<std::uint8_t, 3> Payload{0xAA, 0xBB, 0xCC};
        std::string Wire1;
        ChunkStream.Encrypt(Payload, Wire1);
        std::string Wire2;
        ChunkStream.Encrypt({}, Wire2); // 结束块
        EXPECT_EQ(Wire2.size(), 18u);

        std::string Plain1;
        const auto Result1 = ChunkStream.Decrypt(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(Wire1.data()),
                                          Wire1.size()),
            Plain1);
        EXPECT_FALSE(Result1.Ec);
        EXPECT_EQ(Plain1.size(), 3u);

        /** @brief 认证长度结束 marker 只消费其完整 18 字节头部。 */
        std::string Plain2("sentinel");
        const auto Result2 = ChunkStream.Decrypt(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(Wire2.data()),
                                          Wire2.size()),
            Plain2);
        EXPECT_FALSE(Result2.Ec);
        EXPECT_TRUE(Plain2.empty());
        EXPECT_EQ(Result2.Consumed, 18u);
    }



