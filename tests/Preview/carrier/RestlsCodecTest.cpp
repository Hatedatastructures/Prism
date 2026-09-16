/**
 * @file RestlsCodecTest.cpp
 * @brief Restls 应用数据记录编解码的纯函数测试。
 */

#include <Preview/Protocols/Restls/Codec.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <gtest/gtest.h>

namespace
{

    namespace Restls = Preview::Restls;
    using Preview::Error;

    auto MakeRandom() -> std::array<std::uint8_t, 32>
    {
        std::array<std::uint8_t, 32> Value{};
        for (std::size_t Index = 0; Index < Value.size(); ++Index)
        {
            Value[Index] = static_cast<std::uint8_t>(0x20U + Index);
        }
        return Value;
    }

    TEST(RestlsCodec, BuildsAndDecodesApplicationDataRecord)
    {
        const auto Secret = Restls::DeriveSecret("restls-codec-test");
        const auto ServerRandom = MakeRandom();
        const std::vector<std::uint8_t> ClientFinished{0x17, 0x03, 0x03, 0x00, 0x08,
                                                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                                                       0x17};
        const std::vector<std::uint8_t> Data{'r', 'e', 's', 't', 'l', 's'};

        const auto [BuildError, Wire] = Restls::BuildFrame(Restls::FrameOptions{
            .Secret = Secret,
            .ServerRandom = ServerRandom,
            .Direction = Restls::FlowDirection::ToServer,
            .Counter = 0,
            .ClientFinished = ClientFinished,
            .Data = Data,
            .PaddingLength = 3,
            .Command = Restls::CmdTypeNoop,
            .CommandArgument = 0});

        ASSERT_EQ(BuildError, Error::None);
        ASSERT_EQ(Wire.size(), Restls::TlsHdrlen + Restls::AuthHdrlen + Data.size() + 3U);
        EXPECT_EQ(Wire[0], Restls::TlsApplicationData);
        EXPECT_EQ(Wire[1], 0x03U);
        EXPECT_EQ(Wire[2], 0x03U);
        EXPECT_EQ((static_cast<std::size_t>(Wire[3]) << 8U) | Wire[4],
                  Wire.size() - Restls::TlsHdrlen);

        Restls::DecodedFrame Decoded;
        EXPECT_EQ(Restls::DecodeFrame(
                      Wire,
                      Restls::DecodeOptions{.Secret = Secret,
                                            .ServerRandom = ServerRandom,
                                            .Direction = Restls::FlowDirection::ToServer,
                                            .Counter = 0,
                                            .ClientFinished = ClientFinished},
                      Decoded),
                  Error::None);
        EXPECT_EQ(Decoded.Data, Data);
        EXPECT_EQ(Decoded.Command, Restls::CmdTypeNoop);
        EXPECT_EQ(Decoded.CommandArgument, 0U);
        EXPECT_EQ(Decoded.PaddingLength, 3U);
    }

    TEST(RestlsCodec, RejectsTamperedOrMalformedRecord)
    {
        const auto Secret = Restls::DeriveSecret("restls-codec-test");
        const auto ServerRandom = MakeRandom();
        const std::vector<std::uint8_t> Data{'x'};
        const auto [BuildError, Original] = Restls::BuildFrame(Restls::FrameOptions{
            .Secret = Secret,
            .ServerRandom = ServerRandom,
            .Direction = Restls::FlowDirection::ToClient,
            .Counter = 7,
            .ClientFinished = {},
            .Data = Data,
            .PaddingLength = 0,
            .Command = Restls::CmdTypeNoop,
            .CommandArgument = 0});
        ASSERT_EQ(BuildError, Error::None);

        auto Tampered = Original;
        Tampered[Restls::TlsHdrlen] ^= 0x01U;
        Restls::DecodedFrame Decoded;
        const Restls::DecodeOptions Options{.Secret = Secret,
                                            .ServerRandom = ServerRandom,
                                            .Direction = Restls::FlowDirection::ToClient,
                                            .Counter = 7,
                                            .ClientFinished = {}};
        EXPECT_EQ(Restls::DecodeFrame(Tampered, Options, Decoded), Error::BadAuth);

        auto BadType = Original;
        BadType[0] = 0x16U;
        EXPECT_EQ(Restls::DecodeFrame(BadType, Options, Decoded), Error::BadMagic);

        auto Truncated = Original;
        Truncated.pop_back();
        EXPECT_EQ(Restls::DecodeFrame(Truncated, Options, Decoded), Error::NeedMore);
    }

} // namespace
