/**
 * @file AnytlsAuthFrameTest.cpp
 * @brief Anytls 认证帧编解码值测试。
 */

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Anytls/Codec.hpp>
#include <gtest/gtest.h>

namespace
{

    namespace Anytls = Prism::Anytls;
    using Prism::Error;

TEST(AnyTlsBeast, AuthFrame)
    {
        const std::string password = "anytls_password";
        std::string Frame;
        EXPECT_EQ(Anytls::BuildAuthFrame(password, 16, Frame), Error::None);
        EXPECT_EQ(Frame.size(), Anytls::AuthFrameHdrlen + 16);

        std::array<std::uint8_t, Anytls::PasswordHashLen> Hash{};
        std::uint16_t PadLen = 0;
        EXPECT_EQ(
            Anytls::ParseAuthFrame(std::span<const std::uint8_t>(
                                         reinterpret_cast<const std::uint8_t *>(Frame.data()), Frame.size()),
                                     Hash, PadLen),
            Error::None);
        EXPECT_EQ(PadLen, 16u);
        EXPECT_TRUE(Anytls::VerifyAuth(password, Hash));
        EXPECT_FALSE(Anytls::VerifyAuth("wrong", Hash));
    }

} // namespace
