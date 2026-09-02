#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

#include <preview/Protocols/Http3/Qpack.hpp>
#include <preview/Foundation/Memory/Container.hpp>

namespace
{
    TEST(QpackInterop, EncodeOutputForGo)
    {
        // ?? C++ ??? hex?? Go ? qpackcmp Decode ???
        auto mr = Preview::Memory::CurrentResource();
        std::array<std::uint8_t, 512> buf{};
        auto offset = Preview::Http3::Qpack::EncodePrefix(buf);
        offset += Preview::Http3::Qpack::EncodeLiteral(
            ":method", "POST", std::span<std::uint8_t>(buf.data() + offset, buf.size() - offset));
        offset += Preview::Http3::Qpack::EncodeLiteral(
            ":path", "/auth", std::span<std::uint8_t>(buf.data() + offset, buf.size() - offset));
        offset += Preview::Http3::Qpack::EncodeLiteral(
            "hysteria-auth", "password123",
            std::span<std::uint8_t>(buf.data() + offset, buf.size() - offset));

        std::string hex;
        for (std::size_t i = 0; i < offset; ++i)
        {
            char t[4];
            std::snprintf(t, sizeof(t), "%02x", buf[i]);
            hex += t;
        }
        std::printf("CXX_QPACK_HEX=%s\n", hex.c_str());
        ASSERT_FALSE(hex.empty());
    }
} // namespace
