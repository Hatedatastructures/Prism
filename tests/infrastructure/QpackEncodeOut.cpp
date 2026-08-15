#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

#include <common/core/http3/qpack.hpp>
#include <common/core/memory/container.hpp>

namespace
{
    TEST(QpackInterop, EncodeOutputForGo)
    {
        // ?? C++ ??? hex?? Go ? qpackcmp decode ???
        auto mr = psmtest::memory::current_resource();
        std::array<std::uint8_t, 512> buf{};
        auto offset = psmtest::protocol::hysteria2::qpack::encode_prefix(buf);
        offset += psmtest::protocol::hysteria2::qpack::encode_literal(
            ":method", "POST", std::span<std::uint8_t>(buf.data() + offset, buf.size() - offset));
        offset += psmtest::protocol::hysteria2::qpack::encode_literal(
            ":path", "/auth", std::span<std::uint8_t>(buf.data() + offset, buf.size() - offset));
        offset += psmtest::protocol::hysteria2::qpack::encode_literal(
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
