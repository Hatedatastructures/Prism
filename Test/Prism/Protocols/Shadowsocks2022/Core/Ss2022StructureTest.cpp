/**
 * @file Ss2022StructureTest.cpp
 * @brief Shadowsocks 2022 连接实现头文件结构测试
 * @details 验证连接实现头文件保持在生产头文件行数边界内。
 */

#include <array>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>

#include <gtest/gtest.h>

namespace
{

    [[nodiscard]] auto FindRepositoryRoot() -> std::filesystem::path
    {
#ifdef PRISM_TEST_REPO_ROOT
        return std::filesystem::path{PRISM_TEST_REPO_ROOT};
#else
        return {};
#endif
    }

    [[nodiscard]] auto CountLines(const std::filesystem::path &Path) -> std::size_t
    {
        std::ifstream Input(Path);
        std::size_t Lines = 0;
        std::string Line;
        while (std::getline(Input, Line))
        {
            ++Lines;
        }
        return Lines;
    }

    TEST(Ss2022CodecDeep, ConnImplementationHeadersStayFocused)
    {
        const auto Root = FindRepositoryRoot();
        ASSERT_FALSE(Root.empty());
        constexpr std::array<std::string_view, 5> Headers{
            "Conn.hpp",
            "ConnSession.hpp",
            "ConnRecord.hpp",
            "ConnHandshake.hpp",
            "ConnDatagram.hpp"};
        for (const auto Header : Headers)
        {
            const auto Path = Root / "Include" / "Prism" / "Protocols" / "Shadowsocks2022" / Header;
            const auto Lines = CountLines(Path);
            ASSERT_GT(Lines, 0u) << Path.string();
            EXPECT_LE(Lines, 600u) << Path.string();
        }
    }

} // namespace

