/**
 * @file FieldCodecTest.cpp
 * @brief 字段编译期类型约束、截断和敏感值处理测试。
 */

#include <gtest/gtest.h>

#include <Prism/Foundation/Utility/Diagnose/FieldCodec.hpp>
#include <Prism/Foundation/Utility/Diagnose/FieldKey.hpp>

#include <string>
#include <string_view>

namespace
{

    using Prism::Diagnose::EncodeFieldValue;
    using Prism::Diagnose::FieldValueCompatible;
    using Prism::Diagnose::Fields::NativeError;
    using Prism::Diagnose::Fields::Route;
    using Prism::Diagnose::Fields::Session;
    using Prism::Diagnose::Fields::Worker;

    static_assert(FieldValueCompatible<decltype(Worker), Prism::WorkerId>);
    static_assert(!FieldValueCompatible<decltype(Worker), Prism::SessionId>);
    static_assert(FieldValueCompatible<decltype(Route), std::string_view>);
    static_assert(FieldValueCompatible<decltype(Route), std::string>);

    TEST(PrismDiagnose, FieldCodecTruncatesShortTextAtUtf8Boundaries)
    {
        std::string Input;
        for (std::size_t Index = 0; Index < 32U; ++Index)
        {
            Input.append("路");
        }

        const auto Encoded = EncodeFieldValue(Route, Input);
        std::string Expected;
        for (std::size_t Index = 0; Index < 16U; ++Index)
        {
            Expected.append("路");
        }
        Expected.append("...[truncated]");

        EXPECT_TRUE(Encoded.Truncated);
        EXPECT_EQ(Encoded.Text, Expected);
        EXPECT_LE(Encoded.Text.size(), 64U);
    }

    TEST(PrismDiagnose, FieldCodecRedactsSensitiveDescriptorBeforeEncoding)
    {
        constexpr std::string_view Canary{"token=field-canary"};
        const auto Encoded = EncodeFieldValue(NativeError, Canary);

        EXPECT_EQ(Encoded.Text, "token=<redacted>");
        EXPECT_EQ(Encoded.Text.find("field-canary"), std::string::npos);
        EXPECT_FALSE(Encoded.Truncated);
    }

    TEST(PrismDiagnose, FieldCodecRedactsSensitiveValuesWithEscapedQuotes)
    {
        constexpr std::string_view Input{
            R"({"password":"prefix\"suffix-canary","token":"token-tail"})"};
        const auto Encoded = EncodeFieldValue(NativeError, Input);

        EXPECT_EQ(Encoded.Text, R"({"password":"<redacted>","token":"<redacted>"})");
        EXPECT_EQ(Encoded.Text.find("suffix-canary"), std::string::npos);
        EXPECT_EQ(Encoded.Text.find("token-tail"), std::string::npos);
        EXPECT_FALSE(Encoded.Truncated);
    }

    TEST(PrismDiagnose, FieldCodecNumericIdentityCodecsPreserveStrongTypes)
    {
        const auto WorkerValue = EncodeFieldValue(Worker, Prism::WorkerId{41});
        const auto SessionValue = EncodeFieldValue(Session, Prism::SessionId{73});

        EXPECT_EQ(WorkerValue.Unsigned, 41U);
        EXPECT_EQ(SessionValue.Unsigned, 73U);
    }

} // namespace
