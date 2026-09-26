/**
 * @file FieldCodecTest.cpp
 * @brief 字段编译期类型约束、截断和敏感值处理测试。
 */

#include <gtest/gtest.h>

#include <Preview/Foundation/Utility/Diagnose/FieldCodec.hpp>
#include <Preview/Foundation/Utility/Diagnose/FieldKey.hpp>

#include <string>
#include <string_view>

namespace
{

    using Preview::Diagnose::EncodeFieldValue;
    using Preview::Diagnose::FieldValueCompatible;
    using Preview::Diagnose::Fields::NativeError;
    using Preview::Diagnose::Fields::Route;
    using Preview::Diagnose::Fields::Session;
    using Preview::Diagnose::Fields::Worker;

    static_assert(FieldValueCompatible<decltype(Worker), Preview::WorkerId>);
    static_assert(!FieldValueCompatible<decltype(Worker), Preview::SessionId>);
    static_assert(FieldValueCompatible<decltype(Route), std::string_view>);
    static_assert(FieldValueCompatible<decltype(Route), std::string>);

    TEST(PreviewDiagnose, FieldCodecTruncatesShortTextAtUtf8Boundaries)
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

    TEST(PreviewDiagnose, FieldCodecRedactsSensitiveDescriptorBeforeEncoding)
    {
        constexpr std::string_view Canary{"token=field-canary"};
        const auto Encoded = EncodeFieldValue(NativeError, Canary);

        EXPECT_EQ(Encoded.Text, "token=<redacted>");
        EXPECT_EQ(Encoded.Text.find("field-canary"), std::string::npos);
        EXPECT_FALSE(Encoded.Truncated);
    }

    TEST(PreviewDiagnose, FieldCodecNumericIdentityCodecsPreserveStrongTypes)
    {
        const auto WorkerValue = EncodeFieldValue(Worker, Preview::WorkerId{41});
        const auto SessionValue = EncodeFieldValue(Session, Preview::SessionId{73});

        EXPECT_EQ(WorkerValue.Unsigned, 41U);
        EXPECT_EQ(SessionValue.Unsigned, 73U);
    }

} // namespace
