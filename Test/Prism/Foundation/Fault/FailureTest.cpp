/**
 * @file FailureTest.cpp
 * @brief Prism 流程错误码体系测试（Core/Fault）
 * @details 覆盖 Fault::Code 枚举与标准库兼容：
 * 1. Describe/CachedMessage 错误描述
 * 2. FaultCategory 分类器
 * 3. Fault::Code 与 std/boost ErrorCode 双向转换
 * 4. Succeeded/Failed 统一检查
 * 5. Hash 特化
 */

#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>

#include <boost/system/error_code.hpp>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Compatible.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>

namespace
{

    TEST(PrismFault, Describe)
    {
        EXPECT_FALSE(Prism::Fault::Describe(Prism::Fault::Code::Success).empty());
        EXPECT_FALSE(Prism::Fault::Describe(Prism::Fault::Code::BadMessage).empty());
        EXPECT_FALSE(Prism::Fault::Describe(Prism::Fault::Code::Timeout).empty());
    }

    TEST(PrismFault, CachedMessage)
    {
        EXPECT_FALSE(Prism::Fault::CachedMessage(Prism::Fault::Code::IoError).empty());
        // 缓存引用稳定
        const auto &FirstMessage = Prism::Fault::CachedMessage(Prism::Fault::Code::IoError);
        const auto &SecondMessage = Prism::Fault::CachedMessage(Prism::Fault::Code::IoError);
        EXPECT_EQ(&FirstMessage, &SecondMessage);
    }

    TEST(PrismFault, Category)
    {
        EXPECT_STREQ(Prism::Fault::Category().name(), "Prism::fault");
        EXPECT_FALSE(Prism::Fault::Category().message(static_cast<int>(Prism::Fault::Code::GenericError)).empty());
    }

    TEST(PrismFault, StdConversion)
    {
        const std::error_code ErrorCode = Prism::Fault::Code::BadMessage;
        EXPECT_TRUE(ErrorCode);
        EXPECT_EQ(ErrorCode.value(), static_cast<int>(Prism::Fault::Code::BadMessage));
        EXPECT_EQ(ErrorCode.category(), Prism::Fault::Category());
    }

    TEST(PrismFault, BoostConversion)
    {
        const boost::system::error_code ErrorCode = boost::system::make_error_code(Prism::Fault::Code::Timeout);
        EXPECT_TRUE(ErrorCode);
        EXPECT_EQ(ErrorCode.value(), static_cast<int>(Prism::Fault::Code::Timeout));
    }

    TEST(PrismFault, SucceededFailed)
    {
        EXPECT_TRUE(Prism::Fault::Succeeded(Prism::Fault::Code::Success));
        EXPECT_FALSE(Prism::Fault::Failed(Prism::Fault::Code::Success));

        EXPECT_TRUE(Prism::Fault::Failed(Prism::Fault::Code::IoError));
        EXPECT_FALSE(Prism::Fault::Succeeded(Prism::Fault::Code::IoError));

        // std::error_code 分支
        const std::error_code Ok;
        EXPECT_TRUE(Prism::Fault::Succeeded(Ok));
        EXPECT_FALSE(Prism::Fault::Failed(Ok));

        const std::error_code ErrorValue = Prism::Fault::Code::Canceled;
        EXPECT_TRUE(Prism::Fault::Failed(ErrorValue));

        // boost::system::error_code 分支
        const boost::system::error_code BoostOk;
        EXPECT_TRUE(Prism::Fault::Succeeded(BoostOk));
        const boost::system::error_code BoostError = boost::system::make_error_code(Prism::Fault::Code::AuthFailed);
        EXPECT_TRUE(Prism::Fault::Failed(BoostError));
    }

    TEST(PrismFault, Hash)
    {
        std::unordered_set<Prism::Fault::Code> CodeSet;
        CodeSet.insert(Prism::Fault::Code::Success);
        CodeSet.insert(Prism::Fault::Code::IoError);
        EXPECT_EQ(CodeSet.size(), 2U);
        EXPECT_NE(CodeSet.find(Prism::Fault::Code::IoError), CodeSet.end());
    }

} // namespace
