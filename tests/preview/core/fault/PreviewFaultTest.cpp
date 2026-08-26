/**
 * @file PreviewFaultTest.cpp
 * @brief Preview 流程错误码体系测试（core/fault）
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

#include <common/Core/Fault/Code.hpp>
#include <common/Core/Fault/Compatible.hpp>
#include <common/Core/Fault/Handling.hpp>

namespace
{

    TEST(PreviewFault, Describe)
    {
        EXPECT_FALSE(Preview::Fault::Describe(Preview::Fault::Code::Success).empty());
        EXPECT_FALSE(Preview::Fault::Describe(Preview::Fault::Code::BadMessage).empty());
        EXPECT_FALSE(Preview::Fault::Describe(Preview::Fault::Code::Timeout).empty());
    }

    TEST(PreviewFault, CachedMessage)
    {
        EXPECT_FALSE(Preview::Fault::CachedMessage(Preview::Fault::Code::IoError).empty());
        // 缓存引用稳定
        const auto &a = Preview::Fault::CachedMessage(Preview::Fault::Code::IoError);
        const auto &b = Preview::Fault::CachedMessage(Preview::Fault::Code::IoError);
        EXPECT_EQ(&a, &b);
    }

    TEST(PreviewFault, Category)
    {
        EXPECT_STREQ(Preview::Fault::Category().name(), "Preview::fault");
        EXPECT_FALSE(Preview::Fault::Category().message(static_cast<int>(Preview::Fault::Code::GenericError)).empty());
    }

    TEST(PreviewFault, StdConversion)
    {
        const std::error_code ec = Preview::Fault::Code::BadMessage;
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec.value(), static_cast<int>(Preview::Fault::Code::BadMessage));
        EXPECT_EQ(ec.category(), Preview::Fault::Category());
    }

    TEST(PreviewFault, BoostConversion)
    {
        const boost::system::error_code ec = boost::system::make_error_code(Preview::Fault::Code::Timeout);
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec.value(), static_cast<int>(Preview::Fault::Code::Timeout));
    }

    TEST(PreviewFault, SucceededFailed)
    {
        EXPECT_TRUE(Preview::Fault::Succeeded(Preview::Fault::Code::Success));
        EXPECT_FALSE(Preview::Fault::Failed(Preview::Fault::Code::Success));

        EXPECT_TRUE(Preview::Fault::Failed(Preview::Fault::Code::IoError));
        EXPECT_FALSE(Preview::Fault::Succeeded(Preview::Fault::Code::IoError));

        // std::error_code 分支
        const std::error_code Ok;
        EXPECT_TRUE(Preview::Fault::Succeeded(Ok));
        EXPECT_FALSE(Preview::Fault::Failed(Ok));

        const std::error_code err = Preview::Fault::Code::Canceled;
        EXPECT_TRUE(Preview::Fault::Failed(err));

        // boost::system::error_code 分支
        const boost::system::error_code bok;
        EXPECT_TRUE(Preview::Fault::Succeeded(bok));
        const boost::system::error_code berr = boost::system::make_error_code(Preview::Fault::Code::AuthFailed);
        EXPECT_TRUE(Preview::Fault::Failed(berr));
    }

    TEST(PreviewFault, Hash)
    {
        std::unordered_set<Preview::Fault::Code> set;
        set.insert(Preview::Fault::Code::Success);
        set.insert(Preview::Fault::Code::IoError);
        EXPECT_EQ(set.size(), 2U);
        EXPECT_NE(set.find(Preview::Fault::Code::IoError), set.end());
    }

} // namespace