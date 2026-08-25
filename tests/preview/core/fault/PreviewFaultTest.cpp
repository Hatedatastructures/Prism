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
        EXPECT_FALSE(Preview::Fault::Describe(Preview::Fault::Code::success).empty());
        EXPECT_FALSE(Preview::Fault::Describe(Preview::Fault::Code::bad_message).empty());
        EXPECT_FALSE(Preview::Fault::Describe(Preview::Fault::Code::timeout).empty());
    }

    TEST(PreviewFault, CachedMessage)
    {
        EXPECT_FALSE(Preview::Fault::CachedMessage(Preview::Fault::Code::io_error).empty());
        // 缓存引用稳定
        const auto &a = Preview::Fault::CachedMessage(Preview::Fault::Code::io_error);
        const auto &b = Preview::Fault::CachedMessage(Preview::Fault::Code::io_error);
        EXPECT_EQ(&a, &b);
    }

    TEST(PreviewFault, Category)
    {
        EXPECT_STREQ(Preview::Fault::category().name(), "Preview::fault");
        EXPECT_FALSE(Preview::Fault::category().message(static_cast<int>(Preview::Fault::Code::generic_error)).empty());
    }

    TEST(PreviewFault, StdConversion)
    {
        const std::error_code ec = Preview::Fault::Code::bad_message;
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec.value(), static_cast<int>(Preview::Fault::Code::bad_message));
        EXPECT_EQ(ec.category(), Preview::Fault::category());
    }

    TEST(PreviewFault, BoostConversion)
    {
        const boost::system::error_code ec = boost::system::make_error_code(Preview::Fault::Code::timeout);
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec.value(), static_cast<int>(Preview::Fault::Code::timeout));
    }

    TEST(PreviewFault, SucceededFailed)
    {
        EXPECT_TRUE(Preview::Fault::Succeeded(Preview::Fault::Code::success));
        EXPECT_FALSE(Preview::Fault::Failed(Preview::Fault::Code::success));

        EXPECT_TRUE(Preview::Fault::Failed(Preview::Fault::Code::io_error));
        EXPECT_FALSE(Preview::Fault::Succeeded(Preview::Fault::Code::io_error));

        // std::error_code 分支
        const std::error_code Ok;
        EXPECT_TRUE(Preview::Fault::Succeeded(Ok));
        EXPECT_FALSE(Preview::Fault::Failed(Ok));

        const std::error_code err = Preview::Fault::Code::canceled;
        EXPECT_TRUE(Preview::Fault::Failed(err));

        // boost::system::error_code 分支
        const boost::system::error_code bok;
        EXPECT_TRUE(Preview::Fault::Succeeded(bok));
        const boost::system::error_code berr = boost::system::make_error_code(Preview::Fault::Code::auth_failed);
        EXPECT_TRUE(Preview::Fault::Failed(berr));
    }

    TEST(PreviewFault, Hash)
    {
        std::unordered_set<Preview::Fault::Code> set;
        set.insert(Preview::Fault::Code::success);
        set.insert(Preview::Fault::Code::io_error);
        EXPECT_EQ(set.size(), 2U);
        EXPECT_NE(set.find(Preview::Fault::Code::io_error), set.end());
    }

} // namespace