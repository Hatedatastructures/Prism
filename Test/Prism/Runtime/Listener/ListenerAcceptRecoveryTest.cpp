/**
 * @file ListenerAcceptRecoveryTest.cpp
 * @brief TcpListener accept 错误分类与退避策略契约。
 * @details 资源瞬时耗尽与对端建连放弃不得关闭监听 socket；其余错误仍需
 *          终止 accept 循环并上报失败。
 */

#include <gtest/gtest.h>

#include <Prism/Runtime/Detail/ListenerAcceptRecovery.hpp>

#include <boost/system/error_code.hpp>

#include <chrono>
#include <cstddef>

namespace
{

    using Prism::Runtime::Detail::AcceptBackoffDelay;
    using Prism::Runtime::Detail::IsAcceptResourceExhaustion;
    using Prism::Runtime::Detail::IsRecoverableAcceptError;

    [[nodiscard]] auto MakeError(const boost::system::errc::errc_t Value) -> boost::system::error_code
    {
        return boost::system::errc::make_error_code(Value);
    }

} // namespace

TEST(ListenerAcceptRecovery, FileDescriptorExhaustionIsResourceExhaustion)
{
    EXPECT_TRUE(IsAcceptResourceExhaustion(MakeError(boost::system::errc::too_many_files_open)));
    EXPECT_TRUE(IsAcceptResourceExhaustion(
        MakeError(boost::system::errc::too_many_files_open_in_system)));
    EXPECT_TRUE(IsAcceptResourceExhaustion(MakeError(boost::system::errc::no_buffer_space)));
}

TEST(ListenerAcceptRecovery, ResourceExhaustionIsRecoverable)
{
    EXPECT_TRUE(IsRecoverableAcceptError(MakeError(boost::system::errc::too_many_files_open)));
    EXPECT_TRUE(IsRecoverableAcceptError(
        MakeError(boost::system::errc::too_many_files_open_in_system)));
}

TEST(ListenerAcceptRecovery, PeerAbortAndInterruptAreRecoverable)
{
    EXPECT_TRUE(IsRecoverableAcceptError(boost::asio::error::connection_aborted));
    EXPECT_TRUE(IsRecoverableAcceptError(boost::asio::error::interrupted));
}

TEST(ListenerAcceptRecovery, FatalAcceptErrorsAreNotRecoverable)
{
    EXPECT_FALSE(IsRecoverableAcceptError(boost::asio::error::bad_descriptor));
    EXPECT_FALSE(IsRecoverableAcceptError(boost::asio::error::invalid_argument));
    EXPECT_FALSE(IsRecoverableAcceptError(boost::asio::error::operation_not_supported));
    EXPECT_FALSE(IsRecoverableAcceptError(boost::asio::error::fault));
}

TEST(ListenerAcceptRecovery, BackoffGrowsExponentiallyAndIsCapped)
{
    EXPECT_EQ(AcceptBackoffDelay(0), std::chrono::milliseconds(2));
    EXPECT_EQ(AcceptBackoffDelay(1), std::chrono::milliseconds(4));
    EXPECT_EQ(AcceptBackoffDelay(2), std::chrono::milliseconds(8));
    EXPECT_EQ(AcceptBackoffDelay(3), std::chrono::milliseconds(16));

    const auto Capped = std::chrono::seconds(1);
    EXPECT_EQ(AcceptBackoffDelay(8), std::chrono::milliseconds(512));
    EXPECT_EQ(AcceptBackoffDelay(9), Capped);
    EXPECT_EQ(AcceptBackoffDelay(64), Capped);
    EXPECT_EQ(AcceptBackoffDelay(static_cast<std::size_t>(1) << 20), Capped);
}

TEST(ListenerAcceptRecovery, BackoffIsMonotonic)
{
    auto Previous = AcceptBackoffDelay(0);
    for (std::size_t Failures = 1; Failures < 16; ++Failures)
    {
        const auto Current = AcceptBackoffDelay(Failures);
        EXPECT_GE(Current, Previous) << "failures=" << Failures;
        Previous = Current;
    }
}
