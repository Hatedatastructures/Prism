/**
 * @file NativeReadFailureTest.cpp
 * @brief Trojan 规范数据报的原生读取失败传播回归。
 */
#include <gtest/gtest.h>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Protocols/Trojan/DatagramSession.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>
#include "TrojanDatagramTestSupport.hpp"
#include <boost/asio/io_context.hpp>
#include <expected>
#include <memory>
#include <system_error>

namespace
{
    namespace Net = boost::asio;
    namespace Trojan = Prism::Trojan;
    namespace Fault = Prism::Fault;
    using Prism::PrismMockTransport;
    using Prism::Testing::RunCoro;
    using DatagramRunResult = std::expected<void, Fault::Failure>;

    TEST(CanonicalDatagramRegression, NativePacketReadFailureSurvivesDatagramRun)
    {
        Net::io_context Io;
        auto Carrier = std::make_shared<PrismMockTransport>(Io.get_executor());
        Carrier->ToRead = {0x01};
        const auto Native = std::make_error_code(std::errc::connection_reset);
        Carrier->SetReadError(Native);
        Carrier->ReadErrorBytes = 1;
        auto Wire = std::make_shared<Trojan::Dgram<>>(Carrier);
        auto Session = Prism::Testing::TrojanDatagram::MakeSession(
            Wire, Trojan::DatagramSession::Options{{}, {}});
        const auto Activity = Session->Activity();
        const auto Retirement =
            std::dynamic_pointer_cast<Prism::Executor::ClosingResource>(Activity);
        ASSERT_TRUE(Retirement);
        DatagramRunResult Result;
        std::expected<void, Fault::Failure> DrainResult;

        RunCoro(Io, [&]() -> Net::awaitable<void>
        {
            Result = co_await Session->Run();
            DrainResult = co_await Activity->Drain();
        });

        ASSERT_FALSE(Result);
        EXPECT_EQ(Result.error().Code, Fault::Code::ConnectionReset);
        EXPECT_EQ(Result.error().Native, Native);
        EXPECT_EQ(Carrier->ReadsDone, 1U);
        EXPECT_TRUE(DrainResult);
        EXPECT_TRUE(Carrier->IsClosed());
        EXPECT_TRUE(Retirement->IsRetired());
    }
}
