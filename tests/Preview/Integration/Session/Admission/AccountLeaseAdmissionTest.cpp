/**
 * @file AccountLeaseAdmissionTest.cpp
 * @brief 数据面账户租约与入站准入的跨模块生命周期测试。
 */

#include <gtest/gtest.h>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <utility>

#include <Preview/Contract/Ingress/DataPlane.hpp>
#include <Preview/Contract/Ingress/InboundAdmission.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Transport/MemoryStream.hpp>

namespace
{

    namespace Net = boost::asio;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

    auto RunCanonicalAdmission(Preview::Contract::ProtocolDataPlane Plane)
        -> Net::awaitable<Preview::Contract::AcceptOutcome>
    {
        auto Admission = co_await Preview::Contract::InboundAdmission::Prepare(Plane.Transport());
        if (!Admission)
        {
            co_return std::unexpected(Admission.error());
        }
        co_return co_await Admission->Admit(std::move(Plane));
    }

    TEST(Authenticator, CanonicalAdmissionRejectsAccountWithoutLease)
    {
        Net::io_context Io;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(Io.get_executor());
        ASSERT_TRUE(ClientMemory.IsOpen());

        Preview::Contract::ProtocolDataPlane Result;
        Result.Root = Preview::Contract::StreamDataPlane{
            std::make_shared<MemoryStream>(std::move(ServerMemory))};
        Result.ProtocolAuthenticated = true;
        Result.AccountId = Preview::AccountId{99};
        Result.Identity = "credential-secret-must-not-escape";

        std::optional<Preview::Contract::AcceptOutcome> Accepted;
        std::exception_ptr Exception;
        Net::co_spawn(
            Io, RunCanonicalAdmission(std::move(Result)),
            [&](std::exception_ptr Failure, Preview::Contract::AcceptOutcome Outcome)
            {
                Exception = std::move(Failure);
                Accepted.emplace(std::move(Outcome));
            });
        Io.run();

        ASSERT_FALSE(Exception);
        ASSERT_TRUE(Accepted.has_value());
        ASSERT_FALSE(Accepted->has_value());
        EXPECT_EQ(Accepted->error().Code, Preview::Fault::Code::AuthFailed);
    }

} // namespace
