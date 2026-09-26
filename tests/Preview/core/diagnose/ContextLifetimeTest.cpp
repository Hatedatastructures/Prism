/**
 * @file ContextLifetimeTest.cpp
 * @brief 异步提交前快照拥有字段值的生命周期测试。
 */

#include <gtest/gtest.h>

#include <Preview/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <Preview/Foundation/Utility/Diagnose/RenderMode.hpp>
#include <Preview/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Preview/Foundation/Utility/Diagnose/Detail/ContextDecoder.hpp>
#include <Preview/Foundation/Utility/Diagnose/Detail/SubmissionRecord.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace
{

    namespace Net = boost::asio;
    using Preview::Diagnose::Fields::Route;
    using Preview::Diagnose::Fields::Session;
    using Preview::Diagnose::Fields::Worker;
    using Preview::Diagnose::RenderMode;
    using Preview::Diagnose::ContextState;
    using Preview::Diagnose::Detail::ContextDecoder;
    using Preview::Diagnose::Detail::SubmissionRecord;

    TEST(PreviewDiagnose, CapturedContextOutlivesCoroutineAndOriginalOwner)
    {
        Net::io_context Ioc;
        std::optional<SubmissionRecord> CapturedRecord;
        std::exception_ptr Failure;

        Net::co_spawn(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                auto Context = ContextState::Empty()
                                   .With(Worker, Preview::WorkerId{3})
                                   .With(Session, Preview::SessionId{8});
                std::string RouteName{"owned-route"};
                const auto RouteView = std::string_view{RouteName};
                auto PerCall = Context.TryWith(Route, RouteView);
                if (!PerCall)
                {
                    throw std::runtime_error("per-call Context unexpectedly overflowed");
                }

                SubmissionRecord Record;
                Record.Context = ContextDecoder::Capture(*PerCall, RenderMode::Structured);
                Record.Message = "captured";
                CapturedRecord = std::move(Record);
                RouteName.clear();
                Context = ContextState::Empty();
                co_return;
            }(),
            [&](std::exception_ptr Error) { Failure = std::move(Error); });

        Ioc.run();

        ASSERT_FALSE(Failure);
        ASSERT_TRUE(CapturedRecord.has_value());
        const auto Json = ContextDecoder::RenderStructured(*CapturedRecord);
        EXPECT_NE(Json.find("owned-route"), std::string::npos);
        EXPECT_NE(Json.find("\"worker\":3"), std::string::npos);
        EXPECT_NE(Json.find("\"session\":8"), std::string::npos);
    }

} // namespace
