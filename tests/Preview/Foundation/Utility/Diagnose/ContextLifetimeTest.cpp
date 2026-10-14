/**
 * @file ContextLifetimeTest.cpp
 * @brief 异步提交前快照拥有字段值的生命周期测试。
 */

#include <gtest/gtest.h>

#include <Preview/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <Preview/Foundation/Utility/Diagnose/RenderMode.hpp>
#include <Preview/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Preview/Foundation/Utility/Diagnose/Detail/ContextDecoder.hpp>
#include <Preview/Foundation/Utility/Diagnose/Detail/ContextSnapshot.hpp>
#include <Preview/Foundation/Utility/Diagnose/Detail/SubmissionRecord.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <exception>
#include <memory>
#include <optional>
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

    /**
     * @brief 在原始上下文释放前生成拥有型结构化提交记录。
     * @param CapturedRecord 接收完整拥有型记录的测试结果槽。
     * @return 完成上下文捕获和原始字段释放的异步操作。
     * @details 记录槽由测试持有到 Ioc.run() 返回，捕获完成后才清空借用的路由文本。
     */
    auto CaptureStructuredContext(std::optional<SubmissionRecord>& CapturedRecord)
        -> Net::awaitable<Preview::Fault::Failure>
    {
        auto Context = ContextState::Empty()
                           .With(Worker, Preview::WorkerId{3})
                           .With(Session, Preview::SessionId{8});
        std::string RouteName{"owned-route"};
        const auto RouteView = std::string_view{RouteName};
        auto PerCall = Context.TryWith(Route, RouteView);
        if (!PerCall)
        {
            co_return Preview::Fault::Failure{Preview::Fault::Code::ResourceUnavailable};
        }

        SubmissionRecord Record;
        Preview::Diagnose::Detail::ContextSnapshot Snapshot;
        if (!Snapshot.Capture(*PerCall))
        {
            co_return Preview::Fault::Failure{Preview::Fault::Code::ResourceUnavailable};
        }
        Record.Context = Snapshot.Decode(RenderMode::Structured, {});
        Record.Message = "captured";
        CapturedRecord = std::move(Record);
        RouteName.clear();
        Context = ContextState::Empty();
        co_return Preview::Fault::Failure{};
    }

    TEST(PreviewDiagnose, CapturedContextOutlivesCoroutineAndOriginalOwner)
    {
        Net::io_context Ioc;
        std::optional<SubmissionRecord> CapturedRecord;
        std::exception_ptr Fatal;
        Preview::Fault::Failure Failure;

        Net::co_spawn(
            Ioc, CaptureStructuredContext(CapturedRecord),
            [&](std::exception_ptr Error, Preview::Fault::Failure Result)
            { Fatal = std::move(Error); Failure = Result; });

        Ioc.run();

        ASSERT_FALSE(Fatal || Failure.Failed());
        ASSERT_TRUE(CapturedRecord.has_value());
        const auto Json = ContextDecoder::RenderStructured(*CapturedRecord);
        EXPECT_NE(Json.find("owned-route"), std::string::npos);
        EXPECT_NE(Json.find("\"Worker\":3"), std::string::npos);
        EXPECT_NE(Json.find("\"Session\":8"), std::string::npos);
    }

} // namespace
