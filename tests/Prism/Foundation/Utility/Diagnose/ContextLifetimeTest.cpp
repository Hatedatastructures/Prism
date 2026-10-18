/**
 * @file ContextLifetimeTest.cpp
 * @brief 异步提交前快照拥有字段值的生命周期测试。
 */

#include <gtest/gtest.h>

#include <Prism/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <Prism/Foundation/Utility/Diagnose/RenderMode.hpp>
#include <Prism/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/ContextDecoder.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/ContextSnapshot.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/SubmissionRecord.hpp>

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
    using Prism::Diagnose::Fields::Route;
    using Prism::Diagnose::Fields::Session;
    using Prism::Diagnose::Fields::Worker;
    using Prism::Diagnose::RenderMode;
    using Prism::Diagnose::ContextState;
    using Prism::Diagnose::Detail::ContextDecoder;
    using Prism::Diagnose::Detail::SubmissionRecord;

    /**
     * @brief 在原始上下文释放前生成拥有型结构化提交记录。
     * @param CapturedRecord 接收完整拥有型记录的测试结果槽。
     * @return 完成上下文捕获和原始字段释放的异步操作。
     * @details 记录槽由测试持有到 Ioc.run() 返回，捕获完成后才清空借用的路由文本。
     */
    auto CaptureStructuredContext(std::optional<SubmissionRecord>& CapturedRecord)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        auto Context = ContextState::Empty()
                           .With(Worker, Prism::WorkerId{3})
                           .With(Session, Prism::SessionId{8});
        std::string RouteName{"owned-route"};
        const auto RouteView = std::string_view{RouteName};
        auto PerCall = Context.TryWith(Route, RouteView);
        if (!PerCall)
        {
            co_return Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable};
        }

        SubmissionRecord Record;
        Prism::Diagnose::Detail::ContextSnapshot Snapshot;
        if (!Snapshot.Capture(*PerCall))
        {
            co_return Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable};
        }
        Record.Context = Snapshot.Decode(RenderMode::Structured, {});
        Record.Message = "captured";
        CapturedRecord = std::move(Record);
        RouteName.clear();
        Context = ContextState::Empty();
        co_return Prism::Fault::Failure{};
    }

    TEST(PrismDiagnose, CapturedContextOutlivesCoroutineAndOriginalOwner)
    {
        Net::io_context Ioc;
        std::optional<SubmissionRecord> CapturedRecord;
        std::exception_ptr Fatal;
        Prism::Fault::Failure Failure;

        Net::co_spawn(
            Ioc, CaptureStructuredContext(CapturedRecord),
            [&](std::exception_ptr Error, Prism::Fault::Failure Result)
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
