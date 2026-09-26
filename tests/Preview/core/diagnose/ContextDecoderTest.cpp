/**
 * @file ContextDecoderTest.cpp
 * @brief Diagnose 三种渲染模式和字段安全测试。
 */

#include <gtest/gtest.h>

#include <Preview/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <Preview/Foundation/Utility/Diagnose/RenderMode.hpp>
#include <Preview/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Preview/Foundation/Utility/Diagnose/Detail/ContextDecoder.hpp>
#include <Preview/Foundation/Utility/Diagnose/Detail/SubmissionRecord.hpp>
#include <Preview/Statistics/Trace.hpp>

#include <string>
#include <string_view>

namespace
{

    using Preview::Diagnose::Fields::Correlation;
    using Preview::Diagnose::Fields::NativeError;
    using Preview::Diagnose::Fields::Protocol;
    using Preview::Diagnose::Fields::Route;
    using Preview::Diagnose::Fields::Session;
    using Preview::Diagnose::Fields::Stream;
    using Preview::Diagnose::Fields::Worker;
    using Preview::Diagnose::RenderMode;
    using Preview::Diagnose::SubmissionKind;
    using Preview::Diagnose::ContextState;
    using Preview::Diagnose::Detail::ContextDecoder;
    using Preview::Diagnose::Detail::SubmissionRecord;

    TEST(PreviewDiagnose, CompactHumanCapturesOnlyCachedWorkerSessionPrefix)
    {
        const auto Context = ContextState::Empty()
                                .With(Worker, Preview::WorkerId{7})
                                .With(Session, Preview::SessionId{9})
                                .With(Route, std::string_view{"route-a"});
        const Preview::Statistics::TraceSelection Selection{
            .IncludeCorrelation = true,
            .IncludeWorker = false,
            .IncludeSession = false,
            .IncludeStream = true};

        const auto Captured = ContextDecoder::Capture(Context, RenderMode::CompactHuman, Selection);
        const auto Human = ContextDecoder::RenderHuman(Captured, "ready");

        EXPECT_EQ(Human, "[W7][S9] ready");
        EXPECT_TRUE(Captured.Fields.empty());
    }

    TEST(PreviewDiagnose, HumanWithFieldsKeepsPrefixAndUsesTraceSelection)
    {
        const auto Context = ContextState::Empty()
                                .With(Worker, Preview::WorkerId{7})
                                .With(Session, Preview::SessionId{9})
                                .With(Route, std::string_view{"route-a"})
                                .TryWith(Correlation, Preview::RequestId{15});
        ASSERT_TRUE(Context.has_value());
        const Preview::Statistics::TraceSelection Selection{
            .IncludeCorrelation = true,
            .IncludeWorker = false,
            .IncludeSession = false,
            .IncludeStream = false};

        const auto Captured = ContextDecoder::Capture(
            *Context, RenderMode::HumanWithFields, Selection);
        const auto Human = ContextDecoder::RenderHuman(Captured, "connected");

        EXPECT_NE(Human.find("[W7][S9]"), std::string::npos);
        EXPECT_NE(Human.find("[Correlation=15]"), std::string::npos);
        EXPECT_EQ(Human.find("route-a"), std::string::npos);
        EXPECT_NE(Human.find("connected"), std::string::npos);

        const Preview::Statistics::TraceSelection ExpandedSelection{
            .IncludeCorrelation = false,
            .IncludeWorker = true,
            .IncludeSession = true,
            .IncludeStream = false};
        const auto ExpandedContext = ContextDecoder::Capture(
            *Context, RenderMode::HumanWithFields, ExpandedSelection);
        const auto ExpandedHuman = ContextDecoder::RenderHuman(ExpandedContext, "connected");
        EXPECT_NE(ExpandedHuman.find("[W7][S9]"), std::string::npos);
        EXPECT_NE(ExpandedHuman.find("[Worker=7]"), std::string::npos);
        EXPECT_NE(ExpandedHuman.find("[Session=9]"), std::string::npos);
        EXPECT_EQ(ExpandedHuman.find("Correlation"), std::string::npos);
    }

    TEST(PreviewDiagnose, StructuredUsesCatalogOrderEscapesJsonAndRedactsSensitiveFields)
    {
        const auto Context = ContextState::Empty()
                                .With(Worker, Preview::WorkerId{7})
                                .With(Session, Preview::SessionId{9})
                                .With(Correlation, Preview::RequestId{6})
                                .With(Stream, Preview::StreamId{8})
                                .With(Route, std::string_view{"route-b"})
                                .With(Protocol, std::string_view{"vless"})
                                .With(NativeError, std::string_view{"token=decoder-canary"});
        const Preview::Statistics::TraceSelection ExcludedSelection{
            .IncludeCorrelation = false,
            .IncludeWorker = false,
            .IncludeSession = false,
            .IncludeStream = false};
        const auto Captured = ContextDecoder::Capture(
            Context, RenderMode::Structured, ExcludedSelection);

        SubmissionRecord Record;
        Record.TimestampMilliseconds = 123U;
        Record.ThreadId = 45U;
        Record.Sequence = 101U;
        Record.Kind = SubmissionKind::Audit;
        Record.Message = "quote=\" slash=\\ newline=\n bad=";
        Record.Message.push_back(static_cast<char>(0xFF));
        Record.Context = Captured;

        const auto Json = ContextDecoder::RenderStructured(Record);
        const auto ProtocolPosition = Json.find("\"Protocol\"");
        const auto RoutePosition = Json.find("\"Route\"");

        EXPECT_LT(ProtocolPosition, RoutePosition);
        EXPECT_NE(Json.find("\"worker\":7"), std::string::npos);
        EXPECT_NE(Json.find("\"session\":9"), std::string::npos);
        EXPECT_NE(Json.find("\"sequence\":101"), std::string::npos);
        EXPECT_NE(Json.find("\"kind\":\"audit\""), std::string::npos);
        EXPECT_EQ(Json.find("\"Worker\":7"), std::string::npos);
        EXPECT_EQ(Json.find("\"Session\":9"), std::string::npos);
        EXPECT_NE(Json.find("\"Correlation\":6"), std::string::npos);
        EXPECT_NE(Json.find("\"Stream\":8"), std::string::npos);
        EXPECT_NE(Json.find("token=<redacted>"), std::string::npos);
        EXPECT_EQ(Json.find("decoder-canary"), std::string::npos);
        EXPECT_NE(Json.find("quote=\\\""), std::string::npos);
        EXPECT_NE(Json.find("newline=\\u000A"), std::string::npos);
        EXPECT_NE(Json.find("\\uFFFD"), std::string::npos);
        ASSERT_FALSE(Json.empty());
        EXPECT_EQ(Json.back(), '\n');
        EXPECT_EQ(Json.find('\n'), Json.size() - 1U);
    }

} // namespace
