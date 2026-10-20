/**
 * @file ContextDecoderTest.cpp
 * @brief Diagnose 三种渲染模式和字段安全测试。
 */

#include <gtest/gtest.h>

#include <Prism/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <Prism/Foundation/Utility/Diagnose/RenderMode.hpp>
#include <Prism/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/ContextDecoder.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/ContextSnapshot.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/Record.hpp>
#include <Prism/Foundation/Utility/Text/TraceSelection.hpp>

#include <string>
#include <string_view>

namespace
{

    using Prism::Diagnose::Fields::Correlation;
    using Prism::Diagnose::Fields::NativeError;
    using Prism::Diagnose::Fields::Protocol;
    using Prism::Diagnose::Fields::Route;
    using Prism::Diagnose::Fields::Session;
    using Prism::Diagnose::Fields::Stream;
    using Prism::Diagnose::Fields::Worker;
    using Prism::Diagnose::RenderMode;
    using Prism::Diagnose::SubmissionKind;
    using Prism::Diagnose::ContextState;
    using Prism::Diagnose::Detail::ContextDecoder;
    using Prism::Diagnose::Detail::SubmissionRecord;

    TEST(PrismDiagnose, HumanTimestampUsesStableUtcMilliseconds)
    {
        EXPECT_EQ(Prism::Diagnose::Detail::FormatHumanTimestamp(0U),
            "[1970-01-01 00:00:00.000] ");
        EXPECT_EQ(Prism::Diagnose::Detail::FormatHumanTimestamp(1710000000123U),
            "[2024-03-09 16:00:00.123] ");
    }

    TEST(PrismDiagnose, CompactHumanCapturesOnlyCachedWorkerSessionPrefix)
    {
        const auto Context = ContextState::Empty()
                                .With(Worker, Prism::WorkerId{7})
                                .With(Session, Prism::SessionId{9})
                                .With(Route, std::string_view{"route-a"});
        const Prism::Text::TraceSelection Selection{
            .IncludeCorrelation = true,
            .IncludeWorker = false,
            .IncludeSession = false,
            .IncludeStream = true};

        Prism::Diagnose::Detail::ContextSnapshot Snapshot;
        ASSERT_TRUE(Snapshot.Capture(Context));
        const auto Captured = Snapshot.Decode(RenderMode::CompactHuman, Selection);
        const auto Human = ContextDecoder::RenderHuman(Captured, "ready");

        EXPECT_EQ(Human, "[W7][S9] ready");
        EXPECT_TRUE(Captured.Fields.empty());
    }

    TEST(PrismDiagnose, HumanWithFieldsKeepsPrefixAndUsesTraceSelection)
    {
        const auto Context = ContextState::Empty()
                                .With(Worker, Prism::WorkerId{7})
                                .With(Session, Prism::SessionId{9})
                                .With(Route, std::string_view{"route-a"})
                                .TryWith(Correlation, Prism::RequestId{15});
        ASSERT_TRUE(Context.has_value());
        const Prism::Text::TraceSelection Selection{
            .IncludeCorrelation = true,
            .IncludeWorker = false,
            .IncludeSession = false,
            .IncludeStream = false};

        Prism::Diagnose::Detail::ContextSnapshot Snapshot;
        ASSERT_TRUE(Snapshot.Capture(*Context));
        const auto Captured = Snapshot.Decode(RenderMode::HumanWithFields, Selection);
        const auto Human = ContextDecoder::RenderHuman(Captured, "connected");

        EXPECT_NE(Human.find("[W7][S9]"), std::string::npos);
        EXPECT_NE(Human.find("[Correlation=15]"), std::string::npos);
        EXPECT_EQ(Human.find("route-a"), std::string::npos);
        EXPECT_NE(Human.find("connected"), std::string::npos);

        const Prism::Text::TraceSelection ExpandedSelection{
            .IncludeCorrelation = false,
            .IncludeWorker = true,
            .IncludeSession = true,
            .IncludeStream = false};
        const auto ExpandedContext = Snapshot.Decode(RenderMode::HumanWithFields, ExpandedSelection);
        const auto ExpandedHuman = ContextDecoder::RenderHuman(ExpandedContext, "connected");
        EXPECT_NE(ExpandedHuman.find("[W7][S9]"), std::string::npos);
        EXPECT_NE(ExpandedHuman.find("[Worker=7]"), std::string::npos);
        EXPECT_NE(ExpandedHuman.find("[Session=9]"), std::string::npos);
        EXPECT_EQ(ExpandedHuman.find("Correlation"), std::string::npos);
    }

    TEST(PrismDiagnose, LongLivedContextReplacementKeepsOnlyCurrentFieldValue)
    {
        auto Parent = ContextState::Empty().With(Route, std::string_view{"route-parent"});
        auto Current = Parent;
        for (std::size_t Index = 0U; Index < 32U; ++Index)
        {
            const auto Value = std::string{"route-old-"} + std::to_string(Index);
            Current = Current.With(Route, Value);
        }
        Current = Current.With(Route, std::string_view{"route-current"});

        Prism::Diagnose::Detail::ContextSnapshot ParentSnapshot;
        ASSERT_TRUE(ParentSnapshot.Capture(Parent));
        SubmissionRecord ParentRecord;
        ParentRecord.Context = ParentSnapshot.Decode(RenderMode::Structured, {});
        const auto ParentJson = ContextDecoder::RenderStructured(ParentRecord);
        EXPECT_NE(ParentJson.find("route-parent"), std::string::npos);

        Prism::Diagnose::Detail::ContextSnapshot CurrentSnapshot;
        ASSERT_TRUE(CurrentSnapshot.Capture(Current));
        SubmissionRecord CurrentRecord;
        CurrentRecord.Context = CurrentSnapshot.Decode(RenderMode::Structured, {});
        const auto CurrentJson = ContextDecoder::RenderStructured(CurrentRecord);
        EXPECT_NE(CurrentJson.find("route-current"), std::string::npos);
        EXPECT_EQ(CurrentJson.find("route-old-"), std::string::npos);
        EXPECT_EQ(Current.FieldCount(), 1U);
        EXPECT_EQ(Parent.FieldCount(), 1U);
    }

    TEST(PrismDiagnose, StructuredUsesCatalogOrderEscapesJsonAndRedactsSensitiveFields)
    {
        const auto Context = ContextState::Empty()
                                .With(Worker, Prism::WorkerId{7})
                                .With(Session, Prism::SessionId{9})
                                .With(Correlation, Prism::RequestId{6})
                                .With(Stream, Prism::StreamId{8})
                                .With(Route, std::string_view{"route-b"})
                                .With(Protocol, std::string_view{"Vless"})
                                .With(NativeError, std::string_view{"token=decoder-canary"});
        const Prism::Text::TraceSelection ExcludedSelection{
            .IncludeCorrelation = false,
            .IncludeWorker = false,
            .IncludeSession = false,
            .IncludeStream = false};
        Prism::Diagnose::Detail::ContextSnapshot Snapshot;
        ASSERT_TRUE(Snapshot.Capture(Context));
        const auto Captured = Snapshot.Decode(RenderMode::Structured, ExcludedSelection);

        SubmissionRecord Record;
        Record.TimestampMilliseconds = 123U;
        Record.Sequence = 101U;
        Record.Kind = SubmissionKind::Audit;
        Record.Message = "quote=\" slash=\\ newline=\n bad=";
        Record.Message.push_back(static_cast<char>(0xFF));
        Record.Context = Captured;

        const auto Json = ContextDecoder::RenderStructured(Record);
        const auto ProtocolPosition = Json.find("\"Protocol\"");
        const auto RoutePosition = Json.find("\"Route\"");

        EXPECT_LT(ProtocolPosition, RoutePosition);
        EXPECT_NE(Json.find("\"Worker\":7"), std::string::npos);
        EXPECT_NE(Json.find("\"Session\":9"), std::string::npos);
        EXPECT_NE(Json.find("\"Sequence\":101"), std::string::npos);
        EXPECT_NE(Json.find("\"Level\":\"Info\""), std::string::npos);
        EXPECT_NE(Json.find("\"Kind\":\"Audit\""), std::string::npos);
        EXPECT_EQ(Json.find("\"Thread\""), std::string::npos);
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
