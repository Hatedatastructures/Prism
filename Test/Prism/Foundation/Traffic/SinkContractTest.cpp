/**
 * @file TrafficSinkContractTest.cpp
 * @brief 流量观察基础契约测试
 * @details 验证字节增量和终结事件携带同一数值 owner，方向与失败事实保持准确。
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <memory>
#include <utility>

#include <Prism/Foundation/Utility/TrafficSink.hpp>

namespace
{

    class RecordingSink final : public Prism::Foundation::TrafficSink
    {
    public:
        auto Report(Prism::Foundation::TrafficEvent Event) noexcept -> void override
        {
            if (Count_ < Events_.size()) Events_[Count_++] = Event;
        }

        auto Retire(Prism::Foundation::TrafficRetirement Owner)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override
        { (void)Owner; co_return std::expected<void, Prism::Fault::Failure>{}; }

        std::array<Prism::Foundation::TrafficEvent, 3> Events_{};
        std::size_t Count_{0};
    };

    TEST(TrafficSinkContract, ReportsProtocolTraffic)
    {
        auto Sink = std::make_shared<RecordingSink>();
        Prism::Foundation::TrafficObservation Observation{
            Sink,
            Prism::Foundation::TrafficEvent{
                .Generation = Prism::GenerationId{4},
                .Worker = Prism::WorkerId{2},
                .Session = Prism::SessionId{9},
                .Account = Prism::AccountId{7}}};

        Observation.Transfer(128, Prism::Foundation::TrafficObservation::Direction::Upload);
        Observation.Transfer(256, Prism::Foundation::TrafficObservation::Direction::Download);
        Observation.Complete(Prism::Fault::Failure{Prism::Fault::Code::Timeout});

        ASSERT_EQ(Sink->Count_, 3U);
        EXPECT_EQ(Sink->Events_[0].Kind, Prism::Foundation::TrafficEventKind::Bytes);
        EXPECT_EQ(Sink->Events_[0].Generation, Prism::GenerationId{4});
        EXPECT_EQ(Sink->Events_[0].Worker, Prism::WorkerId{2});
        EXPECT_EQ(Sink->Events_[0].Session, Prism::SessionId{9});
        EXPECT_EQ(Sink->Events_[0].Account, Prism::AccountId{7});
        EXPECT_FALSE(Sink->Events_[0].Failure.Failed());
        EXPECT_EQ(Sink->Events_[0].Up, 128U);
        EXPECT_EQ(Sink->Events_[0].Down, 0U);
        EXPECT_EQ(Sink->Events_[1].Kind, Prism::Foundation::TrafficEventKind::Bytes);
        EXPECT_EQ(Sink->Events_[1].Generation, Prism::GenerationId{4});
        EXPECT_EQ(Sink->Events_[1].Worker, Prism::WorkerId{2});
        EXPECT_EQ(Sink->Events_[1].Session, Prism::SessionId{9});
        EXPECT_EQ(Sink->Events_[1].Account, Prism::AccountId{7});
        EXPECT_EQ(Sink->Events_[1].Up, 0U);
        EXPECT_EQ(Sink->Events_[1].Down, 256U);
        EXPECT_EQ(Sink->Events_[2].Kind, Prism::Foundation::TrafficEventKind::Completed);
        EXPECT_EQ(Sink->Events_[2].Generation, Prism::GenerationId{4});
        EXPECT_EQ(Sink->Events_[2].Worker, Prism::WorkerId{2});
        EXPECT_EQ(Sink->Events_[2].Session, Prism::SessionId{9});
        EXPECT_EQ(Sink->Events_[2].Account, Prism::AccountId{7});
        EXPECT_EQ(Sink->Events_[2].Up, 0U);
        EXPECT_EQ(Sink->Events_[2].Down, 0U);
        EXPECT_EQ(Sink->Events_[2].Failure.Code, Prism::Fault::Code::Timeout);
    }

} // namespace
