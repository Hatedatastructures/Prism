/**
 * @file SessionHeaderContractTest.cpp
 * @brief HTTP/3 会话职责头和公开聚合入口契约。
 */

#include <Prism/Protocols/Http3/Detail/SessionContract.hpp>
#include <Prism/Protocols/Http3/Session.hpp>

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <type_traits>
#include <vector>

namespace
{

    static_assert(!std::is_copy_constructible_v<Prism::Http3::Session>);
    static_assert(!std::is_copy_assignable_v<Prism::Http3::Session>);

    static_assert(requires(Prism::Http3::Session &Session,
                           std::vector<Prism::Http3::OutPacket> &Output)
                  {
                      Session.Init(std::function<std::int64_t()>{});
                      Session.Feed(0, std::span<const std::byte>{}, false);
                      Session.TakeEvent();
                      Session.PumpOutput(Output);
                      Session.AddWriteOffset(0, 0);
                      Session.IsOpen();
                      Session.Native();
                      Session.Close();
                  });

    TEST(Http3SessionHeaderContract, AggregateKeepsUninitializedSessionClosed)
    {
        Prism::Http3::Session Session;
        EXPECT_FALSE(Session.IsOpen());
        EXPECT_EQ(
            Session.Feed(0, std::span<const std::byte>{}, false),
            Prism::Fault::Code::ProtocolError);

        std::vector<Prism::Http3::OutPacket> Output;
        EXPECT_FALSE(Session.PumpOutput(Output));
        EXPECT_FALSE(Session.TakeEvent().has_value());
        Session.Close();
        EXPECT_FALSE(Session.IsOpen());
    }

    TEST(Http3SessionHeaderContract, NativeMatchesOpenStateAcrossLifecycle)
    {
        Prism::Http3::Session Session;
        EXPECT_FALSE(Session.IsOpen());
        EXPECT_EQ(Session.Native(), Session.IsOpen());

        bool NativeMatchesOpenDuringStreamOpen = false;
        std::int64_t NextStreamId = 3;
        ASSERT_TRUE(Session.Init([&]()
        {
            NativeMatchesOpenDuringStreamOpen = Session.Native() == Session.IsOpen();
            const auto StreamId = NextStreamId;
            NextStreamId += 4;
            return StreamId;
        }));

        EXPECT_TRUE(NativeMatchesOpenDuringStreamOpen);
        EXPECT_TRUE(Session.IsOpen());
        EXPECT_EQ(Session.Native(), Session.IsOpen());
        Session.Close();
        EXPECT_EQ(Session.Native(), Session.IsOpen());
        EXPECT_FALSE(Session.Native());
        EXPECT_FALSE(Session.IsOpen());
    }

} // namespace
