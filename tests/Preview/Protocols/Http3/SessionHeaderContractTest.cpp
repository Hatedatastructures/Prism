/**
 * @file SessionHeaderContractTest.cpp
 * @brief HTTP/3 会话职责头和公开聚合入口契约。
 */

#include <Preview/Protocols/Http3/Detail/SessionCallbacks.hpp>
#include <Preview/Protocols/Http3/Detail/SessionInput.hpp>
#include <Preview/Protocols/Http3/Detail/SessionLifecycle.hpp>
#include <Preview/Protocols/Http3/Detail/SessionOutput.hpp>
#include <Preview/Protocols/Http3/Session.hpp>

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <type_traits>
#include <vector>

namespace
{

    static_assert(!std::is_copy_constructible_v<Preview::Http3::Session>);
    static_assert(!std::is_copy_assignable_v<Preview::Http3::Session>);
    static_assert(requires(Preview::Http3::Session &Session,
                           std::vector<Preview::Http3::OutPacket> &Output)
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
        Preview::Http3::Session Session;
        EXPECT_FALSE(Session.IsOpen());
        EXPECT_EQ(
            Session.Feed(0, std::span<const std::byte>{}, false),
            Preview::Fault::Code::ProtocolError);

        std::vector<Preview::Http3::OutPacket> Output;
        EXPECT_FALSE(Session.PumpOutput(Output));
        EXPECT_FALSE(Session.TakeEvent().has_value());
        Session.Close();
        EXPECT_FALSE(Session.IsOpen());
    }

} // namespace
