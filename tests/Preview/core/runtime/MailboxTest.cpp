#include <gtest/gtest.h>

#include <Preview/Runtime/Mailbox.hpp>

#include <vector>

namespace
{

    using Preview::GenerationId;
    using Preview::Runtime::Mailbox;

    TEST(Mailbox, EnforcesCapacityAndPreservesFifo)
    {
        Mailbox Box(Mailbox::Options{2, GenerationId{7}});
        std::vector<int> Seen;

        EXPECT_EQ(Box.Post(GenerationId{7}, [&Seen] { Seen.push_back(1); }), Mailbox::Result::Accepted);
        EXPECT_EQ(Box.Post(GenerationId{7}, [&Seen] { Seen.push_back(2); }), Mailbox::Result::Accepted);
        EXPECT_EQ(Box.Post(GenerationId{7}, [&Seen] { Seen.push_back(3); }), Mailbox::Result::Full);

        Mailbox::Command Command;
        ASSERT_TRUE(Box.TryReceive(Command));
        Command();
        ASSERT_TRUE(Box.TryReceive(Command));
        Command();
        EXPECT_FALSE(Box.TryReceive(Command));
        EXPECT_EQ(Seen, (std::vector<int>{1, 2}));

        EXPECT_EQ(Box.Post(GenerationId{7}, [&Seen] { Seen.push_back(3); }), Mailbox::Result::Accepted);
    }

    TEST(Mailbox, RejectsClosedAndStaleGenerations)
    {
        Mailbox Box(Mailbox::Options{1, GenerationId{11}});

        EXPECT_EQ(Box.Post(GenerationId{10}, [] {}), Mailbox::Result::GenerationRejected);
        Box.Close();
        EXPECT_TRUE(Box.IsClosed());
        EXPECT_EQ(Box.Post(GenerationId{11}, [] {}), Mailbox::Result::Closed);
    }

} // namespace
