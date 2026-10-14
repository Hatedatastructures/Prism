#include <gtest/gtest.h>

#include "WorkerTestSupport.hpp"

#include <Preview/Runtime/Detail/Mailbox.hpp>
#include <Preview/Runtime/WorkerDispatchResult.hpp>
#include <Preview/Runtime/Worker.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <latch>
#include <memory>
#include <thread>
#include <vector>

namespace
{

    using Preview::GenerationId;
    using Preview::Runtime::Detail::Mailbox;
    using Preview::Runtime::Worker;
    using Preview::Runtime::WorkerDispatchResult;
    using Preview::Runtime::WorkerTestAccess;

    struct MpscProducerContext final
    {
        Mailbox &Box;
        GenerationId Generation;
        std::size_t CommandsPerProducer;
        std::atomic<std::uint32_t> *ExecutionCounts;
        std::atomic<bool> *AcceptedFlags;
        std::atomic<std::size_t> &Accepted;
        std::atomic<std::size_t> &Full;
        std::atomic<std::size_t> &Closed;
        std::atomic<std::size_t> &Rejected;
    };

    auto RecordPostResult(MpscProducerContext &Context, const std::size_t Id,
                          const WorkerDispatchResult Result) -> void
    {
        switch (Result)
        {
        case WorkerDispatchResult::Accepted:
            if (Context.AcceptedFlags != nullptr)
            {
                Context.AcceptedFlags[Id].store(true, std::memory_order_release);
            }
            Context.Accepted.fetch_add(1, std::memory_order_relaxed);
            break;
        case WorkerDispatchResult::Full:
            Context.Full.fetch_add(1, std::memory_order_relaxed);
            break;
        case WorkerDispatchResult::Closed:
            Context.Closed.fetch_add(1, std::memory_order_relaxed);
            break;
        case WorkerDispatchResult::WorkerUnavailable:
        case WorkerDispatchResult::GenerationRejected:
            Context.Rejected.fetch_add(1, std::memory_order_relaxed);
            break;
        }
    }

    auto RunMpscProducer(MpscProducerContext &Context, const std::size_t Producer) -> void
    {
        for (std::size_t Sequence = 0; Sequence < Context.CommandsPerProducer; ++Sequence)
        {
            const auto Id = Producer * Context.CommandsPerProducer + Sequence;
            const auto Result = Context.Box.Post(
                Context.Generation,
                [Counts = Context.ExecutionCounts, Id]
                {
                    Counts[Id].fetch_add(1, std::memory_order_relaxed);
                });
            RecordPostResult(Context, Id, Result);
        }
    }

    struct HighCapacityContext final
    {
        Mailbox &Box;
        GenerationId Generation;
        std::size_t TotalCommands;
        std::size_t ProducerCount;
        std::atomic<std::size_t> &RemainingProducers;
        std::atomic<std::size_t> &Accepted;
        std::atomic<std::size_t> &Full;
        std::atomic<std::size_t> &Closed;
        std::atomic<std::size_t> &Rejected;
        std::atomic<std::size_t> &Consumed;
        std::atomic<std::size_t> &Empty;
    };

    auto RunHighCapacityProducer(HighCapacityContext &Context,
                                 const std::size_t Producer) -> void
    {
        for (std::size_t Index = Producer; Index < Context.TotalCommands;
             Index += Context.ProducerCount)
        {
            const auto Result = Context.Box.Post(
                Context.Generation,
                [Consumed = &Context.Consumed]
                { Consumed->fetch_add(1, std::memory_order_relaxed); });
            switch (Result)
            {
            case WorkerDispatchResult::Accepted:
                Context.Accepted.fetch_add(1, std::memory_order_relaxed);
                break;
            case WorkerDispatchResult::Full:
                Context.Full.fetch_add(1, std::memory_order_relaxed);
                break;
            case WorkerDispatchResult::Closed:
                Context.Closed.fetch_add(1, std::memory_order_relaxed);
                break;
            case WorkerDispatchResult::WorkerUnavailable:
            case WorkerDispatchResult::GenerationRejected:
                Context.Rejected.fetch_add(1, std::memory_order_relaxed);
                break;
            }
        }
        Context.RemainingProducers.fetch_sub(1, std::memory_order_acq_rel);
    }

    auto RunHighCapacityConsumer(HighCapacityContext &Context) -> void
    {
        for (;;)
        {
            Mailbox::Command Command;
            if (Context.Box.TryReceive(Command))
            {
                if (Command)
                {
                    Command();
                }
                else
                {
                    Context.Empty.fetch_add(1, std::memory_order_relaxed);
                }
                continue;
            }
            if (Context.RemainingProducers.load(std::memory_order_acquire) == 0 &&
                Context.Box.Size() == 0)
            {
                return;
            }
            std::this_thread::yield();
        }
    }

    TEST(Mailbox, EnforcesCapacityAndPreservesFifo)
    {
        Mailbox Box(Mailbox::Options{2, GenerationId{7}});
        std::vector<int> Seen;

        EXPECT_EQ(Box.Post(GenerationId{7}, [&Seen] { Seen.push_back(1); }), WorkerDispatchResult::Accepted);
        EXPECT_EQ(Box.Post(GenerationId{7}, [&Seen] { Seen.push_back(2); }), WorkerDispatchResult::Accepted);
        EXPECT_EQ(Box.Post(GenerationId{7}, [&Seen] { Seen.push_back(3); }), WorkerDispatchResult::Full);

        Mailbox::Command Command;
        ASSERT_TRUE(Box.TryReceive(Command));
        Command();
        ASSERT_TRUE(Box.TryReceive(Command));
        Command();
        EXPECT_FALSE(Box.TryReceive(Command));
        EXPECT_EQ(Seen, (std::vector<int>{1, 2}));

        EXPECT_EQ(Box.Post(GenerationId{7}, [&Seen] { Seen.push_back(3); }), WorkerDispatchResult::Accepted);
    }

    TEST(Mailbox, RejectsClosedAndStaleGenerations)
    {
        Mailbox Box(Mailbox::Options{1, GenerationId{11}});

        EXPECT_EQ(Box.Post(GenerationId{10}, [] {}), WorkerDispatchResult::GenerationRejected);
        EXPECT_EQ(Box.Size(), 0U);
        Box.Close();
        EXPECT_TRUE(Box.IsClosed());
        EXPECT_EQ(Box.Post(GenerationId{11}, [] {}), WorkerDispatchResult::Closed);
        EXPECT_EQ(Box.Size(), 0U);
    }

    TEST(Mailbox, MpscProducersExecuteAcceptedCommandsExactlyOnce)
    {
        constexpr std::size_t ProducerCount = 4;
        constexpr std::size_t CommandsPerProducer = 64;
        constexpr std::size_t CommandCount = ProducerCount * CommandsPerProducer;
        const GenerationId Generation{17};
        Mailbox Box(Mailbox::Options{CommandCount, Generation});
        auto ExecutionCounts = std::make_unique<std::atomic<std::uint32_t>[]>(CommandCount);
        for (std::size_t Index = 0; Index < CommandCount; ++Index)
        {
            ExecutionCounts[Index].store(0, std::memory_order_relaxed);
        }

        std::latch Ready(static_cast<std::ptrdiff_t>(ProducerCount));
        std::latch Start(1);
        std::atomic<std::size_t> Accepted{0};
        std::atomic<std::size_t> Full{0};
        std::atomic<std::size_t> Closed{0};
        std::atomic<std::size_t> GenerationRejected{0};
        std::vector<std::thread> Producers;
        Producers.reserve(ProducerCount);
        MpscProducerContext Context{Box,
                                    Generation,
                                    CommandsPerProducer,
                                    ExecutionCounts.get(),
                                    nullptr,
                                    Accepted,
                                    Full,
                                    Closed,
                                    GenerationRejected};

        for (std::size_t Producer = 0; Producer < ProducerCount; ++Producer)
        {
            Producers.emplace_back(
                [&Ready, &Start, &Context, Producer]
                {
                    Ready.count_down();
                    Start.wait();
                    RunMpscProducer(Context, Producer);
                });
        }

        Ready.wait();
        Start.count_down();
        for (auto &Producer : Producers)
        {
            Producer.join();
        }

        std::size_t Received = 0;
        Mailbox::Command Command;
        while (Box.TryReceive(Command))
        {
            ASSERT_TRUE(static_cast<bool>(Command));
            Command();
            ++Received;
        }

        EXPECT_EQ(Accepted.load(std::memory_order_relaxed), CommandCount);
        EXPECT_EQ(Full.load(std::memory_order_relaxed), 0U);
        EXPECT_EQ(Closed.load(std::memory_order_relaxed), 0U);
        EXPECT_EQ(GenerationRejected.load(std::memory_order_relaxed), 0U);
        EXPECT_EQ(Received, CommandCount);
        EXPECT_EQ(Box.Size(), 0U);
        for (std::size_t Index = 0; Index < CommandCount; ++Index)
        {
            EXPECT_EQ(ExecutionCounts[Index].load(std::memory_order_relaxed), 1U)
                << "command=" << Index;
        }
    }

    TEST(Mailbox, HighCapacityMpscNeverReportsFull)
    {
        constexpr std::size_t TotalCommands = 100'000;
        constexpr std::size_t Capacity = 131'072;
        constexpr std::size_t RepeatCount = 5;
        constexpr std::array<std::size_t, 2> ProducerCounts{2, 4};

        for (const auto ProducerCount : ProducerCounts)
        {
            for (std::size_t Repeat = 0; Repeat < RepeatCount; ++Repeat)
            {
                const GenerationId Generation{
                    100 + static_cast<std::uint64_t>(ProducerCount * Repeat)};
                Mailbox Box(Mailbox::Options{Capacity, Generation});
                std::atomic<std::size_t> RemainingProducers{ProducerCount};
                std::atomic<std::size_t> Accepted{0};
                std::atomic<std::size_t> Full{0};
                std::atomic<std::size_t> Closed{0};
                std::atomic<std::size_t> Rejected{0};
                std::atomic<std::size_t> Consumed{0};
                std::atomic<std::size_t> Empty{0};
                HighCapacityContext Context{Box,
                                            Generation,
                                            TotalCommands,
                                            ProducerCount,
                                            RemainingProducers,
                                            Accepted,
                                            Full,
                                            Closed,
                                            Rejected,
                                            Consumed,
                                            Empty};

                std::latch Ready(static_cast<std::ptrdiff_t>(ProducerCount + 1));
                std::latch Start(1);
                std::vector<std::thread> Threads;
                Threads.reserve(ProducerCount + 1);
                Threads.emplace_back(
                    [&Ready, &Start, &Context]
                    {
                        Ready.count_down();
                        Start.wait();
                        RunHighCapacityConsumer(Context);
                    });
                for (std::size_t Producer = 0; Producer < ProducerCount; ++Producer)
                {
                    Threads.emplace_back(
                        [&Ready, &Start, &Context, Producer]
                        {
                            Ready.count_down();
                            Start.wait();
                            RunHighCapacityProducer(Context, Producer);
                        });
                }

                Ready.wait();
                Start.count_down();
                for (auto &Thread : Threads)
                {
                    Thread.join();
                }

                EXPECT_EQ(Accepted.load(std::memory_order_relaxed), TotalCommands)
                    << "producers=" << ProducerCount << " repeat=" << Repeat;
                EXPECT_EQ(Full.load(std::memory_order_relaxed), 0U)
                    << "producers=" << ProducerCount << " repeat=" << Repeat;
                EXPECT_EQ(Closed.load(std::memory_order_relaxed), 0U)
                    << "producers=" << ProducerCount << " repeat=" << Repeat;
                EXPECT_EQ(Rejected.load(std::memory_order_relaxed), 0U)
                    << "producers=" << ProducerCount << " repeat=" << Repeat;
                EXPECT_EQ(RemainingProducers.load(std::memory_order_relaxed), 0U)
                    << "producers=" << ProducerCount << " repeat=" << Repeat;
                EXPECT_EQ(Consumed.load(std::memory_order_relaxed), TotalCommands)
                    << "producers=" << ProducerCount << " repeat=" << Repeat;
                EXPECT_EQ(Empty.load(std::memory_order_relaxed), 0U)
                    << "producers=" << ProducerCount << " repeat=" << Repeat;
                EXPECT_EQ(Box.Size(), 0U)
                    << "producers=" << ProducerCount << " repeat=" << Repeat;
            }
        }
    }

    TEST(Mailbox, CloseRaceDrainsAcceptedAndReservedTickets)
    {
        constexpr std::size_t ProducerCount = 4;
        constexpr std::size_t CommandsPerProducer = 32;
        constexpr std::size_t CommandCount = ProducerCount * CommandsPerProducer;
        const GenerationId Generation{23};
        Mailbox Box(Mailbox::Options{CommandCount, Generation});
        auto ExecutionCounts = std::make_unique<std::atomic<std::uint32_t>[]>(CommandCount);
        auto AcceptedFlags = std::make_unique<std::atomic<bool>[]>(CommandCount);
        for (std::size_t Index = 0; Index < CommandCount; ++Index)
        {
            ExecutionCounts[Index].store(0, std::memory_order_relaxed);
            AcceptedFlags[Index].store(false, std::memory_order_relaxed);
        }

        std::latch Ready(static_cast<std::ptrdiff_t>(ProducerCount));
        std::latch Start(1);
        std::atomic<std::size_t> Accepted{0};
        std::atomic<std::size_t> Full{0};
        std::atomic<std::size_t> Closed{0};
        std::atomic<std::size_t> Rejected{0};
        std::vector<std::thread> Producers;
        Producers.reserve(ProducerCount);
        MpscProducerContext Context{Box,
                                    Generation,
                                    CommandsPerProducer,
                                    ExecutionCounts.get(),
                                    AcceptedFlags.get(),
                                    Accepted,
                                    Full,
                                    Closed,
                                    Rejected};

        for (std::size_t Producer = 0; Producer < ProducerCount; ++Producer)
        {
            Producers.emplace_back(
                [&Ready, &Start, &Context, Producer]
                {
                    Ready.count_down();
                    Start.wait();
                    RunMpscProducer(Context, Producer);
                });
        }

        Ready.wait();
        Start.count_down();
        Box.Close();
        for (auto &Producer : Producers)
        {
            Producer.join();
        }

        std::size_t ReceivedCommands = 0;
        std::size_t EmptyTickets = 0;
        Mailbox::Command Command;
        while (Box.TryReceive(Command))
        {
            if (Command)
            {
                Command();
                ++ReceivedCommands;
            }
            else
            {
                ++EmptyTickets;
            }
        }

        EXPECT_TRUE(Box.IsClosed());
        EXPECT_EQ(Accepted.load(std::memory_order_relaxed) +
                      Full.load(std::memory_order_relaxed) +
                      Closed.load(std::memory_order_relaxed),
                  CommandCount);
        EXPECT_EQ(Rejected.load(std::memory_order_relaxed), 0U);
        EXPECT_EQ(ReceivedCommands, Accepted.load(std::memory_order_relaxed));
        EXPECT_LE(EmptyTickets, Closed.load(std::memory_order_relaxed));
        EXPECT_EQ(Box.Size(), 0U);
        for (std::size_t Index = 0; Index < CommandCount; ++Index)
        {
            const auto Executions = ExecutionCounts[Index].load(std::memory_order_relaxed);
            const auto WasAccepted = AcceptedFlags[Index].load(std::memory_order_acquire);
            EXPECT_EQ(Executions, WasAccepted ? 1U : 0U) << "command=" << Index;
        }
        // 公共 API 无法稳定暂停在“已取 ticket、尚未发布”的窗口；此处只验证
        // 关闭竞态完成后，已发布命令和空槽都能被单消费者推进并最终清空。
    }

    TEST(Mailbox, WorkerStopDropsQueuedCommandsAndReleasesAfterRunJoin)
    {
        Worker::Options Options;
        Options.Process = Preview::ProcessId{2};
        Options.Id = Preview::WorkerId{1};
        Options.Generation = GenerationId{29};
        Options.MailboxCapacity = 2;

        std::atomic<std::size_t> Executed{0};
        std::weak_ptr<int> Lifetime;
        {
            auto Marker = std::make_shared<int>(1);
            Lifetime = Marker;
            Worker WorkerValue(Options);
            EXPECT_EQ(WorkerValue.Dispatch(
                          Options.Generation,
                          [Marker, &Executed]
                          {
                              (void)Marker;
                              Executed.fetch_add(1, std::memory_order_relaxed);
                          }),
                      WorkerDispatchResult::Accepted);
            Marker.reset();
            EXPECT_EQ(WorkerValue.Snapshot().MailboxSize, 1U);

            WorkerValue.Stop();
            std::thread Runner([&WorkerValue] { WorkerValue.Run(); });
            Runner.join();

            EXPECT_FALSE(WorkerValue.IsRunning());
            EXPECT_FALSE(WorkerValue.IsAccepting());
            EXPECT_EQ(Executed.load(std::memory_order_relaxed), 0U);
            EXPECT_TRUE(WorkerTestAccess::IsMailboxClosed(WorkerValue));
        }
        EXPECT_TRUE(Lifetime.expired());
    }

} // namespace
