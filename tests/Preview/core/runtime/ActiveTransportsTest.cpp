#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

#include <Preview/Runtime/ActiveTransports.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace
{

    TEST(ActiveTransports, ConcurrentStoreAndLoadKeepsTransmissionOwnership)
    {
        boost::asio::io_context IoContext;
        auto First = std::make_shared<Preview::PreviewMockTransport>(IoContext.get_executor());
        auto Second = std::make_shared<Preview::PreviewMockTransport>(IoContext.get_executor());
        Preview::Runtime::ActiveTransports Active;
        std::atomic_bool Failed{false};
        std::vector<std::thread> Threads;

        for (int Index = 0; Index < 4; ++Index)
        {
            Threads.emplace_back([&, Index]
                                 {
                                     for (int Iteration = 0; Iteration < 10000; ++Iteration)
                                     {
                                         auto Value = ((Iteration + Index) % 2 == 0) ? First : Second;
                                         Active.StoreInbound(Value);
                                         Active.StoreOutbound(Value);
                                         const auto Snapshot = Active.Load();
                                         if ((Snapshot.Inbound && Snapshot.Inbound != First &&
                                              Snapshot.Inbound != Second) ||
                                             (Snapshot.Outbound && Snapshot.Outbound != First &&
                                              Snapshot.Outbound != Second))
                                         {
                                             Failed.store(true, std::memory_order_release);
                                         }
                                     }
                                 });
        }

        for (auto &Thread : Threads)
        {
            Thread.join();
        }

        EXPECT_FALSE(Failed.load(std::memory_order_acquire));
        const auto Final = Active.Load();
        EXPECT_TRUE(Final.Inbound);
        EXPECT_TRUE(Final.Outbound);
    }

} // namespace
