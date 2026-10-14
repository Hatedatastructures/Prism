/**
 * @file RecognitionProbeRouteTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "RecognitionTestSupport.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>

#include <exception>

namespace
{
    /** @brief 写入 TLS 预读首包并验证回放字节。 */
    auto RunProbeAndRewindScenario(
        const std::shared_ptr<Preview::MemoryStream> &Source,
        const std::shared_ptr<Preview::MemoryStream> &Peer) -> Net::awaitable<void>
    {
        std::array<std::byte, 4> Tls{
            std::byte{0x16}, std::byte{0x03}, std::byte{0x01}, std::byte{0x00}};
        EXPECT_FALSE((co_await Peer->WriteSome(Tls)).Failure.Failed());
        auto ProbeResult = co_await rec::Probe(*Source);
        EXPECT_EQ(ProbeResult.Type, Preview::Contract::ProtocolType::Tls);
        EXPECT_EQ(ProbeResult.PreReadSize, 4U);
        auto Rewound = rec::WrapPreread(
            Source, std::span<const std::byte>(ProbeResult.PreRead.data(), ProbeResult.PreReadSize),
            std::make_shared<Preview::Memory::BytePool>(
                Preview::Memory::BytePoolOptions{.BlockCount = 1}));
        std::array<std::byte, 22> Buffer{};
        const auto Part = co_await Rewound->ReadSome(Buffer);
        EXPECT_EQ(Part.Bytes, 4U);
        EXPECT_EQ(Buffer[0], std::byte{0x16});
    }

    /** @brief 按字节分片写入 TLS prefix。 */
    auto RunFragmentedTlsWrite(const std::shared_ptr<Preview::MemoryStream> &Peer)
        -> Net::awaitable<void>
    {
        const std::array<std::byte, 4> Tls{
            std::byte{0x16}, std::byte{0x03}, std::byte{0x01}, std::byte{0x00}};
        for (const auto Byte : Tls)
        {
            const std::array<std::byte, 1> One{Byte};
            EXPECT_FALSE((co_await Peer->WriteSome(One)).Failure.Failed());
            co_await Net::post(Peer->Executor(), Net::use_awaitable);
        }
    }

    /** @brief 分片写入 SOCKS5 greeting。 */
    auto RunFragmentedSocks5Write(const std::shared_ptr<Preview::MemoryStream> &Peer)
        -> Net::awaitable<void>
    {
        const std::array<std::byte, 1> Version{std::byte{0x05}};
        EXPECT_FALSE((co_await Peer->WriteSome(Version)).Failure.Failed());
        co_await Net::post(Peer->Executor(), Net::use_awaitable);
        const std::array<std::byte, 1> MethodCount{std::byte{0x01}};
        EXPECT_FALSE((co_await Peer->WriteSome(MethodCount)).Failure.Failed());
    }

    /** @brief 分片写入 HTTP OPTIONS 方法前缀。 */
    auto RunFragmentedHttpWrite(const std::shared_ptr<Preview::MemoryStream> &Peer)
        -> Net::awaitable<void>
    {
        const std::array<std::byte, 3> Prefix{
            std::byte{'O'}, std::byte{'P'}, std::byte{'T'}};
        EXPECT_FALSE((co_await Peer->WriteSome(Prefix)).Failure.Failed());
        co_await Net::post(Peer->Executor(), Net::use_awaitable);
        const std::array<std::byte, 5> Suffix{
            std::byte{'I'}, std::byte{'O'}, std::byte{'N'}, std::byte{'S'}, std::byte{' '}};
        EXPECT_FALSE((co_await Peer->WriteSome(Suffix)).Failure.Failed());
    }

    struct RouteMutationRequest final
    {
        rec::Experiment::SniRouteTable &Routes;
        std::atomic<bool> &Failed;
    };

    struct WriterCompletion final
    {
        explicit WriterCompletion(Net::any_io_executor Executor) : Done(std::move(Executor), 1) {}

        Net::experimental::channel<void(boost::system::error_code)> Done;
        std::exception_ptr Failure;
    };

    auto RecordWriterCompletion(const std::shared_ptr<WriterCompletion> &State,
                                std::exception_ptr Failure) -> void
    {
        State->Failure = Failure;
        (void)State->Done.try_send(boost::system::error_code{});
    }

    auto AwaitWriterCompletion(const std::shared_ptr<WriterCompletion> &State) -> Net::awaitable<void>
    {
        co_await State->Done.async_receive(Net::use_awaitable);
        if (State->Failure)
        {
            std::rethrow_exception(State->Failure);
        }
    }

    struct FragmentedProbeRequest final
    {
        std::shared_ptr<Preview::MemoryStream> Source;
        std::shared_ptr<Preview::MemoryStream> Peer;
        Net::awaitable<void> Writer;
        rec::ProbeResult &Result;
    };

    auto RunFragmentedProbe(FragmentedProbeRequest Request) -> Net::awaitable<void>
    {
        const auto Completion = std::make_shared<WriterCompletion>(Request.Peer->Executor());
        Net::co_spawn(Request.Peer->Executor(), std::move(Request.Writer),
                      [Completion, Source = Request.Source, Peer = Request.Peer](std::exception_ptr Failure)
                      {
                          if (Failure)
                          {
                              Source->Close();
                              Peer->Close();
                          }
                          RecordWriterCompletion(Completion, Failure);
                      });
        std::exception_ptr Failure;
        try
        {
            Request.Result = co_await rec::Probe(*Request.Source);
        }
        catch (...)
        {
            Failure = std::current_exception();
            Request.Source->Close();
            Request.Peer->Close();
        }
        try
        {
            co_await AwaitWriterCompletion(Completion);
        }
        catch (...) { if (!Failure) Failure = std::current_exception(); }
        Request.Source->Close();
        Request.Peer->Close();
        if (Failure) std::rethrow_exception(Failure);
    }

    auto RunNaturalCoro(Net::io_context &Io, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(Io, std::move(Operation),
                      [&Failure](std::exception_ptr Error) { Failure = Error; });
        Io.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    /** @brief 并发修改 route snapshot。 */
    auto RunRouteWriter(RouteMutationRequest Request) -> void
    {
        for (int Index = 0; Index < 500; ++Index)
        {
            const char *CandidateName = Index % 2 == 0 ? "first" : "second";
            Request.Routes.Add("*.example.com", CandidateName);
            Request.Routes.SetDefault(CandidateName);
            if (Index % 3 == 0)
            {
                Request.Routes.ClearDefault();
            }
        }
    }

    /** @brief 并发读取 route snapshot 并报告不可接受的候选值。 */
    auto RunRouteReader(RouteMutationRequest Request) -> void
    {
        for (int Index = 0; Index < 1000; ++Index)
        {
            const auto Value = Request.Routes.LookupValue("node.example.com");
            if (Value && Value->Scheme != "initial" && Value->Scheme != "first" &&
                Value->Scheme != "second")
            {
                Request.Failed.store(true, std::memory_order_release);
            }
        }
    }
}

TEST(RecognitionProbe, ProbeAndRewind)
{
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));

    RunNaturalCoro(ioc, RunProbeAndRewindScenario(sa, sb));
}

TEST(RecognitionProbe, ReadsUntilProtocolCanBeClassified)
{
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));

    rec::ProbeResult result;
    RunNaturalCoro(ioc, RunFragmentedProbe(FragmentedProbeRequest{
        sa, sb, RunFragmentedTlsWrite(sb), result}));

    EXPECT_EQ(result.Type, Preview::Contract::ProtocolType::Tls);
    EXPECT_GE(result.PreReadSize, 2U);
}

TEST(RecognitionProbe, ReadsFragmentedSocks5GreetingBeforeClassification)
{
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));

    rec::ProbeResult result;
    RunNaturalCoro(ioc, RunFragmentedProbe(FragmentedProbeRequest{
        sa, sb, RunFragmentedSocks5Write(sb), result}));

    EXPECT_EQ(result.Type, Preview::Contract::ProtocolType::Socks5);
    EXPECT_EQ(result.PreReadSize, 2U);
}

TEST(RecognitionProbe, ReadsFragmentedOptionsBeforeHttpClassification)
{
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));

    rec::ProbeResult result;
    RunNaturalCoro(ioc, RunFragmentedProbe(FragmentedProbeRequest{
        sa, sb, RunFragmentedHttpWrite(sb), result}));

    EXPECT_EQ(result.Type, Preview::Contract::ProtocolType::Http);
    EXPECT_EQ(result.PreReadSize, 8U);
}

TEST(RecognitionRoute, ExactMatch)
{
    rec::Experiment::SniRouteTable routes;
    routes.Add("example.com", "reality");
    EXPECT_EQ(routes.Lookup("example.com"), "reality");
    EXPECT_EQ(routes.Lookup("other.com"), "");
}

TEST(RecognitionRoute, WildcardMatch)
{
    rec::Experiment::SniRouteTable routes;
    routes.Add("*.example.com", "shadowtls");
    EXPECT_EQ(routes.Lookup("sub.example.com"), "shadowtls");
    EXPECT_EQ(routes.Lookup("example.com"), ""); // 通配不含根域
    EXPECT_EQ(routes.Lookup("other.example.com"), "shadowtls");
}

TEST(RecognitionRoute, MultipleRoutes)
{
    rec::Experiment::SniRouteTable routes;
    routes.Add("a.com", "reality");
    routes.Add("b.com", "shadowtls");
    EXPECT_EQ(routes.Lookup("a.com"), "reality");
    EXPECT_EQ(routes.Lookup("b.com"), "shadowtls");
    EXPECT_EQ(routes.Size(), 2u);
    routes.Clear();
    EXPECT_EQ(routes.Size(), 0u);
}

TEST(RecognitionRoute, LookupNormalizesAsciiCase)
{
    rec::Experiment::SniRouteTable routes;
    routes.Add("Example.COM", "reality");
    EXPECT_EQ(routes.Lookup("example.com"), "reality");
}

TEST(RecognitionRoute, LongestWildcardWins)
{
    rec::Experiment::SniRouteTable routes;
    routes.Add("*.example.com", "shadowtls");
    routes.Add("*.deep.example.com", "reality");
    EXPECT_EQ(routes.Lookup("node.deep.example.com"), "reality");
}

TEST(RecognitionRoute, WildcardMatchesSingleLabelOnly)
{
    rec::Experiment::SniRouteTable routes;
    routes.Add("*.example.com", "shadowtls");
    EXPECT_EQ(routes.Lookup("a.b.example.com"), "");
}

TEST(RecognitionRoute, LookupEntryCarriesProtocolAndFallback)
{
    rec::Experiment::SniRouteTable routes;
    routes.Add("api.example.com", "native", rec::Experiment::RouteOptions{Preview::Contract::ProtocolType::Vless, true});
    const auto entry = routes.LookupEntry("API.EXAMPLE.COM.");
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->Scheme, "native");
    EXPECT_EQ(entry->Protocol, Preview::Contract::ProtocolType::Vless);
    EXPECT_TRUE(entry->AllowFallback);
}

TEST(RecognitionRoute, LookupEntryReturnsOwnedValue)
{
    rec::Experiment::SniRouteTable routes;
    routes.Add("example.com", "native");

    const auto entry = routes.LookupEntry("example.com");
    ASSERT_TRUE(entry.has_value());
    routes.Clear();

    EXPECT_EQ(entry->Scheme, "native");
}

TEST(RecognitionRoute, ConcurrentLookupAndMutationUsesStableSnapshots)
{
    rec::Experiment::SniRouteTable routes;
    routes.Add("*.example.com", "initial");
    std::atomic<bool> failed{false};

    std::thread Writer(RunRouteWriter, RouteMutationRequest{routes, failed});
    std::array<std::thread, 4> readers;
    for (auto &reader : readers)
    {
        reader = std::thread(RunRouteReader, RouteMutationRequest{routes, failed});
    }
    Writer.join();
    for (auto &reader : readers)
    {
        reader.join();
    }

    EXPECT_FALSE(failed.load());
    EXPECT_EQ(routes.Size(), 1u);
}
