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
        const std::shared_ptr<Prism::MemoryStream> &Source,
        const std::shared_ptr<Prism::MemoryStream> &Peer) -> Net::awaitable<void>
    {
        std::array<std::byte, 4> Tls{
            std::byte{0x16}, std::byte{0x03}, std::byte{0x01}, std::byte{0x00}};
        EXPECT_FALSE((co_await Peer->WriteSome(Tls)).Failure.Failed());
        auto ProbeResult = co_await rec::Probe(*Source);
        EXPECT_EQ(ProbeResult.Type, Prism::Contract::ProtocolType::Tls);
        EXPECT_EQ(ProbeResult.PreReadSize, 4U);
        auto Rewound = rec::WrapPreread(
            Source, std::span<const std::byte>(ProbeResult.PreRead.data(), ProbeResult.PreReadSize),
            std::make_shared<Prism::Memory::BytePool>(
                Prism::Memory::BytePoolOptions{.BlockCount = 1}));
        std::array<std::byte, 22> Buffer{};
        const auto Part = co_await Rewound->ReadSome(Buffer);
        EXPECT_EQ(Part.Bytes, 4U);
        EXPECT_EQ(Buffer[0], std::byte{0x16});
    }

    /** @brief 按字节分片写入 TLS prefix。 */
    auto RunFragmentedTlsWrite(const std::shared_ptr<Prism::MemoryStream> &Peer)
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
    auto RunFragmentedSocks5Write(const std::shared_ptr<Prism::MemoryStream> &Peer)
        -> Net::awaitable<void>
    {
        const std::array<std::byte, 1> Version{std::byte{0x05}};
        EXPECT_FALSE((co_await Peer->WriteSome(Version)).Failure.Failed());
        co_await Net::post(Peer->Executor(), Net::use_awaitable);
        const std::array<std::byte, 1> MethodCount{std::byte{0x01}};
        EXPECT_FALSE((co_await Peer->WriteSome(MethodCount)).Failure.Failed());
    }

    /** @brief 分片写入 HTTP OPTIONS 方法前缀。 */
    auto RunFragmentedHttpWrite(const std::shared_ptr<Prism::MemoryStream> &Peer)
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
        std::shared_ptr<Prism::MemoryStream> Source;
        std::shared_ptr<Prism::MemoryStream> Peer;
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

}

TEST(RecognitionProbe, ProbeAndRewind)
{
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Prism::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Prism::MemoryStream>(std::move(b));

    RunNaturalCoro(ioc, RunProbeAndRewindScenario(sa, sb));
}

TEST(RecognitionProbe, ReadsUntilProtocolCanBeClassified)
{
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Prism::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Prism::MemoryStream>(std::move(b));

    rec::ProbeResult result;
    RunNaturalCoro(ioc, RunFragmentedProbe(FragmentedProbeRequest{
        sa, sb, RunFragmentedTlsWrite(sb), result}));

    EXPECT_EQ(result.Type, Prism::Contract::ProtocolType::Tls);
    EXPECT_GE(result.PreReadSize, 2U);
}

TEST(RecognitionProbe, ReadsFragmentedSocks5GreetingBeforeClassification)
{
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Prism::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Prism::MemoryStream>(std::move(b));

    rec::ProbeResult result;
    RunNaturalCoro(ioc, RunFragmentedProbe(FragmentedProbeRequest{
        sa, sb, RunFragmentedSocks5Write(sb), result}));

    EXPECT_EQ(result.Type, Prism::Contract::ProtocolType::Socks5);
    EXPECT_EQ(result.PreReadSize, 2U);
}

TEST(RecognitionProbe, ReadsFragmentedOptionsBeforeHttpClassification)
{
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Prism::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Prism::MemoryStream>(std::move(b));

    rec::ProbeResult result;
    RunNaturalCoro(ioc, RunFragmentedProbe(FragmentedProbeRequest{
        sa, sb, RunFragmentedHttpWrite(sb), result}));

    EXPECT_EQ(result.Type, Prism::Contract::ProtocolType::Http);
    EXPECT_EQ(result.PreReadSize, 8U);
}
