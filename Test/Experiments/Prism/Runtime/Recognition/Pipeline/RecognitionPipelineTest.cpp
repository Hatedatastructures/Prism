/**
 * @file RecognitionPipelineTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include <Test/Experiments/Prism/Runtime/Recognition/Pipeline/RecognitionSupport.hpp>

#include <boost/asio/co_spawn.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

#include <Prism/Foundation/Memory/BytePool.hpp>

namespace
{
    /** @brief 创建实验识别流水线所需的有界预读池。 */
    auto MakeExperimentProbeBytePool() -> std::shared_ptr<Prism::Memory::BytePool>
    {
        return std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{64U * 1024U, 64U});
    }

    struct AcceptedSchemeRequest final
    {
        std::shared_ptr<Prism::MemoryStream> Client;
        std::shared_ptr<Prism::MemoryStream> Peer;
        std::vector<std::uint8_t> Record;
        rec::Experiment::ProbeRecognition *Pipeline;
        std::shared_ptr<bool> Called;
    };

    /** @brief 写入 TLS record，运行 scheme 并核对 accepted replay。 */
    auto RunAcceptedScheme(AcceptedSchemeRequest Request) -> Net::awaitable<void>
    {
        const auto WriteResult = co_await Request.Peer->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.Record.data()), Request.Record.size()));
        EXPECT_FALSE(WriteResult.Failure.Failed());
        auto Result = co_await Request.Pipeline->Recognize(Request.Client);
        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.preread.size(), Request.Record.size());
        EXPECT_EQ(Result.detected, Prism::Contract::ProtocolType::Trojan);
        EXPECT_EQ(Result.scheme, "reality");
        EXPECT_TRUE(*Request.Called);
        std::array<std::byte, 5> Replay{};
        const auto ReadResult = co_await Result.transport->ReadSome(Replay);
        EXPECT_FALSE(ReadResult.Failure.Failed());
        EXPECT_EQ(ReadResult.Bytes, Replay.size());
        EXPECT_EQ(Replay[0], std::byte{0x16});
    }

    /** @brief 写入未知 SNI record 并确认没有 scheme 结果。 */
    auto RunUnknownScheme(AcceptedSchemeRequest Request) -> Net::awaitable<void>
    {
        const auto WriteResult = co_await Request.Peer->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.Record.data()), Request.Record.size()));
        EXPECT_FALSE(WriteResult.Failure.Failed());
        const auto Result = co_await Request.Pipeline->Recognize(Request.Client);
        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.detected, Prism::Contract::ProtocolType::Tls);
        EXPECT_TRUE(Result.scheme.empty());
    }

    /** @brief scheme 失败后保留并回放 TLS transport。 */
    auto RunSchemeRewind(AcceptedSchemeRequest Request) -> Net::awaitable<void>
    {
        const auto WriteResult = co_await Request.Peer->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.Record.data()), Request.Record.size()));
        EXPECT_FALSE(WriteResult.Failure.Failed());
        auto Result = co_await Request.Pipeline->Recognize(Request.Client);
        EXPECT_FALSE(Result.success);
        EXPECT_NE(Result.transport, nullptr);
        if (!Result.transport)
        {
            co_return;
        }
        std::array<std::byte, 5> Replayed{};
        const auto ReadResult = co_await Result.transport->ReadSome(Replayed);
        EXPECT_FALSE(ReadResult.Failure.Failed());
        EXPECT_EQ(ReadResult.Bytes, Replayed.size());
        EXPECT_EQ(Replayed[0], std::byte{0x16});
    }

    struct SchemeExceptionRequest final
    {
        std::shared_ptr<Prism::MemoryStream> Client;
        std::shared_ptr<Prism::MemoryStream> Peer;
        rec::Experiment::ProbeRecognition &Pipeline;
        rec::RecognizeResult &Result;
        std::vector<std::byte> Record;
        std::array<std::byte, 5> &ReplayedPrefix;
        std::size_t &Replayed;
    };

    /** @brief 运行 throwing scheme，保留失败后的可回放传输。 */
    auto RunSchemeException(SchemeExceptionRequest Request) -> Net::awaitable<void>
    {
        const auto WriteResult = co_await Request.Peer->WriteSome(Request.Record);
        EXPECT_FALSE(WriteResult.Failure.Failed());
        Request.Result = co_await Request.Pipeline.Recognize(Request.Client);
        if (Request.Result.transport)
        {
            const auto ReadResult = co_await Request.Result.transport->ReadSome(Request.ReplayedPrefix);
            EXPECT_FALSE(ReadResult.Failure.Failed());
            Request.Replayed = ReadResult.Bytes;
        }
    }

    /** @brief 运行 VLESS 结构探测并核对回放完整性。 */
    auto RunVlessRewind(
        const std::shared_ptr<Prism::MemoryStream> &Source,
        const std::shared_ptr<Prism::MemoryStream> &Peer,
        experiment::ProbeRecognition &Pipeline) -> Net::awaitable<void>
    {
        std::array<std::byte, 22> Vless{};
        Vless[0] = std::byte{0x00};
        Vless[17] = std::byte{0x00};
        Vless[18] = std::byte{0x01};
        Vless[19] = std::byte{0x01};
        Vless[20] = std::byte{0xBB};
        Vless[21] = std::byte{0x02};
        const auto WriteResult = co_await Peer->WriteSome(Vless);
        EXPECT_FALSE(WriteResult.Failure.Failed());
        auto Result = co_await Pipeline.Recognize(Source);
        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.detected, Prism::Contract::ProtocolType::Vless);
        EXPECT_EQ(Result.preread.size(), Vless.size());
        std::array<std::byte, 22> Buffer{};
        const auto ReadResult = co_await Result.transport->ReadSome(Buffer);
        EXPECT_FALSE(ReadResult.Failure.Failed());
        EXPECT_EQ(ReadResult.Bytes, Vless.size());
    }

    /** @brief 运行未知首包并确认数据仍被回注。 */
    auto RunUnknownPassthrough(
        const std::shared_ptr<Prism::MemoryStream> &Source,
        const std::shared_ptr<Prism::MemoryStream> &Peer,
        experiment::ProbeRecognition &Pipeline) -> Net::awaitable<void>
    {
        const std::array<std::byte, 3> Unknown{
            std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}};
        const auto WriteResult = co_await Peer->WriteSome(Unknown);
        EXPECT_FALSE(WriteResult.Failure.Failed());
        Peer->Close();
        const auto Result = co_await Pipeline.Recognize(Source);
        EXPECT_FALSE(Result.success);
        EXPECT_GE(Result.preread.size(), 1U);
    }

    struct HttpProbeRequest final
    {
        std::shared_ptr<Prism::MemoryStream> Client;
        std::shared_ptr<Prism::MemoryStream> Peer;
        experiment::ProbeRecognition *Pipeline;
        rec::RecognizeResult &Result;
    };

    /** @brief 写入 HTTP wire 并核对 Probe recognition accepted 状态。 */
    auto RunHttpProbe(HttpProbeRequest Request) -> Net::awaitable<void>
    {
        const auto Wire = Prism::Testing::RecognitionWire::MakeHttp();
        const auto WriteResult = co_await Request.Peer->WriteSome(Wire);
        EXPECT_FALSE(WriteResult.Failure.Failed());
        Request.Result = co_await Request.Pipeline->Recognize(Request.Client);
    }

    struct PartialCancellationRequest final
    {
        std::shared_ptr<Prism::MemoryStream> Client;
        std::shared_ptr<Prism::MemoryStream> Peer;
        experiment::ProbeRecognition &Pipeline;
        rec::ProbeBuffer &Buffer;
        rec::RecognitionControl &Control;
        rec::RecognizeResult &Result;
        std::array<std::byte, 1> &Replayed;
        std::size_t &ReplayedCount;
    };

    /** @brief 运行 pre-cancel recognition 并核对 partial prefix replay。 */
    auto RunPartialCancellation(PartialCancellationRequest Request) -> Net::awaitable<void>
    {
        const std::array<std::byte, 1> Prefix{std::byte{0x05}};
        const auto WriteResult = co_await Request.Peer->WriteSome(Prefix);
        EXPECT_FALSE(WriteResult.Failure.Failed());
        Request.Result = co_await Request.Pipeline.Recognize(
            Request.Client, Request.Buffer, std::move(Request.Control));
        if (Request.Result.transport)
        {
            const auto ReadResult = co_await Request.Result.transport->ReadSome(Request.Replayed);
            EXPECT_FALSE(ReadResult.Failure.Failed());
            Request.ReplayedCount = ReadResult.Bytes;
        }
    }

    struct WriteFailureRequest final
    {
        std::shared_ptr<Prism::MemoryStream> Client;
        std::shared_ptr<Prism::MemoryStream> Peer;
        experiment::ProbeRecognition &Pipeline;
        rec::RecognizeResult &Result;
        std::vector<std::byte> Record;
    };

    auto RunWriteFailureScenario(WriteFailureRequest Request) -> Net::awaitable<void>
    {
        const auto WriteResult = co_await Request.Peer->WriteSome(Request.Record);
        EXPECT_FALSE(WriteResult.Failure.Failed());
        Request.Result = co_await Request.Pipeline.Recognize(Request.Client);
        Request.Peer->Close();
        Request.Client->Close();
    }

    struct PreCancelledRequest final
    {
        std::shared_ptr<Prism::MemoryStream> Client;
        std::shared_ptr<Prism::MemoryStream> Peer;
        experiment::ProbeRecognition &Pipeline;
        rec::ProbeBuffer &Buffer;
        rec::RecognitionControl &Control;
    };

    auto RunPreCancelledScenario(PreCancelledRequest Request) -> Net::awaitable<void>
    {
        const std::array<std::byte, 2> Greeting{std::byte{0x05}, std::byte{0x01}};
        const auto WriteResult = co_await Request.Peer->WriteSome(Greeting);
        EXPECT_FALSE(WriteResult.Failure.Failed());
        auto Result = co_await Request.Pipeline.Recognize(
            Request.Client, Request.Buffer, std::move(Request.Control));
        EXPECT_FALSE(Result.success);
        EXPECT_TRUE(Result.Cancelled);
        EXPECT_EQ(Result.Status, rec::RecognitionStatus::IoError);
        Request.Client->Close();
        Request.Peer->Close();
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

TEST(RecognitionPipeline, RoutesTlsClientHelloToScheme)
{
    const auto PushU16 = [](std::vector<std::uint8_t> &out, const std::size_t value)
    {
        out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(value & 0xFF));
    };
    const auto PushU24 = [](std::vector<std::uint8_t> &out, const std::size_t value)
    {
        out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(value & 0xFF));
    };
    const std::string Host = "example.com";
    std::vector<std::uint8_t> Sni;
    PushU16(Sni, Host.size() + 3);
    Sni.push_back(0x00);
    PushU16(Sni, Host.size());
    Sni.insert(Sni.end(), Host.begin(), Host.end());
    std::vector<std::uint8_t> Extensions;
    PushU16(Extensions, 0x0000);
    PushU16(Extensions, Sni.size());
    Extensions.insert(Extensions.end(), Sni.begin(), Sni.end());
    std::vector<std::uint8_t> Body{0x03, 0x03};
    Body.insert(Body.end(), 32, 0x42);
    Body.push_back(0x00);
    Body.push_back(0x00);
    Body.push_back(0x02);
    Body.push_back(0x13);
    Body.push_back(0x01);
    Body.push_back(0x01);
    Body.push_back(0x00);
    PushU16(Body, Extensions.size());
    Body.insert(Body.end(), Extensions.begin(), Extensions.end());
    std::vector<std::uint8_t> Record{0x16, 0x03, 0x01, 0x00, 0x00, 0x01};
    Record[3] = static_cast<std::uint8_t>(((Body.size() + 4) >> 8) & 0xFF);
    Record[4] = static_cast<std::uint8_t>((Body.size() + 4) & 0xFF);
    PushU24(Record, Body.size());
    Record.insert(Record.end(), Body.begin(), Body.end());

    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Prism::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Prism::MemoryStream>(std::move(b));
    rec::Experiment::SniRouteTable routes;
    routes.Add("example.com", "reality", rec::Experiment::RouteOptions{Prism::Contract::ProtocolType::Trojan, false});
    rec::Experiment::SchemeExecutor executor;
    auto called = std::make_shared<bool>(false);
    executor.RegisterScheme("reality", [called](SharedTransmission Inbound)
                            -> Net::awaitable<SharedTransmission>
    {
        *called = true;
        co_return Inbound;
    });
    experiment::ProbeRecognition pipe(&routes, &executor);

    RunNaturalCoro(ioc, RunAcceptedScheme(AcceptedSchemeRequest{
        sa, sb, Record, &pipe, called}));
}

TEST(RecognitionPipeline, NormalizesSchemeCaseAcrossRouteAndExecutor)
{
    Net::io_context Io;
    auto [a, b] = MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(a));
    auto Peer = std::make_shared<Prism::MemoryStream>(std::move(b));
    const auto Wire = Prism::Testing::RecognitionWire::MakeTlsClientHello("case.example");

    rec::Experiment::SniRouteTable Routes;
    Routes.Add("case.example", "NATIVE", rec::Experiment::RouteOptions{Prism::Contract::ProtocolType::Tls, false});
    rec::Experiment::SchemeExecutor Executor;
    Executor.RegisterScheme("native", [](SharedTransmission Inbound) -> Net::awaitable<SharedTransmission>
                            { co_return Inbound; });
    experiment::ProbeRecognition Pipeline(&Routes, &Executor);
    rec::RecognizeResult Result;

    RunNaturalCoro(Io, [Client, Peer, Wire, &Pipeline, &Result]() -> Net::awaitable<void>
              {
                  const auto WriteResult = co_await Peer->WriteSome(Wire);
                  EXPECT_FALSE(WriteResult.Failure.Failed());
                  Result = co_await Pipeline.Recognize(Client);
                  Client->Close();
                  Peer->Close();
              }());

    EXPECT_TRUE(Result.success);
    EXPECT_EQ(Result.preread.size(), Wire.size());
    EXPECT_EQ(Result.scheme, "native");
}

TEST(RecognitionPipeline, RejectsUnknownTlsSni)
{
    const std::vector<std::uint8_t> Record{
        0x16, 0x03, 0x01, 0x00, 0x28, 0x01, 0x00, 0x00, 0x24,
        0x03, 0x03, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x00, 0x00, 0x02, 0x13, 0x01,
        0x01, 0x00};
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Prism::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Prism::MemoryStream>(std::move(b));
    rec::Experiment::SniRouteTable routes;
    routes.Add("known.example", "reality", rec::Experiment::RouteOptions{Prism::Contract::ProtocolType::Trojan, false});
    rec::Experiment::SchemeExecutor executor;
    experiment::ProbeRecognition pipe(&routes, &executor);

    RunNaturalCoro(ioc, RunSchemeRewind(AcceptedSchemeRequest{
        sa, sb, Record, &pipe, {}}));
}

TEST(RecognitionPipeline, RewindsTransportWhenSchemeFails)
{
    const std::vector<std::uint8_t> Sni{
        0x00, 0x0E, 0x00, 0x00, 0x00, 0x0B, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
    std::vector<std::uint8_t> Extensions{0x00, 0x00, 0x00, 0x10};
    Extensions.insert(Extensions.end(), Sni.begin(), Sni.end());
    std::vector<std::uint8_t> Body{0x03, 0x03};
    Body.insert(Body.end(), 32, 0x42);
    Body.insert(Body.end(), {0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00,
                             0x00, 0x14});
    Body.insert(Body.end(), Extensions.begin(), Extensions.end());
    std::vector<std::uint8_t> Record{
        0x16, 0x03, 0x01, 0x00, static_cast<std::uint8_t>(Body.size() + 4),
        0x01, 0x00, static_cast<std::uint8_t>((Body.size() >> 16) & 0xFF),
        static_cast<std::uint8_t>((Body.size() >> 8) & 0xFF),
        static_cast<std::uint8_t>(Body.size() & 0xFF)};
    Record.insert(Record.end(), Body.begin(), Body.end());
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Prism::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Prism::MemoryStream>(std::move(b));
    rec::Experiment::SniRouteTable routes;
    routes.Add("example.com", "reject", rec::Experiment::RouteOptions{Prism::Contract::ProtocolType::Trojan, false});
    rec::Experiment::SchemeExecutor executor;
    executor.RegisterScheme("reject", [](SharedTransmission) -> Net::awaitable<SharedTransmission>
                            { co_return nullptr; });
    experiment::ProbeRecognition pipe(&routes, &executor);

    RunNaturalCoro(ioc, RunUnknownScheme(AcceptedSchemeRequest{
        sa, sb, Record, &pipe, {}}));
}

TEST(RecognitionPipeline, ConvertsSchemeExceptionToReplayableFailure)
{
    const auto Record = Prism::Testing::RecognitionWire::MakeTlsClientHello("example.com");
    Net::io_context Ioc;
    auto [a, b] = MakeMemoryPair(Ioc.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(a));
    auto Peer = std::make_shared<Prism::MemoryStream>(std::move(b));
    rec::Experiment::SniRouteTable Routes;
    Routes.Add("example.com", "throwing", rec::Experiment::RouteOptions{Prism::Contract::ProtocolType::Tls, false});
    rec::Experiment::SchemeExecutor Executor;
    ASSERT_TRUE(Executor.RegisterScheme(
        "throwing", [](SharedTransmission) -> Net::awaitable<SharedTransmission>
        {
            throw std::runtime_error("scheme failure");
            co_return nullptr;
        }));
    experiment::ProbeRecognition Pipeline(&Routes, &Executor);
    rec::RecognizeResult Result;
    std::exception_ptr Failure;
    std::array<std::byte, 5> ReplayedPrefix{};
    std::size_t Replayed = 0;

    RunNaturalCoro(Ioc, RunSchemeException(SchemeExceptionRequest{
        Client, Peer, Pipeline, Result, Record, ReplayedPrefix, Replayed}));

    EXPECT_EQ(Failure, nullptr);
    EXPECT_FALSE(Result.success);
    ASSERT_NE(Result.transport, nullptr);
    EXPECT_EQ(Replayed, ReplayedPrefix.size());
    EXPECT_EQ(ReplayedPrefix.front(), std::byte{0x16});
}

TEST(RecognitionPipeline, ClosesTransportWhenSchemeExceptionFollowsWrite)
{
    const auto Record = Prism::Testing::RecognitionWire::MakeTlsClientHello("example.com");
    Net::io_context Ioc;
    auto [a, b] = MakeMemoryPair(Ioc.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(a));
    auto Peer = std::make_shared<Prism::MemoryStream>(std::move(b));
    rec::Experiment::SniRouteTable Routes;
    Routes.Add("example.com", "write-throw", rec::Experiment::RouteOptions{Prism::Contract::ProtocolType::Tls, false});
    rec::Experiment::SchemeExecutor Executor;
    ASSERT_TRUE(Executor.RegisterScheme(
        "write-throw", [](SharedTransmission Inbound) -> Net::awaitable<SharedTransmission>
        {
            std::array<std::byte, 1> Byte{std::byte{0xA5}};
            const auto WriteResult = co_await Inbound->WriteSome(Byte);
            EXPECT_FALSE(WriteResult.Failure.Failed());
            throw std::runtime_error("scheme write failure");
            co_return nullptr;
        }));
    experiment::ProbeRecognition Pipeline(&Routes, &Executor);
    rec::RecognizeResult Result;
    std::exception_ptr Failure;
    Net::co_spawn(Ioc, RunWriteFailureScenario(WriteFailureRequest{
                      Client, Peer, Pipeline, Result, Record}),
                  [&Failure](std::exception_ptr Error)
                  { Failure = std::move(Error); });
    Ioc.run();

    EXPECT_EQ(Failure, nullptr);
    EXPECT_FALSE(Result.success);
    EXPECT_EQ(Result.transport, nullptr);
    EXPECT_FALSE(Client->IsOpen());
}

TEST(RecognitionPipeline, DetectAndRewind)
{
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Prism::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Prism::MemoryStream>(std::move(b));

    experiment::ProbeRecognition pipe;
    RunNaturalCoro(ioc, RunVlessRewind(sa, sb, pipe));
}

TEST(RecognitionPipeline, UnknownPassthrough)
{
    Net::io_context ioc;
    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Prism::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Prism::MemoryStream>(std::move(b));

    experiment::ProbeRecognition pipe;
    RunNaturalCoro(ioc, RunUnknownPassthrough(sa, sb, pipe));
}

TEST(RecognitionPipeline, ProbeSuccessReportsAcceptedStatus)
{
    Net::io_context Io;
    auto [A, B] = MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(A));
    auto Peer = std::make_shared<Prism::MemoryStream>(std::move(B));
    experiment::ProbeRecognition Pipeline;
    rec::RecognizeResult Result;

    RunNaturalCoro(Io, RunHttpProbe(HttpProbeRequest{Client, Peer, &Pipeline, Result}));

    EXPECT_TRUE(Result.success);
    EXPECT_EQ(Result.Status, rec::RecognitionStatus::Accepted);
}

TEST(RecognitionPipeline, ProbePathHonorsPreCancelledControl)
{
    Net::io_context Io;
    auto [A, B] = MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(A));
    auto Peer = std::make_shared<Prism::MemoryStream>(std::move(B));

    experiment::ProbeRecognition Pipeline;
    rec::ProbeBuffer Buffer(rec::MaxTlsClientHelloBytes, MakeExperimentProbeBytePool());
    rec::RecognitionControl Control;
    bool CancelCalled = false;
    Control.Cancelled = [] { return true; };
    Control.CancelTransport = [&CancelCalled] { CancelCalled = true; };

    RunNaturalCoro(Io, RunPreCancelledScenario(PreCancelledRequest{
        Client, Peer, Pipeline, Buffer, Control}));

    EXPECT_TRUE(CancelCalled);
}

TEST(RecognitionPipeline, ProbePathPreservesPartialPrefixOnCancellation)
{
    Net::io_context Io;
    auto [A, B] = MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(A));
    auto Peer = std::make_shared<Prism::MemoryStream>(std::move(B));

    experiment::ProbeRecognition Pipeline;
    rec::ProbeBuffer Buffer(rec::MaxTlsClientHelloBytes, MakeExperimentProbeBytePool());
    rec::RecognitionControl Control;
    Control.Wait = [Executor = Io.get_executor()]
    {
        return WaitForRecognitionEvent(Executor, std::chrono::milliseconds(1),
                                       rec::RecognitionControlEvent::Cancelled);
    };
    Control.WaitCancellationSafe = true;
    Control.CancelTransport = [Client] { Client->Cancel(); };

    rec::RecognizeResult Result;
    std::array<std::byte, 1> Replayed{};
    std::size_t ReplayedCount = 0;
    RunNaturalCoro(Io, RunPartialCancellation(PartialCancellationRequest{
        Client, Peer, Pipeline, Buffer, Control, Result, Replayed, ReplayedCount}));

    EXPECT_FALSE(Result.success);
    EXPECT_TRUE(Result.Cancelled);
    ASSERT_EQ(Result.preread.size(), 1U);
    EXPECT_EQ(Result.preread.front(), std::byte{0x05});
    ASSERT_NE(Result.transport, nullptr);
    EXPECT_EQ(ReplayedCount, 1U);
    EXPECT_EQ(Replayed.front(), std::byte{0x05});
}
