/**
 * @file H2MuxRequestAdmissionTest.cpp
 * @brief HTTP/2 请求伪头校验与 H2Mux CONNECT 准入契约。
 */

#include "H2MuxLifetimeSupport.hpp"

namespace
{

    struct RequestAdmissionResponse final
    {
        std::int32_t StreamId{0};
        std::uint16_t StatusCode{0};
        std::size_t StatusCount{0};
        bool AllowsConnect{false};
        bool EndStream{false};
    };

    struct RequestAdmissionObservation final
    {
        std::array<std::int32_t, 8> StreamIds{};
        std::array<std::uint32_t, 6> MalformedResetErrors{};
        std::vector<RequestAdmissionResponse> Responses;
        std::size_t DataBytes{0};
        std::vector<std::byte> DataPayload;
        std::int32_t DataStreamId{0};
        bool MixedDataStreams{false};
    };

    inline constexpr std::array<std::byte, 4> RequestAdmissionPayload{
        std::byte{0x31}, std::byte{0x32}, std::byte{0x33}, std::byte{0x34}};

    struct ResponseHeadersEvent final
    {
        std::int32_t StreamId;
        const Prism::Http2::HeaderList &Headers;
        bool EndStream;
    };

    struct ResponseDataEvent final
    {
        std::int32_t StreamId;
        std::span<const std::byte> Data;
    };

    auto ObserveResponseHeaders(
        RequestAdmissionObservation &Observation,
        const ResponseHeadersEvent &Event) -> void
    {
        RequestAdmissionResponse Response;
        Response.StreamId = Event.StreamId;
        Response.EndStream = Event.EndStream;
        for (const auto &[Name, Value] : Event.Headers)
        {
            if (Name == ":status")
            {
                ++Response.StatusCount;
                if (Value == "400") Response.StatusCode = 400;
                if (Value == "405") Response.StatusCode = 405;
                if (Value == "200") Response.StatusCode = 200;
            }
            if (Name == "allow" && Value == "CONNECT") Response.AllowsConnect = true;
        }
        Observation.Responses.push_back(Response);
    }

    auto ObserveResponseData(
        RequestAdmissionObservation &Observation,
        const ResponseDataEvent &Event) -> void
    {
        if (Event.Data.empty()) return;
        if (Observation.DataBytes == 0) Observation.DataStreamId = Event.StreamId;
        else if (Observation.DataStreamId != Event.StreamId) Observation.MixedDataStreams = true;
        Observation.DataBytes += Event.Data.size();
        Observation.DataPayload.insert(
            Observation.DataPayload.end(), Event.Data.begin(), Event.Data.end());
    }

    auto ObserveStreamClosure(
        RequestAdmissionObservation &Observation,
        const Prism::Http2::StreamReceiveClosure &Closure) -> void
    {
        if (Closure.Kind != Prism::Http2::StreamReceiveClosureKind::Reset) return;
        const auto End = Observation.StreamIds.begin() + Observation.MalformedResetErrors.size();
        const auto Iterator = std::find(Observation.StreamIds.begin(), End, Closure.StreamId);
        if (Iterator != End)
            Observation.MalformedResetErrors[static_cast<std::size_t>(Iterator - Observation.StreamIds.begin())] =
                Closure.ErrorCode;
    }

    [[nodiscard]] auto OpenAdmissionRequests(
        Prism::Http2::Session &Client,
        RequestAdmissionObservation &Observation) -> bool
    {
        using Prism::Http2::HeaderList;
        Client.SendSettings();
        const std::array<HeaderList, 8> Requests{
            HeaderList{{":scheme", "https"}, {":path", "/"}, {":authority", "example.test"}},
            HeaderList{{":method", "GET"}, {":method", "GET"}, {":scheme", "https"}, {":path", "/"},
                       {":authority", "example.test"}},
            HeaderList{{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}},
            HeaderList{{":method", "CONNECT"}},
            HeaderList{{":method", "CONNECT"}, {":authority", ""}},
            HeaderList{{":method", "GET"}, {":scheme", "https"}, {":path", "/"},
                       {"x-test", "value"}, {":authority", "example.test"}},
            HeaderList{{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {":authority", "example.test"}},
            HeaderList{{":method", "CONNECT"}, {":authority", "example.test:443"}}};
        for (std::size_t Index = 0; Index < Requests.size(); ++Index)
        {
            const auto Opened = Client.OpenStream(Requests[Index], Index != 7U);
            if (!Opened) return false;
            Observation.StreamIds[Index] = *Opened;
        }
        return true;
    }

    struct RequestAdmissionScenario final
    {
        std::shared_ptr<Prism::Mux::H2Mux::Http2Server> Server;
        Prism::SharedTransmission ClientTransport;
        RequestAdmissionObservation &Observation;
        Watchdog Guard;
    };

    /// 真实 HTTP/2 帧验证 malformed 复位、GET 拒绝及 CONNECT 隧道准入。
    auto RunRequestAdmission(RequestAdmissionScenario Scenario) -> Net::awaitable<void>
    {
        auto Client = std::make_shared<Prism::Http2::Session>(
            Scenario.ClientTransport->Executor(), false);
        auto &Observation = Scenario.Observation;
        Client->OnHeaders = [&Observation](
            const std::int32_t StreamId,
            const Prism::Http2::HeaderList &Headers,
            const bool EndStream)
        {
            ObserveResponseHeaders(Observation, ResponseHeadersEvent{StreamId, Headers, EndStream});
        };
        Client->OnData = [&Observation](
            const std::int32_t StreamId, const std::span<const std::byte> Data)
        {
            ObserveResponseData(Observation, ResponseDataEvent{StreamId, Data});
        };
        Client->OnStreamClose = [&Observation](const Prism::Http2::StreamReceiveClosure &Closure)
        {
            ObserveStreamClosure(Observation, Closure);
        };
        if (!OpenAdmissionRequests(*Client, Observation))
        {
            ADD_FAILURE() << "failed to open malformed, GET, and CONNECT requests";
            co_await DrainHttp2Server(Scenario.Server);
            Scenario.Guard.Cancel();
            co_return;
        }

        std::vector<std::byte> Wire;
        if (!Client->Collect(Wire))
        {
            ADD_FAILURE() << "failed to collect request frames";
            co_await DrainHttp2Server(Scenario.Server);
            Scenario.Guard.Cancel();
            co_return;
        }
        const auto WriteResult = co_await Scenario.ClientTransport->WriteSome(
            std::span<const std::byte>(Wire));
        EXPECT_FALSE(WriteResult.Failure.Failed());
        if (WriteResult.Failure.Failed())
        {
            co_await DrainHttp2Server(Scenario.Server);
            Scenario.Guard.Cancel();
            co_return;
        }

        auto AcceptedStream = co_await Scenario.Server->AcceptStream();
        if (!AcceptedStream)
        {
            ADD_FAILURE() << "CONNECT stream was not accepted";
            co_await DrainHttp2Server(Scenario.Server);
            Scenario.Guard.Cancel();
            co_return;
        }
        const auto TunnelWrite = co_await AcceptedStream->WriteSome(RequestAdmissionPayload);
        EXPECT_FALSE(TunnelWrite.Failure.Failed());
        if (TunnelWrite.Failure.Failed())
        {
            co_await DrainHttp2Server(Scenario.Server);
            Scenario.Guard.Cancel();
            co_return;
        }

        std::array<std::byte, 4096> Buffer{};
        while (Observation.DataBytes == 0)
        {
            const auto ReadResult = co_await Scenario.ClientTransport->ReadSome(Buffer);
            if (ReadResult.Failure.Failed() || ReadResult.Bytes == 0)
            {
                ADD_FAILURE() << "failed to receive CONNECT response frames";
                break;
            }
            std::error_code ErrorCode;
            const auto Fed = Client->Feed(
                std::span<const std::byte>(Buffer.data(), ReadResult.Bytes), ErrorCode);
            if (!Fed || ErrorCode)
            {
                ADD_FAILURE() << "failed to parse CONNECT response frames";
                break;
            }
        }
        co_await DrainHttp2Server(Scenario.Server);
        Scenario.Guard.Cancel();
    }

    [[nodiscard]] auto FindResponse(
        const RequestAdmissionObservation &Observation,
        const std::int32_t StreamId) -> const RequestAdmissionResponse *
    {
        const auto Iterator = std::find_if(
            Observation.Responses.begin(), Observation.Responses.end(), [StreamId](const auto &Response)
            {
                return Response.StreamId == StreamId;
            });
        return Iterator == Observation.Responses.end() ? nullptr : &*Iterator;
    }
}

TEST(H2MuxRequestAdmission, MalformedAndNonConnectRequestsAreRejectedBeforeConnect)
    {
        Net::io_context Io;
        auto [ServerRaw, ClientRaw] = Prism::MakeMemoryPair(Io.get_executor());
        auto Server = std::make_shared<Prism::Mux::H2Mux::Http2Server>(
            std::make_shared<Prism::MemoryStream>(std::move(ServerRaw)), 1U);
        auto ClientTransport = std::make_shared<Prism::MemoryStream>(std::move(ClientRaw));
        RequestAdmissionObservation Observation;
        Watchdog Guard(Io, std::chrono::seconds(3));
        auto RunResult = std::make_shared<ServerRunObservation>();

        StartServerRun(Io.get_executor(), Server, RunResult);
        Net::co_spawn(Io, RunRequestAdmission(RequestAdmissionScenario{
                                Server, ClientTransport, Observation, Guard}),
                      Net::detached);
        Io.run();
        if (*Guard.Timeouted)
        {
            Io.restart();
            Server->Close();
            Io.run();
        }

        EXPECT_FALSE(*Guard.Timeouted);
        EXPECT_TRUE(RunResult->Completed);
        EXPECT_FALSE(RunResult->Threw);
        EXPECT_TRUE(RunResult->Succeeded);
        EXPECT_TRUE(RunResult->Retired);
        EXPECT_EQ(Observation.StreamIds, (std::array<std::int32_t, 8>{1, 3, 5, 7, 9, 11, 13, 15}));
        EXPECT_EQ(Observation.DataBytes, RequestAdmissionPayload.size());
        ASSERT_EQ(Observation.DataPayload.size(), RequestAdmissionPayload.size());
        EXPECT_TRUE(std::equal(RequestAdmissionPayload.begin(), RequestAdmissionPayload.end(),
                               Observation.DataPayload.begin()));
        EXPECT_EQ(Observation.DataStreamId, Observation.StreamIds[7]);
        EXPECT_FALSE(Observation.MixedDataStreams);
        ASSERT_EQ(Observation.Responses.size(), 8U);
        for (const auto &Response : Observation.Responses) EXPECT_EQ(Response.StatusCount, 1U);

        for (std::size_t Index = 0; Index < 6U; ++Index)
        {
            const auto Response = FindResponse(Observation, Observation.StreamIds[Index]);
            ASSERT_NE(Response, nullptr);
            EXPECT_EQ(Response->StatusCode, 400U);
            EXPECT_TRUE(Response->EndStream);
            EXPECT_EQ(Observation.MalformedResetErrors[Index], Prism::Http2::ErrorProtocol);
        }

        const auto GetResponse = FindResponse(Observation, Observation.StreamIds[6]);
        ASSERT_NE(GetResponse, nullptr);
        EXPECT_EQ(GetResponse->StatusCode, 405U);
        EXPECT_TRUE(GetResponse->AllowsConnect);
        EXPECT_TRUE(GetResponse->EndStream);

        const auto ConnectResponse = FindResponse(Observation, Observation.StreamIds[7]);
        ASSERT_NE(ConnectResponse, nullptr);
        EXPECT_EQ(ConnectResponse->StatusCode, 200U);
        EXPECT_FALSE(ConnectResponse->EndStream);
    }
