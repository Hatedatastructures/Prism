/**
 * @file Http11IoResultOrderingTest.cpp
 * @brief HTTP/1.1 读取路径的 Bytes 与同次终态顺序回归测试。
 */

#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Http1/Conn.hpp>
#include <Prism/Protocols/Http1/Parser.hpp>
#include <Prism/Protocols/Http1/ForwardRequestTransport.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>

#include <gtest/gtest.h>

#include "HttpTestSupport.hpp"

namespace
{
    namespace Net = boost::asio;

    class ScriptedTransmission final : public Prism::Transmission
    {
    public:
        ScriptedTransmission(
            Net::any_io_executor Executor,
            std::string Bytes,
            Prism::Fault::Failure Terminal)
            : Prism::Transmission(Executor), Executor_(std::move(Executor)),
              Bytes_(std::move(Bytes)), Terminal_(std::move(Terminal))
        {
        }

        auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

        [[nodiscard]] auto ReadCalls() const noexcept -> std::size_t
        {
            return ReadCalls_;
        }

        [[nodiscard]] auto CloseCalls() const noexcept -> std::size_t
        {
            return CloseCalls_;
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadCalls_;
            Prism::IoResult Result;
            if (!Sent_)
            {
                const auto Count = (std::min)(Buffer.size(), Bytes_.size() - Offset_);
                if (Count != 0U)
                {
                    std::memcpy(Buffer.data(), Bytes_.data() + Offset_, Count);
                    Offset_ += Count;
                    Result.Bytes = Count;
                }
                if (Offset_ == Bytes_.size())
                {
                    Result.Failure = Terminal_;
                    Sent_ = true;
                }
            }
            else
            {
                Result.Failure = {Prism::Fault::Code::WouldBlock};
            }
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), std::move(Result));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), Prism::IoResult{Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor_, std::move(Handler), {});
        }

    protected:
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            ++CloseCalls_;
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        Net::any_io_executor Executor_;
        std::string Bytes_;
        Prism::Fault::Failure Terminal_;
        std::size_t Offset_{0};
        std::size_t ReadCalls_{0};
        std::size_t CloseCalls_{0};
        bool Sent_{false};
    };

    struct ForwardReadCase final
    {
        std::shared_ptr<ScriptedTransmission> Inner;
        Prism::SharedTransmission Forwarded;
        Prism::Testing::Http11::ReadUntilEofResult First;
        Prism::Testing::Http11::ReadUntilEofResult Second;
    };

    auto RunForwardReads(ForwardReadCase *State) -> Net::awaitable<void>
    {
        std::array<std::byte, 512> Buffer{};
        const auto First = co_await State->Forwarded->ReadSome(Buffer);
        Prism::Testing::Http11::CaptureRead(State->First, First, Buffer);
        const auto Second = co_await State->Forwarded->ReadSome(Buffer);
        Prism::Testing::Http11::CaptureRead(State->Second, Second, Buffer);
    }

    struct ServerRequestCase final
    {
        std::shared_ptr<ScriptedTransmission> Inner;
        Prism::SharedTransmission Forwarded;
        Prism::Fault::Failure ReadRequestFailure;
        Prism::Testing::Http11::ReadUntilEofResult First;
        Prism::Testing::Http11::ReadUntilEofResult Second;
    };

    auto RunServerRequest(ServerRequestCase *State) -> Net::awaitable<void>
    {
        Prism::Http11::ServerConn Server(State->Inner, Prism::Testing::Http11::MakeBytePool());
        Prism::Http11::HttpRequest Request;
        State->ReadRequestFailure = co_await Server.ReadRequest(Request);
        if (State->ReadRequestFailure.Failed())
        {
            co_return;
        }
        State->Forwarded = Server.ReleaseForward();
        if (!State->Forwarded)
        {
            co_return;
        }
        std::array<std::byte, 512> Buffer{};
        const auto First = co_await State->Forwarded->ReadSome(Buffer);
        Prism::Testing::Http11::CaptureRead(State->First, First, Buffer);
        const auto Second = co_await State->Forwarded->ReadSome(Buffer);
        Prism::Testing::Http11::CaptureRead(State->Second, Second, Buffer);
    }

    struct TerminalServerRequestCase final
    {
        std::shared_ptr<ScriptedTransmission> Inner;
        Prism::SharedTransmission Forwarded;
        Prism::Fault::Failure ReadRequestFailure;
        std::optional<Prism::Http11::ProxyTarget> Target;
        Prism::Testing::Http11::ReadUntilEofResult First;
        Prism::Testing::Http11::ReadUntilEofResult Second;
        Prism::Testing::Http11::ReadUntilEofResult Third;
    };

    auto RunTerminalServerRequest(TerminalServerRequestCase *State) -> Net::awaitable<void>
    {
        Prism::Http11::ServerConn Server(State->Inner, Prism::Testing::Http11::MakeBytePool());
        Prism::Http11::HttpRequest Request;
        State->ReadRequestFailure = co_await Server.ReadRequest(Request);
        State->Target = Prism::Http11::ResolveTarget(Request);
        if (State->ReadRequestFailure.Failed())
        {
            co_return;
        }
        State->Forwarded = State->Target &&
                                   State->Target->Form == Prism::Http11::RequestForm::Connect
                               ? Server.Release()
                               : Server.ReleaseForward();
        if (!State->Forwarded)
        {
            co_return;
        }
        std::array<std::byte, 512> Buffer{};
        const auto First = co_await State->Forwarded->ReadSome(Buffer);
        Prism::Testing::Http11::CaptureRead(State->First, First, Buffer);
        const auto Second = co_await State->Forwarded->ReadSome(Buffer);
        Prism::Testing::Http11::CaptureRead(State->Second, Second, Buffer);
        const auto Third = co_await State->Forwarded->ReadSome(Buffer);
        Prism::Testing::Http11::CaptureRead(State->Third, Third, Buffer);
    }

    struct ResponseReadCase final
    {
        std::shared_ptr<ScriptedTransmission> Inner;
        Prism::SharedTransmission Transport;
        std::error_code Error;
        int Status{0};
        Prism::Testing::Http11::ReadUntilEofResult Body;
    };

    auto RunResponseRead(ResponseReadCase *State) -> Net::awaitable<void>
    {
        State->Status = co_await Prism::Http11::ReadResponse(
            State->Transport, State->Error, Prism::Testing::Http11::MakeBytePool());
        if (!State->Transport)
        {
            co_return;
        }
        std::array<std::byte, 64> Buffer{};
        const auto Result = co_await State->Transport->ReadSome(Buffer);
        Prism::Testing::Http11::CaptureRead(State->Body, Result, Buffer);
    }
}

TEST(Http11IoResultOrdering, ChunkDataReturnsBufferedBytesAndEofWithoutRefill)
{
    Net::io_context Io;
    ForwardReadCase State;
    State.Inner = std::make_shared<ScriptedTransmission>(
        Io.get_executor(), "4\r\nWi", Prism::Fault::Failure{Prism::Fault::Code::Eof});
    Prism::Http11::ForwardRequestOptions Options;
    Options.Inner = State.Inner;
    Options.Header = "POST /upload HTTP/1.1\r\nHost: example.com\r\n"
                     "Transfer-Encoding: chunked\r\n\r\n";
    Options.BodyMode = Prism::Http11::ForwardBodyMode::Chunked;
    State.Forwarded = Prism::Http11::MakeForwardRequestTransport(std::move(Options));

    Prism::Testing::Http11::RunOwnedCase(Io, {State.Forwarded}, RunForwardReads(&State));

    EXPECT_EQ(State.First.Bytes,
              "POST /upload HTTP/1.1\r\nHost: example.com\r\n"
              "Transfer-Encoding: chunked\r\n\r\n4\r\nWi");
    EXPECT_EQ(Prism::Fault::ToNative(State.First.Failure),
              Prism::make_error_code(Prism::Error::UnexpectedEof));
    EXPECT_TRUE(State.Second.Bytes.empty());
    EXPECT_EQ(State.Second.Failure.Code, State.First.Failure.Code);
    EXPECT_EQ(State.Second.Failure.Native, State.First.Failure.Native);
    EXPECT_EQ(State.Inner->ReadCalls(), 1U);
}

TEST(Http11IoResultOrdering, RequestPreviewKeepsBytesAndNativeFailureFromOneRead)
{
    Net::io_context Io;
    ServerRequestCase State;
    const auto Native = std::make_error_code(std::errc::connection_reset);
    State.Inner = std::make_shared<ScriptedTransmission>(
        Io.get_executor(),
        "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\n\r\nWi",
        Prism::Fault::FromNative(Native));

    Prism::Testing::Http11::RunCoroutine(Io, RunServerRequest(&State));
    const auto Cleanup = State.Forwarded ? State.Forwarded : State.Inner;
    Prism::Testing::Http11::CheckTransmissionClose(
        Prism::Testing::Http11::DriveCloseTransmission(Io, Cleanup));

    EXPECT_FALSE(State.ReadRequestFailure.Failed());
    EXPECT_EQ(State.First.Bytes,
              "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\n\r\nWi");
    EXPECT_EQ(State.First.Failure.Code, Prism::Fault::Code::ConnectionReset);
    EXPECT_EQ(State.First.Failure.Native, Native);
    EXPECT_TRUE(State.Second.Bytes.empty());
    EXPECT_EQ(State.Second.Failure.Native, Native);
    EXPECT_EQ(State.Inner->ReadCalls(), 1U);
}

TEST(Http11IoResultOrdering, ConnectWithoutBodyPreservesSameReadEof)
{
    Net::io_context Io;
    TerminalServerRequestCase State;
    State.Inner = std::make_shared<ScriptedTransmission>(
        Io.get_executor(),
        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        Prism::Fault::Failure{Prism::Fault::Code::Eof});

    Prism::Testing::Http11::RunCoroutine(Io, RunTerminalServerRequest(&State));
    const auto Cleanup = State.Forwarded ? State.Forwarded : State.Inner;
    Prism::Testing::Http11::CheckTransmissionClose(
        Prism::Testing::Http11::DriveCloseTransmission(Io, Cleanup));

    ASSERT_TRUE(State.ReadRequestFailure.Succeeded());
    ASSERT_TRUE(State.Target.has_value());
    EXPECT_EQ(State.Target->Host, "example.com");
    EXPECT_EQ(State.Target->Port, 443U);
    EXPECT_EQ(State.Target->Form, Prism::Http11::RequestForm::Connect);
    EXPECT_TRUE(State.First.Bytes.empty());
    EXPECT_EQ(State.First.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_TRUE(State.Second.Bytes.empty());
    EXPECT_EQ(State.Second.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_TRUE(State.Third.Bytes.empty());
    EXPECT_EQ(State.Third.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(State.Inner->ReadCalls(), 1U);
    EXPECT_EQ(State.Inner->CloseCalls(), 1U);
}

TEST(Http11IoResultOrdering, ConnectWithoutBodyPreservesSameReadNativeFailure)
{
    Net::io_context Io;
    TerminalServerRequestCase State;
    const auto Native = std::make_error_code(std::errc::connection_reset);
    State.Inner = std::make_shared<ScriptedTransmission>(
        Io.get_executor(),
        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        Prism::Fault::Failure{Prism::Fault::Code::IoError, Native});

    Prism::Testing::Http11::RunCoroutine(Io, RunTerminalServerRequest(&State));
    const auto Cleanup = State.Forwarded ? State.Forwarded : State.Inner;
    Prism::Testing::Http11::CheckTransmissionClose(
        Prism::Testing::Http11::DriveCloseTransmission(Io, Cleanup));

    ASSERT_TRUE(State.ReadRequestFailure.Succeeded());
    ASSERT_TRUE(State.Target.has_value());
    EXPECT_EQ(State.Target->Host, "example.com");
    EXPECT_EQ(State.Target->Port, 443U);
    EXPECT_EQ(State.Target->Form, Prism::Http11::RequestForm::Connect);
    EXPECT_TRUE(State.First.Bytes.empty());
    EXPECT_EQ(State.First.Failure.Code, Prism::Fault::Code::IoError);
    EXPECT_EQ(State.First.Failure.Native, Native);
    EXPECT_TRUE(State.Second.Bytes.empty());
    EXPECT_EQ(State.Second.Failure.Code, Prism::Fault::Code::IoError);
    EXPECT_EQ(State.Second.Failure.Native, Native);
    EXPECT_TRUE(State.Third.Bytes.empty());
    EXPECT_EQ(State.Third.Failure.Code, Prism::Fault::Code::IoError);
    EXPECT_EQ(State.Third.Failure.Native, Native);
    EXPECT_EQ(State.Inner->ReadCalls(), 1U);
    EXPECT_EQ(State.Inner->CloseCalls(), 1U);
}

TEST(Http11IoResultOrdering, ZeroLengthRequestPreservesSameReadNativeFailure)
{
    Net::io_context Io;
    TerminalServerRequestCase State;
    const auto Native = std::make_error_code(std::errc::connection_reset);
    State.Inner = std::make_shared<ScriptedTransmission>(
        Io.get_executor(),
        "GET /resource HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
        Prism::Fault::Failure{Prism::Fault::Code::IoError, Native});

    Prism::Testing::Http11::RunCoroutine(Io, RunTerminalServerRequest(&State));
    const auto Cleanup = State.Forwarded ? State.Forwarded : State.Inner;
    Prism::Testing::Http11::CheckTransmissionClose(
        Prism::Testing::Http11::DriveCloseTransmission(Io, Cleanup));

    ASSERT_TRUE(State.ReadRequestFailure.Succeeded());
    ASSERT_TRUE(State.Target.has_value());
    EXPECT_EQ(State.Target->Host, "example.com");
    EXPECT_EQ(State.Target->Port, 80U);
    EXPECT_EQ(State.Target->Form, Prism::Http11::RequestForm::Origin);
    EXPECT_FALSE(State.First.Bytes.empty());
    EXPECT_EQ(State.First.Bytes.find("GET /resource HTTP/1.1"), 0U);
    EXPECT_TRUE(State.First.Failure.Succeeded());
    EXPECT_TRUE(State.Second.Bytes.empty());
    EXPECT_EQ(State.Second.Failure.Code, Prism::Fault::Code::IoError);
    EXPECT_EQ(State.Second.Failure.Native, Native);
    EXPECT_TRUE(State.Third.Bytes.empty());
    EXPECT_EQ(State.Third.Failure.Code, Prism::Fault::Code::IoError);
    EXPECT_EQ(State.Third.Failure.Native, Native);
    EXPECT_EQ(State.Inner->ReadCalls(), 1U);
    EXPECT_EQ(State.Inner->CloseCalls(), 1U);
}

TEST(Http11IoResultOrdering, UnframedGetPreservesSameReadEof)
{
    Net::io_context Io;
    TerminalServerRequestCase State;
    State.Inner = std::make_shared<ScriptedTransmission>(
        Io.get_executor(),
        "GET /resource HTTP/1.1\r\nHost: example.com\r\n\r\n",
        Prism::Fault::Failure{Prism::Fault::Code::Eof});

    Prism::Testing::Http11::RunCoroutine(Io, RunTerminalServerRequest(&State));
    const auto Cleanup = State.Forwarded ? State.Forwarded : State.Inner;
    Prism::Testing::Http11::CheckTransmissionClose(
        Prism::Testing::Http11::DriveCloseTransmission(Io, Cleanup));

    ASSERT_TRUE(State.ReadRequestFailure.Succeeded());
    ASSERT_TRUE(State.Target.has_value());
    EXPECT_EQ(State.Target->Host, "example.com");
    EXPECT_EQ(State.Target->Port, 80U);
    EXPECT_EQ(State.Target->Form, Prism::Http11::RequestForm::Origin);
    EXPECT_EQ(State.First.Bytes, "GET /resource HTTP/1.1\r\nHost: example.com\r\n\r\n");
    EXPECT_TRUE(State.First.Failure.Succeeded());
    EXPECT_TRUE(State.Second.Bytes.empty());
    EXPECT_EQ(State.Second.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_TRUE(State.Third.Bytes.empty());
    EXPECT_EQ(State.Third.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(State.Inner->ReadCalls(), 1U);
    EXPECT_EQ(State.Inner->CloseCalls(), 1U);
}

TEST(Http11IoResultOrdering, IncompleteContentLengthWithSameReadTerminalIsRejected)
{
    Net::io_context Io;
    TerminalServerRequestCase State;
    const auto Native = std::make_error_code(std::errc::connection_reset);
    State.Inner = std::make_shared<ScriptedTransmission>(
        Io.get_executor(),
        "POST /resource HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nWi",
        Prism::Fault::FromNative(Native));

    Prism::Testing::Http11::RunCoroutine(Io, RunTerminalServerRequest(&State));
    Prism::Testing::Http11::CheckTransmissionClose(
        Prism::Testing::Http11::DriveCloseTransmission(Io, State.Inner));

    EXPECT_EQ(State.ReadRequestFailure.Code, Prism::Fault::Code::ConnectionReset);
    EXPECT_EQ(State.ReadRequestFailure.Native, Native);
    EXPECT_FALSE(State.Forwarded);
    ASSERT_TRUE(State.Target.has_value());
    EXPECT_EQ(State.Target->Host, "example.com");
    EXPECT_EQ(State.Target->Port, 80U);
    EXPECT_EQ(State.Inner->ReadCalls(), 1U);
    EXPECT_EQ(State.Inner->CloseCalls(), 1U);
}

TEST(Http11IoResultOrdering, IncompleteChunkedRequestWithSameReadEofIsRejected)
{
    Net::io_context Io;
    TerminalServerRequestCase State;
    State.Inner = std::make_shared<ScriptedTransmission>(
        Io.get_executor(),
        "POST /resource HTTP/1.1\r\nHost: example.com\r\n"
        "Transfer-Encoding: chunked\r\n\r\n4\r\nWi",
        Prism::Fault::Failure{Prism::Fault::Code::Eof});

    Prism::Testing::Http11::RunCoroutine(Io, RunTerminalServerRequest(&State));
    Prism::Testing::Http11::CheckTransmissionClose(
        Prism::Testing::Http11::DriveCloseTransmission(Io, State.Inner));

    EXPECT_EQ(State.ReadRequestFailure.Code, Prism::Fault::Code::Eof);
    EXPECT_FALSE(State.Forwarded);
    ASSERT_TRUE(State.Target.has_value());
    EXPECT_EQ(State.Target->Form, Prism::Http11::RequestForm::Origin);
    EXPECT_EQ(State.Inner->ReadCalls(), 1U);
    EXPECT_EQ(State.Inner->CloseCalls(), 1U);
}

TEST(Http11IoResultOrdering, CompleteChunkedRequestEofBecomesCleanBodyEnd)
{
    Net::io_context Io;
    ServerRequestCase State;
    const std::string Wire =
        "POST /chunked HTTP/1.1\r\nHost: example.com\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "4\r\nWiki\r\n0\r\n\r\n";
    State.Inner = std::make_shared<ScriptedTransmission>(
        Io.get_executor(), Wire, Prism::Fault::Failure{Prism::Fault::Code::Eof});

    Prism::Testing::Http11::RunCoroutine(Io, RunServerRequest(&State));
    Prism::Testing::Http11::CheckTransmissionClose(
        Prism::Testing::Http11::DriveCloseTransmission(Io, State.Forwarded));

    EXPECT_FALSE(State.ReadRequestFailure.Failed());
    EXPECT_EQ(State.First.Bytes,
              "POST /chunked HTTP/1.1\r\nHost: example.com\r\n"
              "Transfer-Encoding: chunked\r\n\r\n"
              "4\r\nWiki\r\n0\r\n\r\n");
    EXPECT_TRUE(State.First.Failure.Succeeded());
    EXPECT_TRUE(State.Second.Bytes.empty());
    EXPECT_EQ(State.Second.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(State.Inner->ReadCalls(), 1U);
}

TEST(Http11IoResultOrdering, CompleteChunkedUpgradeEofDoesNotRefill)
{
    Net::io_context Io;
    ServerRequestCase State;
    const std::string Wire =
        "POST /upgrade HTTP/1.1\r\nHost: example.com\r\n"
        "Connection: Upgrade\r\nUpgrade: websocket\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "4\r\nWiki\r\n0\r\n\r\n";
    State.Inner = std::make_shared<ScriptedTransmission>(
        Io.get_executor(), Wire, Prism::Fault::Failure{Prism::Fault::Code::Eof});

    Prism::Testing::Http11::RunCoroutine(Io, RunServerRequest(&State));
    Prism::Testing::Http11::CheckTransmissionClose(
        Prism::Testing::Http11::DriveCloseTransmission(Io, State.Forwarded));

    EXPECT_FALSE(State.ReadRequestFailure.Failed());
    EXPECT_EQ(State.First.Bytes,
              "POST /upgrade HTTP/1.1\r\nHost: example.com\r\n"
              "Connection: Upgrade\r\nUpgrade: websocket\r\n"
              "Transfer-Encoding: chunked\r\n\r\n"
              "4\r\nWiki\r\n0\r\n\r\n");
    EXPECT_TRUE(State.First.Failure.Succeeded());
    EXPECT_TRUE(State.Second.Bytes.empty());
    EXPECT_EQ(State.Second.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(State.Inner->ReadCalls(), 1U);
}

TEST(Http11IoResultOrdering, CompleteChunkedRequestNativeFailureFollowsWireBytes)
{
    Net::io_context Io;
    ServerRequestCase State;
    const auto Native = std::make_error_code(std::errc::connection_reset);
    const std::string Wire =
        "POST /chunked HTTP/1.1\r\nHost: example.com\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "4\r\nWiki\r\n0\r\n\r\n";
    State.Inner = std::make_shared<ScriptedTransmission>(
        Io.get_executor(), Wire, Prism::Fault::FromNative(Native));

    Prism::Testing::Http11::RunCoroutine(Io, RunServerRequest(&State));
    Prism::Testing::Http11::CheckTransmissionClose(
        Prism::Testing::Http11::DriveCloseTransmission(Io, State.Forwarded));

    EXPECT_FALSE(State.ReadRequestFailure.Failed());
    EXPECT_EQ(State.First.Bytes,
              "POST /chunked HTTP/1.1\r\nHost: example.com\r\n"
              "Transfer-Encoding: chunked\r\n\r\n"
              "4\r\nWiki\r\n0\r\n\r\n");
    EXPECT_EQ(State.First.Failure.Native, Native);
    EXPECT_TRUE(State.Second.Bytes.empty());
    EXPECT_EQ(State.Second.Failure.Native, Native);
    EXPECT_EQ(State.Inner->ReadCalls(), 1U);
}

TEST(Http11IoResultOrdering, CompleteChunkedRequestDoesNotConsumeNextRequestTail)
{
    Net::io_context Io;
    ServerRequestCase State;
    const std::string FirstRequest =
        "POST /chunked HTTP/1.1\r\nHost: example.com\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "4\r\nWiki\r\n0\r\n\r\n";
    const std::string NextRequest = "GET /next HTTP/1.1\r\nHost: example.com\r\n\r\n";
    State.Inner = std::make_shared<ScriptedTransmission>(
        Io.get_executor(), FirstRequest + NextRequest,
        Prism::Fault::FromNative(std::make_error_code(std::errc::connection_reset)));

    Prism::Testing::Http11::RunCoroutine(Io, RunServerRequest(&State));
    Prism::Testing::Http11::CheckTransmissionClose(
        Prism::Testing::Http11::DriveCloseTransmission(Io, State.Forwarded));

    EXPECT_FALSE(State.ReadRequestFailure.Failed());
    EXPECT_EQ(State.First.Bytes,
              "POST /chunked HTTP/1.1\r\nHost: example.com\r\n"
              "Transfer-Encoding: chunked\r\n\r\n"
              "4\r\nWiki\r\n0\r\n\r\n");
    EXPECT_TRUE(State.First.Failure.Succeeded());
    EXPECT_TRUE(State.Second.Bytes.empty());
    EXPECT_EQ(State.Second.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(State.Inner->ReadCalls(), 1U);
}

TEST(Http11IoResultOrdering, ResponsePreviewReturnsBodyBytesBeforeNativeFailure)
{
    Net::io_context Io;
    const auto Native = std::make_error_code(std::errc::connection_reset);
    ResponseReadCase State;
    State.Inner = std::make_shared<ScriptedTransmission>(
        Io.get_executor(),
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc",
        Prism::Fault::FromNative(Native));
    State.Transport = State.Inner;

    Prism::Testing::Http11::RunCoroutine(Io, RunResponseRead(&State));
    Prism::Testing::Http11::CheckTransmissionClose(
        Prism::Testing::Http11::DriveCloseTransmission(Io, State.Transport));

    EXPECT_EQ(State.Status, 200);
    EXPECT_FALSE(State.Error);
    EXPECT_EQ(State.Body.Bytes, "abc");
    EXPECT_EQ(State.Body.Failure.Native, Native);
    EXPECT_EQ(State.Inner->ReadCalls(), 1U);
}
