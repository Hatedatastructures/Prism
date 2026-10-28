/**
 * @file AuthTerminalReadTest.cpp
 * @brief TUIC 精确读取与独立认证流终态测试。
 */
#include <gtest/gtest.h>

#include <Prism/Protocols/Tuic/Connection/Connection.hpp>
#include <Prism/Protocols/Tuic/Connection/Io.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "TerminalReadSupport.hpp"

namespace
{
    namespace Net = boost::asio;
    namespace Tuic = Prism::Tuic;
    namespace Terminal = Prism::Test::TuicTerminalRead;
    using Terminal::CloseAndDrain;
    using Terminal::DrainActivity;
    using Terminal::ReadStep;
    using Terminal::RunCoroutine;
    using Terminal::ScriptedTransport;

    struct AuthenticationScenario final
    {
        Prism::Fault::Failure Terminal{};
        std::size_t ByteCount{0};
        Prism::Error Status{Prism::Error::None};
        Prism::Error EffectiveStatus{Prism::Error::None};
    };

    [[nodiscard]] auto CopyAuthToken(
        const std::array<std::uint8_t, Tuic::TokenLen> &Token,
        const std::span<std::uint8_t> Output) -> bool
    {
        if (Output.size() != Token.size())
        {
            return false;
        }
        std::copy(Token.begin(), Token.end(), Output.begin());
        return true;
    }

    auto MakeAuthExporter(const std::array<std::uint8_t, Tuic::TokenLen> &Token)
        -> Tuic::KeyingMaterialExporter
    {
        return [Token](
                   std::span<std::uint8_t> Output,
                   std::span<const std::uint8_t>,
                   std::string_view) -> bool
        {
            return CopyAuthToken(Token, Output);
        };
    }

    auto VerifyExactReadBytesAndFailure(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        const auto Native = std::make_error_code(std::errc::connection_reset);
        std::deque<ReadStep> Steps;
        Steps.push_back({{'a', 'b', 'c'}, {Prism::Fault::Code::IoError, Native}});
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Tcp, std::move(Steps));
        std::array<std::uint8_t, 3> Buffer{};
        const auto Result = co_await Tuic::detail::ConnIo<
            Prism::Memory::SessionResource<>>::ReadExactFrom(
                Upstream, std::span<std::uint8_t>(Buffer));

        EXPECT_EQ(Result.Bytes, Buffer.size());
        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::IoError);
        EXPECT_EQ(Result.Failure.Native, Native);
        EXPECT_EQ(Buffer, (std::array<std::uint8_t, 3>{'a', 'b', 'c'}));
        EXPECT_TRUE(co_await CloseAndDrain(*Upstream));
    }

    auto VerifyAuthenticationTerminal(
        Net::any_io_executor Executor,
        AuthenticationScenario Scenario) -> Net::awaitable<void>
    {
        std::array<std::uint8_t, Tuic::UuidLen> Uuid{};
        std::array<std::uint8_t, Tuic::TokenLen> Token{};
        Token[0] = 0xA5;
        const auto Wire = Tuic::BuildAuthenticate(Uuid, Token);
        std::vector<std::uint8_t> Bytes(
            Wire.begin(), Wire.begin() + Scenario.ByteCount);
        std::deque<ReadStep> Steps;
        Steps.push_back({std::move(Bytes), Scenario.Terminal});
        auto Upstream = std::make_shared<ScriptedTransport>(
            Executor,
            Prism::Transmission::Type::Tcp,
            std::deque<ReadStep>{});
        auto Connection = std::make_shared<Tuic::Conn<>>(Upstream, Uuid);
        auto AuthStream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Tcp, std::move(Steps));
        Tuic::ServerAuthenticationMaterial Material{
            .Exporter = MakeAuthExporter(Token),
            .ExporterContext = "secret",
            .Credential = {}};

        const auto Result = co_await Connection->ReadAuthentication(
            AuthStream, std::move(Material));
        EXPECT_EQ(Result.Status, Scenario.Status);
        EXPECT_EQ(Result.EffectiveStatus(), Scenario.EffectiveStatus);
        EXPECT_TRUE(Result.Terminal.has_value());
        if (Result.Terminal)
        {
            EXPECT_EQ(Result.Terminal->Code, Scenario.Terminal.Code);
            EXPECT_EQ(Result.Terminal->Native, Scenario.Terminal.Native);
        }
        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
        EXPECT_TRUE(co_await CloseAndDrain(*AuthStream));
    }

} // namespace

TEST(TuicTerminalRead, ConnExactReadRetainsBytesAndNativeFailure)
{
    Net::io_context IoContext;
    RunCoroutine(IoContext, VerifyExactReadBytesAndFailure(IoContext.get_executor()));
}

TEST(TuicTerminalRead, CompleteAuthenticationEofIsNormal)
{
    Net::io_context IoContext;
    RunCoroutine(
        IoContext,
        VerifyAuthenticationTerminal(
            IoContext.get_executor(),
            {{Prism::Fault::Code::Eof},
             Tuic::AuthenticateFrameLen,
             Prism::Error::None,
             Prism::Error::None}));
}

TEST(TuicTerminalRead, CompleteAuthenticationResetPropagates)
{
    Net::io_context IoContext;
    RunCoroutine(
        IoContext,
        VerifyAuthenticationTerminal(
            IoContext.get_executor(),
            {{Prism::Fault::Code::IoError,
              std::make_error_code(std::errc::connection_reset)},
             Tuic::AuthenticateFrameLen,
             Prism::Error::None,
             Prism::Error::IoError}));
}

TEST(TuicTerminalRead, IncompleteAuthenticationEofIsTruncated)
{
    Net::io_context IoContext;
    RunCoroutine(
        IoContext,
        VerifyAuthenticationTerminal(
            IoContext.get_executor(),
            {{Prism::Fault::Code::Eof},
             Tuic::AuthenticateFrameLen - 1U,
             Prism::Error::UnexpectedEof,
             Prism::Error::UnexpectedEof}));
}

TEST(TuicTerminalRead, PartialAuthenticationResetPropagates)
{
    Net::io_context IoContext;
    RunCoroutine(
        IoContext,
        VerifyAuthenticationTerminal(
            IoContext.get_executor(),
            {{Prism::Fault::Code::IoError,
              std::make_error_code(std::errc::connection_reset)},
             Tuic::AuthenticateFrameLen - 1U,
             Prism::Error::IoError,
             Prism::Error::IoError}));
}
