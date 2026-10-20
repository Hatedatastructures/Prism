/**
 * @file TuicTerminalReadTest.cpp
 * @brief TUIC 在有效读取字节与终止状态同次到达时的交付顺序。
 */

#include <boost/asio/awaitable.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <iterator>
#include <memory>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Protocols/Tuic/Conn.hpp>
#include <Prism/Protocols/Tuic/Dgram.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Tuic = Prism::Tuic;

    struct ReadStep final
    {
        std::vector<std::uint8_t> Bytes{};
        Prism::Fault::Failure Failure{};
    };

    struct AuthenticationScenario final
    {
        Prism::Fault::Failure Terminal{};
        std::size_t ByteCount{0};
        Prism::Error Status{Prism::Error::None};
        Prism::Error EffectiveStatus{Prism::Error::None};
    };

    /** @brief 按调用序列回放字节和 terminal，可注入同次完成与失败。 */
    class ScriptedTransport final : public Prism::Transmission
    {
    public:
        ScriptedTransport(
            Net::any_io_executor Executor,
            const Type Transport,
            std::deque<ReadStep> ReadSteps)
            : Transmission(Executor),
              Executor_(std::move(Executor)),
              Transport_(Transport),
              ReadSteps_(std::move(ReadSteps))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Transport_;
        }

        std::size_t ReadsDone{0};

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadsDone;
            Prism::IoResult Result{};
            if (ReadSteps_.empty())
            {
                Result.Failure = {Prism::Fault::Code::Eof};
            }
            else
            {
                auto Step = std::move(ReadSteps_.front());
                ReadSteps_.pop_front();
                Result.Bytes = (std::min)(Buffer.size(), Step.Bytes.size());
                if (Result.Bytes != 0U)
                {
                    std::memcpy(Buffer.data(), Step.Bytes.data(), Result.Bytes);
                }
                Result.Failure = Step.Failure;
            }
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), Result);
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

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        Net::any_io_executor Executor_;
        Type Transport_;
        std::deque<ReadStep> ReadSteps_;
    };

    auto RunCoroutine(Net::io_context &IoContext, Net::awaitable<void> Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(
            IoContext,
            std::move(Coroutine),
            [&Exception](std::exception_ptr ErrorValue)
            { Exception = std::move(ErrorValue); });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    auto MakePacketWire() -> std::vector<std::uint8_t>
    {
        return {0x05, 0x02, 0, 1, 0, 1, 1, 0, 0, 3,
                0x01, 1, 2, 3, 4, 0, 80, 'a', 'b', 'c'};
    }

    auto MakeStreamPacketSteps(Prism::Fault::Failure FinalFailure)
        -> std::deque<ReadStep>
    {
        return {
            {{0x05, 0x02, 0, 1, 0, 1, 1, 0, 0, 3}, {}},
            {{0x01}, {}},
            {{1, 2, 3, 4}, {}},
            {{0, 80}, {}},
            {{'a', 'b', 'c'}, FinalFailure}};
    }

    auto MakeConnPacketSteps(Prism::Fault::Failure FinalFailure)
        -> std::deque<ReadStep>
    {
        return {
            {{0x05, 0x02}, {}},
            {{0, 1, 0, 1, 1, 0, 0, 3}, {}},
            {{0x01}, {}},
            {{1, 2, 3, 4}, {}},
            {{0, 80}, {}},
            {{'a', 'b', 'c'}, FinalFailure}};
    }

    auto MakeRecoveryPacketWire() -> std::vector<std::uint8_t>
    {
        return {0x05, 0x02, 0, 2, 0, 2, 1, 0, 0, 3,
                0x01, 5, 6, 7, 8, 0, 81, 'd', 'e', 'f'};
    }

    auto MakeRecoveryConnPacketSteps() -> std::deque<ReadStep>
    {
        return {
            {{0x05, 0x02}, {}},
            {{0, 2, 0, 2, 1, 0, 0, 3}, {}},
            {{0x01}, {}},
            {{5, 6, 7, 8}, {}},
            {{0, 81}, {}},
            {{'d', 'e', 'f'}, {}}};
    }

    auto MakeFragmentWire(const std::uint8_t FragmentId, std::string_view Payload)
        -> std::vector<std::uint8_t>
    {
        const auto Size = static_cast<std::uint16_t>(Payload.size());
        std::vector<std::uint8_t> Wire{
            0x05, 0x02, 0, 1, 0, 7, 3, FragmentId,
            static_cast<std::uint8_t>(Size >> 8U),
            static_cast<std::uint8_t>(Size)};
        if (FragmentId == 0U)
        {
            Wire.insert(Wire.end(), {0x01, 1, 2, 3, 4, 0, 80});
        }
        else
        {
            Wire.push_back(0xFF);
        }
        for (const auto Character : Payload)
        {
            Wire.push_back(static_cast<std::uint8_t>(Character));
        }
        return Wire;
    }

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

    auto DrainActivity(Prism::Transmission &Carrier) -> Net::awaitable<bool>
    {
        const auto Activity = Carrier.Activity();
        if (!Activity)
        {
            co_return false;
        }
        const auto Drained = co_await Activity->Drain();
        co_return Drained.has_value() && Activity->IsRetired();
    }

    auto CloseAndDrain(Prism::Transmission &Carrier) -> Net::awaitable<bool>
    {
        const auto Closed = Carrier.Close();
        if (!Closed)
        {
            co_return false;
        }
        co_return co_await DrainActivity(Carrier);
    }

    auto VerifyDatagramBeforeIoError(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        std::deque<ReadStep> Steps;
        Steps.push_back({MakePacketWire(), {Prism::Fault::Code::IoError}});
        Steps.push_back({MakeRecoveryPacketWire(), {}});
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Udp, std::move(Steps));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(Upstream);
        Tuic::Address Source{};
        std::vector<std::uint8_t> Payload;

        const auto PacketError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(PacketError, Prism::Error::None);
        EXPECT_EQ(Source.Port, 80);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'a', 'b', 'c'}));
        EXPECT_EQ(Upstream->ReadsDone, 1U);

        const auto TerminalError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(TerminalError, Prism::Error::IoError);
        EXPECT_EQ(Upstream->ReadsDone, 1U);

        const auto NextPacketError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(NextPacketError, Prism::Error::None);
        EXPECT_EQ(Source.Port, 81);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'d', 'e', 'f'}));
        EXPECT_EQ(Upstream->ReadsDone, 2U);
        EXPECT_TRUE(co_await CloseAndDrain(*Dgram));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

    auto VerifyStreamDatagramBeforeEof(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor),
            Prism::Transmission::Type::Tcp,
            MakeStreamPacketSteps({Prism::Fault::Code::Eof}));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(Upstream);
        Tuic::Address Source{};
        std::vector<std::uint8_t> Payload;

        const auto PacketError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(PacketError, Prism::Error::None);
        EXPECT_EQ(Source.Port, 80);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'a', 'b', 'c'}));
        EXPECT_EQ(Upstream->ReadsDone, 5U);

        const auto TerminalError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(TerminalError, Prism::Error::UnexpectedEof);
        EXPECT_EQ(Upstream->ReadsDone, 5U);

        const auto RetryError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(RetryError, Prism::Error::UnexpectedEof);
        EXPECT_EQ(Upstream->ReadsDone, 5U);

        EXPECT_TRUE(co_await CloseAndDrain(*Dgram));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

    auto VerifyStreamHeaderTerminal(
        Net::any_io_executor Executor,
        Prism::Fault::Failure Terminal,
        const Prism::Error ExpectedError) -> Net::awaitable<void>
    {
        std::deque<ReadStep> Steps;
        Steps.push_back({
            {0x05, 0x02, 0, 1, 0, 1, 1, 0, 0, 3}, Terminal});
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Tcp, std::move(Steps));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(Upstream);
        Tuic::Address Source{};
        Source.Port = 123;
        std::vector<std::uint8_t> Payload{'x'};

        const auto FirstError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(FirstError, ExpectedError);
        EXPECT_EQ(Source.Port, 123);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'x'}));
        EXPECT_EQ(Upstream->ReadsDone, 1U);

        const auto RetryError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(RetryError, ExpectedError);
        EXPECT_EQ(Upstream->ReadsDone, 1U);

        EXPECT_TRUE(co_await CloseAndDrain(*Dgram));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

    auto VerifyMalformedStreamHeaderBeforeEof(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        std::deque<ReadStep> Steps;
        Steps.push_back({
            {0x04, 0x02, 0, 1, 0, 1, 1, 0, 0, 3},
            {Prism::Fault::Code::Eof}});
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Tcp, std::move(Steps));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(Upstream);
        Tuic::Address Source{};
        Source.Port = 123;
        std::vector<std::uint8_t> Payload{'x'};

        const auto ParseError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(ParseError, Prism::Error::BadMessage);
        EXPECT_EQ(Source.Port, 123U);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'x'}));
        EXPECT_EQ(Upstream->ReadsDone, 1U);

        const auto TerminalError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(TerminalError, Prism::Error::UnexpectedEof);
        EXPECT_EQ(Upstream->ReadsDone, 1U);

        EXPECT_TRUE(co_await CloseAndDrain(*Dgram));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

    auto VerifyStreamPartialPayloadReset(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        auto Steps = MakeStreamPacketSteps({});
        Steps.back() = {{'a'}, {
            Prism::Fault::Code::IoError,
            std::make_error_code(std::errc::connection_reset)}};
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Tcp, std::move(Steps));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(Upstream);
        Tuic::Address Source{};
        Source.Port = 123;
        std::vector<std::uint8_t> Payload{'x'};

        const auto FirstError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(FirstError, Prism::Error::IoError);
        EXPECT_EQ(Source.Port, 123);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'x'}));
        EXPECT_EQ(Upstream->ReadsDone, 5U);

        const auto RetryError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(RetryError, Prism::Error::IoError);
        EXPECT_EQ(Upstream->ReadsDone, 5U);

        EXPECT_TRUE(co_await CloseAndDrain(*Dgram));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

    auto VerifyConnFrameBeforeEof(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor),
            Prism::Transmission::Type::Tcp,
            MakeConnPacketSteps({Prism::Fault::Code::Eof}));
        auto Connection = std::make_shared<Tuic::Conn<>>(
            Upstream, std::array<std::uint8_t, Tuic::UuidLen>{});
        Tuic::Address Target{};
        Target.Type = Tuic::AddressType::Ipv4;
        Target.Host = "127.0.0.1";
        Target.Port = 443;
        Connection->MarkAuthenticated();
        EXPECT_EQ(
            co_await Connection->WriteHandshake(Target), Prism::Error::None);

        Tuic::Address Source{};
        std::vector<std::uint8_t> Payload;
        const auto PacketError = co_await Connection->AsyncReceiveDatagram(Source, Payload);
        EXPECT_EQ(PacketError, Prism::Error::None);
        EXPECT_EQ(Source.Port, 80);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'a', 'b', 'c'}));
        const auto ReadsAfterPacket = Upstream->ReadsDone;
        EXPECT_EQ(ReadsAfterPacket, 6U);

        const auto TerminalError = co_await Connection->AsyncReceiveDatagram(Source, Payload);
        EXPECT_EQ(TerminalError, Prism::Error::UnexpectedEof);
        EXPECT_EQ(Upstream->ReadsDone, ReadsAfterPacket);
        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

    auto VerifyConnTerminalConsumedOnce(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        auto Steps = MakeConnPacketSteps({Prism::Fault::Code::IoError});
        auto RecoverySteps = MakeRecoveryConnPacketSteps();
        Steps.insert(
            Steps.end(),
            std::make_move_iterator(RecoverySteps.begin()),
            std::make_move_iterator(RecoverySteps.end()));
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Tcp, std::move(Steps));
        auto Connection = std::make_shared<Tuic::Conn<>>(
            Upstream, std::array<std::uint8_t, Tuic::UuidLen>{});
        Tuic::Address Target{};
        Target.Type = Tuic::AddressType::Ipv4;
        Target.Host = "127.0.0.1";
        Target.Port = 443;
        Connection->MarkAuthenticated();
        EXPECT_EQ(
            co_await Connection->WriteHandshake(Target), Prism::Error::None);

        Tuic::Address Source{};
        std::vector<std::uint8_t> Payload;
        const auto PacketError = co_await Connection->AsyncReceiveDatagram(Source, Payload);
        EXPECT_EQ(PacketError, Prism::Error::None);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'a', 'b', 'c'}));
        const auto TerminalError = co_await Connection->AsyncReceiveDatagram(Source, Payload);
        EXPECT_EQ(TerminalError, Prism::Error::IoError);
        EXPECT_EQ(Upstream->ReadsDone, 6U);
        const auto NextPacketError = co_await Connection->AsyncReceiveDatagram(Source, Payload);
        EXPECT_EQ(NextPacketError, Prism::Error::IoError);
        EXPECT_EQ(Upstream->ReadsDone, 6U);
        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

    auto VerifyConnFieldCancelIsSticky(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        std::deque<ReadStep> Steps;
        Steps.push_back({{0x05, 0x02}, {}});
        Steps.push_back({{0, 1, 0, 1, 1, 0, 0, 1}, {}});
        Steps.push_back({{}, {Prism::Fault::Code::Canceled}});
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Tcp, std::move(Steps));
        auto Connection = std::make_shared<Tuic::Conn<>>(
            Upstream, std::array<std::uint8_t, Tuic::UuidLen>{});
        Connection->MarkAuthenticated();
        Tuic::Address Target{};
        Target.Type = Tuic::AddressType::Ipv4;
        Target.Host = "127.0.0.1";
        Target.Port = 443;
        EXPECT_EQ(co_await Connection->WriteHandshake(Target), Prism::Error::None);

        Tuic::Address Source{};
        std::vector<std::uint8_t> Payload;
        const auto FirstError = co_await Connection->AsyncReceiveDatagram(Source, Payload);
        EXPECT_EQ(FirstError, Prism::Error::Canceled);
        EXPECT_EQ(Upstream->ReadsDone, 3U);

        const auto RetryError = co_await Connection->AsyncReceiveDatagram(Source, Payload);
        EXPECT_EQ(RetryError, Prism::Error::Canceled);
        EXPECT_EQ(Upstream->ReadsDone, 3U);
        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

    auto VerifyConnCompleteHandshakeTerminalIsSticky(
        Net::any_io_executor Executor) -> Net::awaitable<void>
    {
        const auto Native = std::make_error_code(std::errc::connection_reset);
        const Prism::Fault::Failure Terminal{Prism::Fault::Code::IoError, Native};
        std::deque<ReadStep> Steps;
        Steps.push_back({{0x05, 0x01}, {}});
        Steps.push_back({{0x01}, {}});
        Steps.push_back({{1, 2, 3, 4}, {}});
        Steps.push_back({{0, 80}, Terminal});
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Tcp, std::move(Steps));
        auto Connection = std::make_shared<Tuic::Conn<>>(
            Upstream, std::array<std::uint8_t, Tuic::UuidLen>{});
        Connection->MarkAuthenticated();

        const auto [HandshakeError, Request] = co_await Connection->ReadHandshake();
        EXPECT_EQ(HandshakeError, Prism::Error::None);
        EXPECT_EQ(Request.Cmd, Tuic::CmdConnect);
        EXPECT_EQ(Request.dst.Port, 80U);
        EXPECT_EQ(Upstream->ReadsDone, 4U);

        std::array<std::byte, 1> Buffer{};
        const auto FirstRead = co_await Connection->ReadSome(Buffer);
        EXPECT_EQ(FirstRead.Bytes, 0U);
        EXPECT_EQ(FirstRead.Failure.Code, Terminal.Code);
        EXPECT_EQ(FirstRead.Failure.Native, Terminal.Native);
        EXPECT_EQ(Upstream->ReadsDone, 4U);

        const auto RetryRead = co_await Connection->ReadSome(Buffer);
        EXPECT_EQ(RetryRead.Bytes, 0U);
        EXPECT_EQ(RetryRead.Failure.Code, Terminal.Code);
        EXPECT_EQ(RetryRead.Failure.Native, Terminal.Native);
        EXPECT_EQ(Upstream->ReadsDone, 4U);
        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

    auto VerifyLastFragmentTerminalFollowsPacket(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        std::deque<ReadStep> Steps;
        Steps.push_back({MakeFragmentWire(0, "ab"), {}});
        Steps.push_back({MakeFragmentWire(1, "cd"), {}});
        Steps.push_back({
            MakeFragmentWire(2, "ef"), {Prism::Fault::Code::IoError}});
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Udp, std::move(Steps));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(Upstream);
        Tuic::Address Source{};
        std::vector<std::uint8_t> Payload;

        const auto PacketError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(PacketError, Prism::Error::None);
        EXPECT_EQ(Source.Port, 80);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'a', 'b', 'c', 'd', 'e', 'f'}));
        EXPECT_EQ(Upstream->ReadsDone, 3U);
        const auto TerminalError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(TerminalError, Prism::Error::IoError);
        EXPECT_EQ(Upstream->ReadsDone, 3U);
        EXPECT_TRUE(co_await CloseAndDrain(*Dgram));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

    auto VerifyMiddleFragmentTerminalStopsReceive(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        std::deque<ReadStep> Steps;
        Steps.push_back({MakeFragmentWire(0, "ab"), {}});
        Steps.push_back({
            MakeFragmentWire(1, "cd"), {Prism::Fault::Code::IoError}});
        Steps.push_back({MakeFragmentWire(2, "ef"), {}});
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Udp, std::move(Steps));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(Upstream);
        Tuic::Address Source{};
        Source.Port = 123;
        std::vector<std::uint8_t> Payload{'x'};

        const auto TerminalError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(TerminalError, Prism::Error::IoError);
        EXPECT_EQ(Source.Port, 123);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'x'}));
        EXPECT_EQ(Upstream->ReadsDone, 2U);
        EXPECT_TRUE(co_await CloseAndDrain(*Dgram));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
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
        auto AuthStream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Tcp, std::move(Steps));
        Tuic::Conn<> Connection({}, Uuid);
        Tuic::ServerAuthenticationMaterial Material{
            .Exporter = MakeAuthExporter(Token),
            .ExporterContext = "secret",
            .Credential = {}};

        const auto Result = co_await Connection.ReadAuthentication(
            AuthStream, std::move(Material));
        EXPECT_EQ(Result.Status, Scenario.Status);
        EXPECT_EQ(Result.EffectiveStatus(), Scenario.EffectiveStatus);
        EXPECT_TRUE(Result.Terminal.has_value());
        if (Result.Terminal)
        {
            EXPECT_EQ(Result.Terminal->Code, Scenario.Terminal.Code);
            EXPECT_EQ(Result.Terminal->Native, Scenario.Terminal.Native);
        }
        EXPECT_TRUE(co_await CloseAndDrain(*AuthStream));
    }

} // namespace

TEST(TuicTerminalRead, DatagramBytesPrecedeIoError)
{
    Net::io_context IoContext;
    RunCoroutine(IoContext, VerifyDatagramBeforeIoError(IoContext.get_executor()));
}

TEST(TuicTerminalRead, StreamFrameBytesPrecedeEof)
{
    Net::io_context IoContext;
    RunCoroutine(IoContext, VerifyStreamDatagramBeforeEof(IoContext.get_executor()));
}

TEST(TuicTerminalRead, CompleteStreamHeaderEofIsSticky)
{
    Net::io_context IoContext;
    RunCoroutine(
        IoContext,
        VerifyStreamHeaderTerminal(
            IoContext.get_executor(),
            {Prism::Fault::Code::Eof},
            Prism::Error::UnexpectedEof));
}

TEST(TuicTerminalRead, CompleteStreamHeaderResetIsSticky)
{
    Net::io_context IoContext;
    RunCoroutine(
        IoContext,
        VerifyStreamHeaderTerminal(
            IoContext.get_executor(),
            {Prism::Fault::Code::IoError,
             std::make_error_code(std::errc::connection_reset)},
            Prism::Error::IoError));
}

TEST(TuicTerminalRead, CompleteMalformedStreamHeaderPrecedesEof)
{
    Net::io_context IoContext;
    RunCoroutine(IoContext, VerifyMalformedStreamHeaderBeforeEof(IoContext.get_executor()));
}

TEST(TuicTerminalRead, PartialStreamPayloadResetIsSticky)
{
    Net::io_context IoContext;
    RunCoroutine(IoContext, VerifyStreamPartialPayloadReset(IoContext.get_executor()));
}

TEST(TuicTerminalRead, ConnFrameBytesPrecedeEof)
{
    Net::io_context IoContext;
    RunCoroutine(IoContext, VerifyConnFrameBeforeEof(IoContext.get_executor()));
}

TEST(TuicTerminalRead, ConnPendingTerminalIsConsumedOnce)
{
    Net::io_context IoContext;
    RunCoroutine(IoContext, VerifyConnTerminalConsumedOnce(IoContext.get_executor()));
}

TEST(TuicTerminalRead, ConnFieldCancelIsStickyAcrossPublicRetry)
{
    Net::io_context IoContext;
    RunCoroutine(IoContext, VerifyConnFieldCancelIsSticky(IoContext.get_executor()));
}

TEST(TuicTerminalRead, ConnHandshakeTerminalIsStickyForRawReads)
{
    Net::io_context IoContext;
    RunCoroutine(
        IoContext,
        VerifyConnCompleteHandshakeTerminalIsSticky(IoContext.get_executor()));
}

TEST(TuicTerminalRead, LastFragmentBytesPrecedeTerminal)
{
    Net::io_context IoContext;
    RunCoroutine(
        IoContext,
        VerifyLastFragmentTerminalFollowsPacket(IoContext.get_executor()));
}

TEST(TuicTerminalRead, MiddleFragmentTerminalStopsReceive)
{
    Net::io_context IoContext;
    RunCoroutine(
        IoContext,
        VerifyMiddleFragmentTerminalStopsReceive(IoContext.get_executor()));
}

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
