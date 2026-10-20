/**
 * @file GunConnTerminalReadTest.cpp
 * @brief Gun CONNECT 握手同读终态的交付顺序测试。
 */

#include <gtest/gtest.h>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Gun/Conn.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace
{
    namespace Net = boost::asio;
    namespace Gun = Prism::Gun;

    class OneShotConnectTransmission final : public Prism::Transmission
    {
    public:
        OneShotConnectTransmission(
            ExecutorType Executor,
            std::vector<std::byte> Input,
            Prism::Fault::Failure Terminal)
            : Transmission(Executor), Ex_(std::move(Executor)), Input_(std::move(Input)),
              Terminal_(Terminal)
        {
        }

        [[nodiscard]] auto ReadCount() const noexcept -> std::size_t
        {
            return ReadCount_;
        }

        [[nodiscard]] auto WasClosed() const noexcept -> bool
        {
            return WasClosed_;
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadCount_;
            if (Offset_ == Input_.size())
            {
                Prism::Transmission::PostResult(
                    Executor(), std::move(Handler),
                    {0, {Prism::Fault::Code::WouldBlock}});
                return;
            }
            const auto Count = (std::min)(Buffer.size(), Input_.size() - Offset_);
            std::copy_n(Input_.begin() + static_cast<std::ptrdiff_t>(Offset_), Count, Buffer.begin());
            Offset_ += Count;
            const auto Failure = Offset_ == Input_.size() ? Terminal_ : Prism::Fault::Failure{};
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Count, Failure});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            WasClosed_ = true;
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        ExecutorType Ex_;
        std::vector<std::byte> Input_;
        Prism::Fault::Failure Terminal_;
        std::size_t Offset_{0};
        std::size_t ReadCount_{0};
        bool WasClosed_{false};
    };

    struct ConnectReadOutcome final
    {
        bool HandshakeSucceeded{false};
        Prism::Fault::Failure HandshakeFailure{};
        std::string Host;
        std::string Tail;
        Prism::Fault::Failure TailFailure{};
        Prism::IoResult Terminal{};
        Prism::IoResult Sticky{};
        std::size_t ReadCount{0};
        bool CloseSucceeded{false};
        bool DrainSucceeded{false};
    };

    struct ConnectReadInput final
    {
        std::string_view Wire;
        Prism::Fault::Failure Terminal;
    };

    struct ConnectReadRequest final
    {
        std::shared_ptr<OneShotConnectTransmission> Transport;
        ConnectReadOutcome *Outcome;
    };

    /** @brief 由 Gun Conn 关闭底层 Raw，再依次排空 Conn 与 Raw 的独立 activity owner。 */
    auto CloseAndDrain(
        const std::shared_ptr<Gun::Conn<>> &Connection,
        const std::shared_ptr<OneShotConnectTransmission> &Raw,
        ConnectReadOutcome &Outcome) -> Net::awaitable<void>
    {
        const auto Closed = Connection->Close();
        Outcome.CloseSucceeded = static_cast<bool>(Closed);

        const auto ConnectionActivity = Connection->Activity();
        if (!ConnectionActivity)
        {
            ADD_FAILURE() << "Gun Conn activity is unavailable during close drain";
            co_return;
        }
        const auto ConnectionDrained = co_await ConnectionActivity->Drain();
        Outcome.DrainSucceeded = static_cast<bool>(ConnectionDrained);

        const auto RawActivity = Raw->Activity();
        if (!RawActivity)
        {
            ADD_FAILURE() << "Gun Raw activity is unavailable after Conn drain";
            co_return;
        }
        const auto RawDrained = co_await RawActivity->Drain();
        EXPECT_TRUE(Raw->WasClosed());
        EXPECT_TRUE(RawDrained.has_value());
        EXPECT_TRUE(RawActivity->IsRetired());
    }

    [[nodiscard]] auto ToWire(std::string_view Input) -> std::vector<std::byte>
    {
        std::vector<std::byte> Wire;
        Wire.reserve(Input.size());
        for (const auto Character : Input)
        {
            Wire.push_back(static_cast<std::byte>(Character));
        }
        return Wire;
    }

    auto RunConnectRead(ConnectReadRequest Request) -> Net::awaitable<void>
    {
        Gun::Config Configuration{.Path = "/GunService/Tun", .ServiceName = "gun"};
        auto Connection = std::make_shared<Gun::Conn<>>(Request.Transport, Configuration);
        auto Handshake = co_await Connection->ReadHandshake(Request.Outcome->Host);
        Request.Outcome->HandshakeSucceeded = static_cast<bool>(Handshake);
        if (!Handshake)
        {
            Request.Outcome->HandshakeFailure = Handshake.error();
        }

        std::array<std::byte, 128> Buffer{};
        if (Handshake)
        {
            const auto Tail = co_await Connection->ReadSome(Buffer);
            Request.Outcome->TailFailure = Tail.Failure;
            if (Tail.Bytes <= Buffer.size())
            {
                Request.Outcome->Tail.assign(
                    reinterpret_cast<const char *>(Buffer.data()), Tail.Bytes);
            }
        }
        Request.Outcome->Terminal = co_await Connection->ReadSome(Buffer);
        Request.Outcome->Sticky = co_await Connection->ReadSome(Buffer);
        Request.Outcome->ReadCount = Request.Transport->ReadCount();
        co_await CloseAndDrain(Connection, Request.Transport, *Request.Outcome);
    }

    auto RunConnectReadScenario(Net::io_context &IoContext, ConnectReadRequest Request) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(
            IoContext, RunConnectRead(std::move(Request)),
            [&Exception](std::exception_ptr Error) { Exception = std::move(Error); });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    [[nodiscard]] auto CompleteConnectWire(std::string_view Tail) -> std::string
    {
        return "CONNECT example.com:443 HTTP/2\r\n"
               ":path: /GunService/Tun\r\n"
               ":service: gun\r\n\r\n" + std::string(Tail);
    }

    [[nodiscard]] auto MakeRequest(
        Net::io_context &IoContext,
        ConnectReadInput Input,
        ConnectReadOutcome &Outcome) -> ConnectReadRequest
    {
        return {
            std::make_shared<OneShotConnectTransmission>(
                IoContext.get_executor(), ToWire(Input.Wire), Input.Terminal),
            &Outcome};
    }
}

TEST(GunConnTerminalRead, CompleteConnectTailPrecedesEof)
{
    Net::io_context IoContext;
    ConnectReadOutcome Outcome;
    constexpr std::string_view Tail{"connect-body-tail"};
    const auto Wire = CompleteConnectWire(Tail);
    RunConnectReadScenario(IoContext, MakeRequest(
        IoContext, {Wire, {Prism::Fault::Code::Eof}}, Outcome));

    EXPECT_TRUE(Outcome.HandshakeSucceeded);
    EXPECT_EQ(Outcome.Host, "example.com:443");
    EXPECT_EQ(Outcome.Tail, Tail);
    EXPECT_TRUE(Outcome.TailFailure.Succeeded());
    EXPECT_EQ(Outcome.Terminal.Bytes, 0U);
    EXPECT_EQ(Outcome.Terminal.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(Outcome.Sticky.Bytes, 0U);
    EXPECT_EQ(Outcome.Sticky.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(Outcome.ReadCount, 1U);
    EXPECT_TRUE(Outcome.CloseSucceeded);
    EXPECT_TRUE(Outcome.DrainSucceeded);
}

TEST(GunConnTerminalRead, CompleteConnectTailPrecedesNativeReset)
{
    Net::io_context IoContext;
    ConnectReadOutcome Outcome;
    constexpr std::string_view Tail{"connect-body-tail"};
    const auto Wire = CompleteConnectWire(Tail);
    const auto Native = std::make_error_code(std::errc::connection_reset);
    RunConnectReadScenario(IoContext, MakeRequest(
        IoContext, {Wire, {Prism::Fault::Code::IoError, Native}}, Outcome));

    EXPECT_TRUE(Outcome.HandshakeSucceeded);
    EXPECT_EQ(Outcome.Host, "example.com:443");
    EXPECT_EQ(Outcome.Tail, Tail);
    EXPECT_TRUE(Outcome.TailFailure.Succeeded());
    EXPECT_EQ(Outcome.Terminal.Bytes, 0U);
    EXPECT_EQ(Outcome.Terminal.Failure.Code, Prism::Fault::Code::IoError);
    EXPECT_EQ(Outcome.Terminal.Failure.Native, Native);
    EXPECT_EQ(Outcome.Sticky.Bytes, 0U);
    EXPECT_EQ(Outcome.Sticky.Failure.Code, Prism::Fault::Code::IoError);
    EXPECT_EQ(Outcome.Sticky.Failure.Native, Native);
    EXPECT_EQ(Outcome.ReadCount, 1U);
    EXPECT_TRUE(Outcome.CloseSucceeded);
    EXPECT_TRUE(Outcome.DrainSucceeded);
}

TEST(GunConnTerminalRead, PartialConnectPreservesEofWithoutReread)
{
    Net::io_context IoContext;
    ConnectReadOutcome Outcome;
    constexpr std::string_view Wire{"CONNECT example.com:443 HTTP/2\r\n"};
    RunConnectReadScenario(IoContext, MakeRequest(
        IoContext, {Wire, {Prism::Fault::Code::Eof}}, Outcome));

    EXPECT_FALSE(Outcome.HandshakeSucceeded);
    EXPECT_EQ(Outcome.HandshakeFailure.Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(Outcome.Terminal.Bytes, 0U);
    EXPECT_EQ(Outcome.Terminal.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(Outcome.Sticky.Bytes, 0U);
    EXPECT_EQ(Outcome.Sticky.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(Outcome.ReadCount, 1U);
    EXPECT_TRUE(Outcome.CloseSucceeded);
    EXPECT_TRUE(Outcome.DrainSucceeded);
}

TEST(GunConnTerminalRead, PartialConnectPreservesNativeResetWithoutReread)
{
    Net::io_context IoContext;
    ConnectReadOutcome Outcome;
    constexpr std::string_view Wire{"CONNECT example.com:443 HTTP/2\r\n"};
    const auto Native = std::make_error_code(std::errc::connection_reset);
    RunConnectReadScenario(IoContext, MakeRequest(
        IoContext, {Wire, {Prism::Fault::Code::IoError, Native}}, Outcome));

    EXPECT_FALSE(Outcome.HandshakeSucceeded);
    EXPECT_EQ(Outcome.HandshakeFailure.Code, Prism::Fault::Code::IoError);
    EXPECT_EQ(Outcome.HandshakeFailure.Native, Native);
    EXPECT_EQ(Outcome.Terminal.Bytes, 0U);
    EXPECT_EQ(Outcome.Terminal.Failure.Code, Prism::Fault::Code::IoError);
    EXPECT_EQ(Outcome.Terminal.Failure.Native, Native);
    EXPECT_EQ(Outcome.Sticky.Bytes, 0U);
    EXPECT_EQ(Outcome.Sticky.Failure.Code, Prism::Fault::Code::IoError);
    EXPECT_EQ(Outcome.Sticky.Failure.Native, Native);
    EXPECT_EQ(Outcome.ReadCount, 1U);
    EXPECT_TRUE(Outcome.CloseSucceeded);
    EXPECT_TRUE(Outcome.DrainSucceeded);
}
