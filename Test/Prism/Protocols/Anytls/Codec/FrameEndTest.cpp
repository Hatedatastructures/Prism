/**
 * @file FrameEndTest.cpp
 * @brief AnyTLS 完整帧与同次读取终态的交付顺序回归。
 */
#include <gtest/gtest.h>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/this_coro.hpp>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <exception>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Protocols/Anytls/Frame.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    using FrameReader = Prism::Anytls::FrameReader;

    class ScriptedTransmission final : public Prism::Transmission
    {
    public:
        struct ReadStep final
        {
            std::vector<std::byte> Bytes;
            Fault::Failure Failure;
        };

        explicit ScriptedTransmission(Net::any_io_executor Executor)
            : Prism::Transmission(std::move(Executor))
        {
        }

        auto QueueRead(ReadStep Step) -> void
        {
            Steps_.push_back(std::move(Step));
        }

        [[nodiscard]] auto ReadsDone() const noexcept -> std::size_t
        {
            return ReadsDone_;
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadsDone_;
            if (Steps_.empty())
            {
                Prism::Transmission::PostResult(
                    Executor(), std::move(Handler), {0, {Fault::Code::Eof}});
                return;
            }
            auto Step = std::move(Steps_.front());
            Steps_.erase(Steps_.begin());
            const auto Count = (std::min)(Buffer.size(), Step.Bytes.size());
            if (Count != 0U)
            {
                std::memcpy(Buffer.data(), Step.Bytes.data(), Count);
            }
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Count, std::move(Step.Failure)});
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
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        std::vector<ReadStep> Steps_;
        std::size_t ReadsDone_{0};
    };

    [[nodiscard]] auto ResetFailure() -> Fault::Failure
    {
        return {Fault::Code::ConnectionReset,
                std::make_error_code(std::errc::connection_reset)};
    }

    [[nodiscard]] auto EofFailure() -> Fault::Failure
    {
        return {Fault::Code::Eof};
    }

    [[nodiscard]] auto TestFrame() -> Prism::Anytls::Frame
    {
        return {Prism::Anytls::Command::Push, 19,
                {std::byte{0x31}, std::byte{0x32}, std::byte{0x33}}};
    }

    auto QueueHeader(const std::shared_ptr<ScriptedTransmission> &Raw,
                     const std::vector<std::byte> &Wire,
                     Fault::Failure Failure = {}) -> void
    {
        Raw->QueueRead({std::vector<std::byte>(Wire.begin(), Wire.begin() + 7),
                        std::move(Failure)});
    }

    auto QueuePayload(const std::shared_ptr<ScriptedTransmission> &Raw,
                      const std::vector<std::byte> &Wire,
                      Fault::Failure Failure = {}) -> void
    {
        Raw->QueueRead({std::vector<std::byte>(Wire.begin() + 7, Wire.end()),
                        std::move(Failure)});
    }

    struct TerminalObservation final
    {
        FrameReader &Reader;
        const ScriptedTransmission &Raw;
        Fault::Failure ExpectedFailure;
        std::size_t ExpectedReads;
    };

    auto VerifyReset(TerminalObservation Observation) -> Net::awaitable<void>
    {
        for (int Attempt = 0; Attempt != 2; ++Attempt)
        {
            bool Caught = false;
            try
            {
                (void)co_await Observation.Reader.Read();
            }
            catch (const std::system_error &Error)
            {
                Caught = true;
                EXPECT_EQ(Error.code(), Observation.ExpectedFailure.Native);
            }
            EXPECT_TRUE(Caught);
            EXPECT_EQ(Observation.Raw.ReadsDone(), Observation.ExpectedReads);
        }
    }

    auto VerifyEof(TerminalObservation Observation) -> Net::awaitable<void>
    {
        for (int Attempt = 0; Attempt != 2; ++Attempt)
        {
            const auto Result = co_await Observation.Reader.Read();
            EXPECT_FALSE(Result);
            if (!Result)
            {
                EXPECT_EQ(Result.error(), Prism::Error::UnexpectedEof);
            }
            EXPECT_EQ(Observation.Raw.ReadsDone(), Observation.ExpectedReads);
        }
    }

    auto VerifyPartialEof(TerminalObservation Observation) -> Net::awaitable<void>
    {
        const Fault::Failure Expected{Fault::Code::ProtocolError};
        for (int Attempt = 0; Attempt != 2; ++Attempt)
        {
            bool Caught = false;
            try
            {
                (void)co_await Observation.Reader.Read();
            }
            catch (const std::system_error &Error)
            {
                Caught = true;
                EXPECT_EQ(Error.code(), Fault::ToNative(Expected));
            }
            EXPECT_TRUE(Caught);
            EXPECT_EQ(Observation.Raw.ReadsDone(), Observation.ExpectedReads);
        }
    }

    auto CloseAndDrain(Prism::Transmission &Carrier) -> Net::awaitable<bool>
    {
        const auto Closed = Carrier.Close();
        const auto Activity = Carrier.Activity();
        if (!Closed || !Activity)
        {
            co_return false;
        }
        const auto Drained = co_await Activity->Drain();
        co_return Drained.has_value();
    }

    auto RunCompleteFrameTerminal(Fault::Failure Terminal) -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<ScriptedTransmission>(co_await Net::this_coro::executor);
        const auto Wire = Prism::Anytls::Encode(TestFrame());
        QueueHeader(Raw, Wire);
        QueuePayload(Raw, Wire, Terminal);
        FrameReader Reader(Raw);
        const auto Result = co_await Reader.Read();
        EXPECT_TRUE(Result);
        if (Result)
        {
            EXPECT_EQ(Result->Kind, Prism::Anytls::Command::Push);
            EXPECT_EQ(Result->StreamId, 19U);
            EXPECT_EQ(Result->Payload, TestFrame().Payload);
        }
        EXPECT_EQ(Raw->ReadsDone(), 2U);
        if (Terminal.Code == Fault::Code::Eof)
        {
            co_await VerifyEof({Reader, *Raw, Terminal, 2U});
        }
        else
        {
            co_await VerifyReset({Reader, *Raw, Terminal, 2U});
        }
        EXPECT_TRUE(co_await CloseAndDrain(*Raw));
    }

    auto RunCompleteHeaderTerminal(Fault::Failure Terminal) -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<ScriptedTransmission>(co_await Net::this_coro::executor);
        const auto Wire = Prism::Anytls::Encode(TestFrame());
        QueueHeader(Raw, Wire, Terminal);
        FrameReader Reader(Raw);
        if (Terminal.Code == Fault::Code::Eof)
        {
            co_await VerifyEof({Reader, *Raw, Terminal, 1U});
        }
        else
        {
            co_await VerifyReset({Reader, *Raw, Terminal, 1U});
        }
        EXPECT_TRUE(co_await CloseAndDrain(*Raw));
    }

    auto RunZeroPayloadFrameTerminal() -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<ScriptedTransmission>(co_await Net::this_coro::executor);
        const Prism::Anytls::Frame ExpectedFrame{
            Prism::Anytls::Command::Push, 19, {}};
        const auto Wire = Prism::Anytls::Encode(ExpectedFrame);
        QueueHeader(Raw, Wire, EofFailure());
        FrameReader Reader(Raw);
        const auto Result = co_await Reader.Read();
        EXPECT_TRUE(Result);
        if (Result)
        {
            EXPECT_EQ(Result->Kind, ExpectedFrame.Kind);
            EXPECT_EQ(Result->StreamId, ExpectedFrame.StreamId);
            EXPECT_TRUE(Result->Payload.empty());
        }
        EXPECT_EQ(Raw->ReadsDone(), 1U);

        co_await VerifyEof({Reader, *Raw, EofFailure(), 1U});
        EXPECT_TRUE(co_await CloseAndDrain(*Raw));
    }

    auto RunPartialPayloadTerminal(Fault::Failure Terminal) -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<ScriptedTransmission>(co_await Net::this_coro::executor);
        const auto Wire = Prism::Anytls::Encode(TestFrame());
        QueueHeader(Raw, Wire);
        Raw->QueueRead({{Wire[7]}, Terminal});
        FrameReader Reader(Raw);
        if (Terminal.Code == Fault::Code::Eof)
        {
            co_await VerifyPartialEof({Reader, *Raw, Terminal, 2U});
        }
        else
        {
            co_await VerifyReset({Reader, *Raw, Terminal, 2U});
        }
        EXPECT_TRUE(co_await CloseAndDrain(*Raw));
    }

    auto RunCleanBoundaryEof() -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<ScriptedTransmission>(co_await Net::this_coro::executor);
        Raw->QueueRead({{}, EofFailure()});
        FrameReader Reader(Raw);
        co_await VerifyEof({Reader, *Raw, EofFailure(), 1U});
        EXPECT_TRUE(co_await CloseAndDrain(*Raw));
    }

    auto RunCoroutine(Net::awaitable<void> Operation) -> void
    {
        Net::io_context Io;
        std::exception_ptr Failure;
        Net::co_spawn(Io, std::move(Operation),
            [&Failure](std::exception_ptr Error) { Failure = std::move(Error); });
        Io.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    TEST(AnytlsFrameReaderTerminal, CompleteFramePrecedesReset)
    {
        RunCoroutine(RunCompleteFrameTerminal(ResetFailure()));
    }

    TEST(AnytlsFrameReaderTerminal, CompleteFramePrecedesEof)
    {
        RunCoroutine(RunCompleteFrameTerminal(EofFailure()));
    }

    TEST(AnytlsFrameReaderTerminal, CompleteHeaderResetCannotCompletePayload)
    {
        RunCoroutine(RunCompleteHeaderTerminal(ResetFailure()));
    }

    TEST(AnytlsFrameReaderTerminal, CompleteHeaderEofCannotCompletePayload)
    {
        RunCoroutine(RunCompleteHeaderTerminal(EofFailure()));
    }

    TEST(AnytlsFrameReaderTerminal, ZeroPayloadFramePrecedesEof)
    {
        RunCoroutine(RunZeroPayloadFrameTerminal());
    }

    TEST(AnytlsFrameReaderTerminal, PartialPayloadResetIsSticky)
    {
        RunCoroutine(RunPartialPayloadTerminal(ResetFailure()));
    }

    TEST(AnytlsFrameReaderTerminal, PartialPayloadEofIsSticky)
    {
        RunCoroutine(RunPartialPayloadTerminal(EofFailure()));
    }

    TEST(AnytlsFrameReaderTerminal, CleanBoundaryEofIsStable)
    {
        RunCoroutine(RunCleanBoundaryEof());
    }
} // namespace
