/**
 * @file GunStreamEndTest.cpp
 * @brief gRPC stream 在同读 payload 与底层终态时保留消息和方向状态。
 */

#include <gtest/gtest.h>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Gun/Grpc.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Http2/Types.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace
{
    namespace H2 = Prism::Http2;
    namespace Grpc = Prism::Gun::Grpc;
    namespace Net = boost::asio;

    struct ScriptedGrpcInput final
    {
        std::vector<std::byte> Wire;
        Prism::Fault::Failure Terminal;
        bool FailResponseHeaders{false};
        bool HoldOpenAfterInput{false};
    };

    class ScriptedGrpcTransmission final : public Prism::Transmission
    {
    public:
        ScriptedGrpcTransmission(
            ExecutorType Executor,
            ScriptedGrpcInput Input)
            : Transmission(std::move(Executor)), Input_(std::move(Input.Wire)),
              Terminal_(Input.Terminal), FailResponseHeaders_(Input.FailResponseHeaders),
              HoldOpenAfterInput_(Input.HoldOpenAfterInput), WriteNotify_(this->Executor(), 16)
        {
        }

        [[nodiscard]] auto ReadCount() const noexcept -> std::size_t
        {
            return ReadCount_;
        }

        [[nodiscard]] auto CloseCount() const noexcept -> std::size_t
        {
            return CloseCount_;
        }

        [[nodiscard]] auto WriteFailureCount() const noexcept -> std::size_t
        {
            return WriteFailureCount_;
        }

        [[nodiscard]] auto Written() const noexcept -> const std::vector<std::byte> &
        {
            return Written_;
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_;
        }

        [[nodiscard]] auto WaitForWire(std::span<const std::byte> Expected)
            -> Net::awaitable<bool>
        {
            while (std::search(Written_.begin(), Written_.end(),
                               Expected.begin(), Expected.end()) == Written_.end())
            {
                boost::system::error_code Error;
                co_await WriteNotify_.async_receive(
                    Net::redirect_error(Net::use_awaitable, Error));
                if (Error)
                {
                    co_return false;
                }
            }
            co_return true;
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadCount_;
            if (ReadDelivered_ && HoldOpenAfterInput_)
            {
                PendingRead_.emplace(std::move(Handler));
                return;
            }
            const auto Count = ReadDelivered_
                ? 0U
                : (std::min)(Buffer.size(), Input_.size());
            if (!ReadDelivered_)
            {
                std::copy_n(Input_.begin(), Count, Buffer.begin());
                ReadDelivered_ = true;
            }
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Count, Terminal_});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            if (FailResponseHeaders_ && ContainsFrameType(Buffer, 1U))
            {
                ++WriteFailureCount_;
                Prism::Transmission::PostResult(
                    Executor(), std::move(Handler),
                    {0, Prism::Fault::FromNative(
                        std::make_error_code(std::errc::broken_pipe))});
                return;
            }
            Written_.insert(Written_.end(), Buffer.begin(), Buffer.end());
            (void)WriteNotify_.try_send(boost::system::error_code{});
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed_ = true;
            ++CloseCount_;
            CompletePendingRead({Prism::Fault::Code::Canceled});
            WriteNotify_.close();
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        auto CompletePendingRead(const Prism::Fault::Failure Failure) -> void
        {
            if (!PendingRead_)
            {
                return;
            }
            auto Handler = std::move(*PendingRead_);
            PendingRead_.reset();
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {0, Failure});
        }

        [[nodiscard]] static auto ContainsFrameType(
            std::span<const std::byte> Wire,
            const std::uint8_t Type) noexcept -> bool
        {
            std::size_t Offset = 0;
            while (Wire.size() - Offset >= 9U)
            {
                const auto Length =
                    (static_cast<std::size_t>(std::to_integer<std::uint8_t>(Wire[Offset])) << 16U) |
                    (static_cast<std::size_t>(std::to_integer<std::uint8_t>(Wire[Offset + 1U])) << 8U) |
                    static_cast<std::size_t>(std::to_integer<std::uint8_t>(Wire[Offset + 2U]));
                if (Length > Wire.size() - Offset - 9U)
                {
                    return false;
                }
                if (std::to_integer<std::uint8_t>(Wire[Offset + 3U]) == Type)
                {
                    return true;
                }
                Offset += 9U + Length;
            }
            return false;
        }

        std::vector<std::byte> Input_;
        std::vector<std::byte> Written_;
        Prism::Fault::Failure Terminal_;
        bool FailResponseHeaders_{false};
        bool HoldOpenAfterInput_{false};
        Net::experimental::channel<void(boost::system::error_code)> WriteNotify_;
        std::optional<Completion> PendingRead_;
        bool ReadDelivered_{false};
        bool Closed_{false};
        std::size_t ReadCount_{0};
        std::size_t CloseCount_{0};
        std::size_t WriteFailureCount_{0};
    };

    struct ScenarioResult final
    {
        bool Accepted{false};
        Prism::Fault::Failure AcceptFailure{};
        std::string Payload;
        Prism::IoResult FirstTerminal{};
        Prism::IoResult SecondTerminal{};
        bool ActivityRetired{false};
        Prism::IoResult ResponseWrite{};
        bool WriteShutdownAccepted{false};
        bool ResponseOnWire{false};
        bool LowerOpenBeforeClose{false};
        bool CloseAccepted{false};
        bool DrainSucceeded{false};
        Prism::Fault::Failure DrainFailure{};
        bool PublicReadStarted{false};
        Prism::IoResult CanceledRead{};
        bool CancelAccepted{false};
        bool CanceledReadBeforeClose{false};
    };

    struct ScenarioInput final
    {
        std::shared_ptr<ScriptedGrpcTransmission> Lower;
        std::string_view Payload;
        bool WriteResponse{false};
    };

    [[nodiscard]] auto MakeRequestWire(
        Net::io_context &Io,
        std::string_view Payload) -> std::vector<std::byte>
    {
        H2::Session Client(Io.get_executor(), false);
        Client.SendSettings();
        const auto Stream = Client.OpenStream(
            Grpc::MakeRequestHeaders("/GunService/Tun", "gun"), false);
        if (!Stream)
        {
            return {};
        }
        const auto Input = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        const auto Message = Grpc::EncodeMessage(Input);
        if (Client.SubmitData(
                *Stream, std::span<const std::byte>(Message), true) !=
            H2::SubmitDataStatus::Accepted)
        {
            return {};
        }
        std::vector<std::byte> Wire;
        if (!Client.Collect(Wire))
        {
            return {};
        }
        return Wire;
    }

    [[nodiscard]] auto MakeOpenRequestWire(Net::io_context &Io) -> std::vector<std::byte>
    {
        H2::Session Client(Io.get_executor(), false);
        Client.SendSettings();
        if (!Client.OpenStream(
                Grpc::MakeRequestHeaders("/GunService/Tun", "gun"), false))
        {
            return {};
        }
        std::vector<std::byte> Wire;
        if (!Client.Collect(Wire))
        {
            return {};
        }
        return Wire;
    }

    [[nodiscard]] auto RunScenario(
        const std::shared_ptr<ScriptedGrpcTransmission> &Lower,
        std::string_view Payload,
        const bool WriteResponse) -> Net::awaitable<ScenarioResult>
    {
        ScenarioResult Result;
        auto Accepted = co_await Grpc::StreamTransport::Accept(Lower, Grpc::Config{});
        if (!Accepted)
        {
            Result.AcceptFailure = Accepted.error();
            co_return Result;
        }
        Result.Accepted = true;
        auto Stream = std::move(*Accepted);
        std::array<std::byte, 3> Buffer{};
        while (Result.Payload.size() < Payload.size())
        {
            const auto Part = co_await Stream->ReadSome(Buffer);
            if (Part.Failure.Failed() || Part.Bytes == 0U || Part.Bytes > Buffer.size())
            {
                break;
            }
            Result.Payload.append(
                reinterpret_cast<const char *>(Buffer.data()), Part.Bytes);
        }
        std::array<std::byte, 1> TerminalBuffer{};
        Result.FirstTerminal = co_await Stream->ReadSome(TerminalBuffer);
        Result.SecondTerminal = co_await Stream->ReadSome(TerminalBuffer);
        if (WriteResponse)
        {
            constexpr std::string_view Response{"gun-response-after-eof"};
            const auto ResponseBytes = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Response.data()), Response.size());
            Result.ResponseWrite = co_await Stream->WriteSome(ResponseBytes);
            Result.WriteShutdownAccepted = static_cast<bool>(co_await Stream->WriteShutdown());
            const auto WireMessage = Grpc::EncodeMessage(ResponseBytes);
            Result.ResponseOnWire = co_await Lower->WaitForWire(
                std::span<const std::byte>(WireMessage));
        }
        Result.LowerOpenBeforeClose = Lower->IsOpen();
        Result.CloseAccepted = static_cast<bool>(Stream->Close());
        const auto Drained = co_await Stream->Activity()->Drain();
        Result.DrainSucceeded = static_cast<bool>(Drained);
        if (!Drained)
        {
            Result.DrainFailure = Drained.error();
        }
        Result.ActivityRetired = Stream->Activity()->IsRetired();
        co_return Result;
    }

    using ReadCompletionChannel = Net::experimental::channel<
        void(boost::system::error_code, Prism::IoResult)>;
    using ReadStartedChannel = Net::experimental::channel<
        void(boost::system::error_code, bool)>;
    using ReadFinishedChannel = Net::experimental::channel<void(boost::system::error_code)>;

    struct ReadProbeChannels final
    {
        std::shared_ptr<ReadCompletionChannel> Completion;
        std::shared_ptr<ReadStartedChannel> Started;
    };

    [[nodiscard]] auto ReadStreamAndPublishCompletion(
        Prism::SharedTransmission Stream,
        std::array<std::byte, 8> Buffer,
        ReadProbeChannels Channels)
        -> Net::awaitable<void>
    {
        auto ReadFinished = std::make_shared<ReadFinishedChannel>(Stream->Executor(), 1);
        Stream->ReadSome(Buffer,
            [Completion = Channels.Completion, ReadFinished](const Prism::IoResult Part)
            {
                (void)Completion->try_send(boost::system::error_code{}, Part);
                (void)ReadFinished->try_send(boost::system::error_code{});
            });

        // fence 排在同 executor 的 ReadSome 受理之后；随后的 Cancel/完成断言验证该读仍在途。
        co_await Net::post(Stream->Executor(), Net::use_awaitable);
        (void)Channels.Started->try_send(boost::system::error_code{}, true);

        boost::system::error_code Error;
        co_await ReadFinished->async_receive(Net::redirect_error(Net::use_awaitable, Error));
    }

    [[nodiscard]] auto RunCancelScenario(
        const std::shared_ptr<ScriptedGrpcTransmission> &Lower) -> Net::awaitable<ScenarioResult>
    {
        ScenarioResult Result;
        auto Accepted = co_await Grpc::StreamTransport::Accept(Lower, Grpc::Config{});
        if (!Accepted)
        {
            Result.AcceptFailure = Accepted.error();
            co_return Result;
        }
        Result.Accepted = true;
        auto Stream = std::move(*Accepted);
        std::array<std::byte, 8> Buffer{};
        const auto Executor = Stream->Executor();
        auto ReadCompletion = std::make_shared<ReadCompletionChannel>(Executor, 1);
        auto ReadStarted = std::make_shared<ReadStartedChannel>(Executor, 1);
        Net::co_spawn(Executor,
            ReadStreamAndPublishCompletion(
                Stream, Buffer, ReadProbeChannels{ReadCompletion, ReadStarted}),
            Net::detached);
        boost::system::error_code StartError;
        Result.PublicReadStarted = co_await ReadStarted->async_receive(
            Net::redirect_error(Net::use_awaitable, StartError));
        Result.PublicReadStarted = Result.PublicReadStarted && !StartError;
        if (!Result.PublicReadStarted)
        {
            Result.AcceptFailure = {Prism::Fault::Code::IoError};
            Result.CloseAccepted = static_cast<bool>(Stream->Close());
            const auto Drained = co_await Stream->Activity()->Drain();
            Result.DrainSucceeded = static_cast<bool>(Drained);
            if (!Drained) Result.DrainFailure = Drained.error();
            co_return Result;
        }
        Result.CancelAccepted = static_cast<bool>(Stream->Cancel());
        boost::system::error_code ReadError;
        Result.CanceledRead = co_await ReadCompletion->async_receive(
            Net::redirect_error(Net::use_awaitable, ReadError));
        Result.CanceledReadBeforeClose = !ReadError &&
            Result.CanceledRead.Failure.Code == Prism::Fault::Code::Canceled;
        Result.CloseAccepted = static_cast<bool>(Stream->Close());
        const auto Drained = co_await Stream->Activity()->Drain();
        Result.DrainSucceeded = static_cast<bool>(Drained);
        if (!Drained)
        {
            Result.DrainFailure = Drained.error();
        }
        co_return Result;
    }

    [[nodiscard]] auto RunScenarioInContext(
        Net::io_context &Io,
        ScenarioInput Input) -> ScenarioResult
    {
        std::optional<ScenarioResult> Result;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunScenario(Input.Lower, Input.Payload, Input.WriteResponse),
            [&Result, &Exception](std::exception_ptr Error, ScenarioResult Value)
            {
                Exception = std::move(Error);
                if (!Exception) Result.emplace(std::move(Value));
            });
        Io.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
        return Result ? std::move(*Result) : ScenarioResult{};
    }

    auto RunIoContext(Net::io_context &Io, std::exception_ptr &Exception) -> void
    {
        try
        {
            Io.run();
        }
        catch (...)
        {
            Exception = std::current_exception();
        }
    }

    [[nodiscard]] auto RunCancelScenarioInContext(
        Net::io_context &Io,
        const std::shared_ptr<ScriptedGrpcTransmission> &Lower) -> ScenarioResult
    {
        std::optional<ScenarioResult> Result;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunCancelScenario(Lower),
            [&Result, &Exception](std::exception_ptr Error, ScenarioResult Value)
            {
                Exception = std::move(Error);
                if (!Exception) Result.emplace(std::move(Value));
            });
        std::exception_ptr WorkerException;
        std::thread Worker([&Io, &WorkerException]
        { RunIoContext(Io, WorkerException); });
        std::exception_ptr CallerException;
        RunIoContext(Io, CallerException);
        Worker.join();
        if (CallerException)
        {
            std::rethrow_exception(CallerException);
        }
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
        if (WorkerException)
        {
            std::rethrow_exception(WorkerException);
        }
        return Result ? std::move(*Result) : ScenarioResult{};
    }
}

TEST(GunStreamTransportTerminal, CompleteMessagePrecedesEofAndWriteHalfCloseRemainsUsable)
{
    constexpr std::string_view Payload{"request-message-after-peer-half-close"};
    Net::io_context Io;
    auto Wire = MakeRequestWire(Io, Payload);
    ASSERT_FALSE(Wire.empty());
    auto Lower = std::make_shared<ScriptedGrpcTransmission>(
        Io.get_executor(), ScriptedGrpcInput{
            std::move(Wire), {Prism::Fault::Code::Eof}, false});

    const auto Result = RunScenarioInContext(Io, ScenarioInput{Lower, Payload, true});

    ASSERT_TRUE(Result.Accepted) << static_cast<int>(Result.AcceptFailure.Code);
    EXPECT_EQ(Result.Payload, Payload);
    EXPECT_EQ(Result.FirstTerminal.Bytes, 0U);
    EXPECT_EQ(Result.FirstTerminal.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_TRUE(Result.FirstTerminal.Failure.Native);
    EXPECT_EQ(Result.SecondTerminal.Bytes, 0U);
    EXPECT_EQ(Result.SecondTerminal.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_TRUE(Result.SecondTerminal.Failure.Native);
    EXPECT_EQ(Result.ResponseWrite.Bytes, std::string_view{"gun-response-after-eof"}.size());
    EXPECT_FALSE(Result.ResponseWrite.Failure.Failed());
    EXPECT_TRUE(Result.WriteShutdownAccepted);
    EXPECT_TRUE(Result.ResponseOnWire);
    EXPECT_TRUE(Result.CloseAccepted);
    EXPECT_TRUE(Result.DrainSucceeded);
    EXPECT_EQ(Lower->ReadCount(), 1U);
    EXPECT_EQ(Lower->CloseCount(), 1U);
}

TEST(GunStreamTransportTerminal, CompleteMessagePrecedesNativeResetAndResetIsSticky)
{
    constexpr std::string_view Payload{"request-message-before-native-reset"};
    const auto Native = std::make_error_code(std::errc::connection_reset);
    const auto Terminal = Prism::Fault::FromNative(Native);
    Net::io_context Io;
    auto Wire = MakeRequestWire(Io, Payload);
    ASSERT_FALSE(Wire.empty());
    auto Lower = std::make_shared<ScriptedGrpcTransmission>(
        Io.get_executor(), ScriptedGrpcInput{std::move(Wire), Terminal, false});

    const auto Result = RunScenarioInContext(Io, ScenarioInput{Lower, Payload, false});

    ASSERT_TRUE(Result.Accepted) << static_cast<int>(Result.AcceptFailure.Code);
    EXPECT_EQ(Result.Payload, Payload);
    EXPECT_EQ(Result.FirstTerminal.Bytes, 0U);
    EXPECT_EQ(Result.FirstTerminal.Failure.Code, Terminal.Code);
    EXPECT_EQ(Result.FirstTerminal.Failure.Native, Native);
    EXPECT_EQ(Result.SecondTerminal.Bytes, 0U);
    EXPECT_EQ(Result.SecondTerminal.Failure.Code, Terminal.Code);
    EXPECT_EQ(Result.SecondTerminal.Failure.Native, Native);
    EXPECT_TRUE(Result.CloseAccepted);
    EXPECT_FALSE(Result.DrainSucceeded);
    EXPECT_EQ(Result.DrainFailure.Code, Terminal.Code);
    EXPECT_EQ(Result.DrainFailure.Native, Native);
    EXPECT_TRUE(Result.ActivityRetired);
    EXPECT_EQ(Lower->ReadCount(), 1U);
    EXPECT_EQ(Lower->WriteFailureCount(), 0U);
    EXPECT_EQ(Lower->CloseCount(), 1U);
}

TEST(GunStreamTransportTerminal, Http2EndStreamIsStickyEofWhileLowerRemainsOpen)
{
    constexpr std::string_view Payload{"request-ended-at-http2-stream-boundary"};
    Net::io_context Io;
    auto Wire = MakeRequestWire(Io, Payload);
    ASSERT_FALSE(Wire.empty());
    auto Lower = std::make_shared<ScriptedGrpcTransmission>(
        Io.get_executor(), ScriptedGrpcInput{std::move(Wire), {}, false, true});

    const auto Result = RunScenarioInContext(Io, ScenarioInput{Lower, Payload, true});

    ASSERT_TRUE(Result.Accepted) << static_cast<int>(Result.AcceptFailure.Code);
    EXPECT_EQ(Result.Payload, Payload);
    EXPECT_EQ(Result.FirstTerminal.Bytes, 0U);
    EXPECT_EQ(Result.FirstTerminal.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(Result.SecondTerminal.Bytes, 0U);
    EXPECT_EQ(Result.SecondTerminal.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(Result.ResponseWrite.Bytes, std::string_view{"gun-response-after-eof"}.size());
    EXPECT_FALSE(Result.ResponseWrite.Failure.Failed());
    EXPECT_TRUE(Result.WriteShutdownAccepted);
    EXPECT_TRUE(Result.ResponseOnWire);
    EXPECT_TRUE(Result.LowerOpenBeforeClose);
    EXPECT_TRUE(Result.CloseAccepted);
    EXPECT_TRUE(Result.DrainSucceeded);
    EXPECT_EQ(Lower->ReadCount(), 1U);
    EXPECT_EQ(Lower->CloseCount(), 1U);
}

TEST(GunStreamTransportTerminal, ExternalCancelCompletesPendingPublicRead)
{
    Net::io_context Io;
    auto Wire = MakeOpenRequestWire(Io);
    ASSERT_FALSE(Wire.empty());
    auto Lower = std::make_shared<ScriptedGrpcTransmission>(
        Net::make_strand(Io.get_executor()),
        ScriptedGrpcInput{std::move(Wire), {}, false, true});

    const auto Result = RunCancelScenarioInContext(Io, Lower);

    ASSERT_TRUE(Result.Accepted) << static_cast<int>(Result.AcceptFailure.Code);
    EXPECT_TRUE(Result.PublicReadStarted);
    EXPECT_TRUE(Result.CancelAccepted);
    EXPECT_TRUE(Result.CanceledReadBeforeClose);
    EXPECT_EQ(Result.CanceledRead.Bytes, 0U);
    EXPECT_EQ(Result.CanceledRead.Failure.Code, Prism::Fault::Code::Canceled);
    EXPECT_TRUE(Result.CloseAccepted);
    EXPECT_TRUE(Result.DrainSucceeded);
    EXPECT_EQ(Lower->ReadCount(), 2U);
    EXPECT_EQ(Lower->CloseCount(), 1U);
}
