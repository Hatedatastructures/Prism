/**
 * @file GunStreamCloseTest.cpp
 * @brief gRPC stream 在 RST 与写半关闭时保留已提交数据和完成回执。
 */

#include <gtest/gtest.h>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/dispatch.hpp>
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
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace
{
    namespace H2 = Prism::Http2;
    namespace Grpc = Prism::Gun::Grpc;
    namespace Net = boost::asio;

    using ReadNotifyChannel = Net::experimental::channel<void(boost::system::error_code)>;

    struct ReadCompletion final
    {
        std::shared_ptr<Prism::IoResult> Result;
        std::shared_ptr<std::vector<std::byte>> Bytes;
        std::shared_ptr<ReadNotifyChannel> Notify;
    };

    struct ScriptedInput final
    {
        std::vector<std::byte> Wire;
        bool HoldOpenAfterInput{false};
        bool HoldDataWrites{false};
    };

    class ScriptedTransmission final : public Prism::Transmission
    {
    public:
        ScriptedTransmission(ExecutorType Executor, ScriptedInput Input)
            : Transmission(std::move(Executor)), Input_(std::move(Input.Wire)),
              HoldOpenAfterInput_(Input.HoldOpenAfterInput),
              HoldDataWrites_(Input.HoldDataWrites), PendingReadNotify_(this->Executor(), 1),
              PendingWriteNotify_(this->Executor(), 1)
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

        [[nodiscard]] auto Written() const noexcept -> const std::vector<std::byte> &
        {
            return Written_;
        }

        [[nodiscard]] auto WaitForPendingRead() -> Net::awaitable<bool>
        {
            co_await Net::dispatch(Executor(), Net::use_awaitable);
            while (!PendingRead_)
            {
                boost::system::error_code Error;
                co_await PendingReadNotify_.async_receive(
                    Net::redirect_error(Net::use_awaitable, Error));
                if (Error)
                {
                    co_return false;
                }
            }
            co_return true;
        }

        [[nodiscard]] auto CompletePendingInput(std::vector<std::byte> Input)
            -> Net::awaitable<bool>
        {
            co_await Net::dispatch(Executor(), Net::use_awaitable);
            if (!PendingRead_ || Input.size() > PendingReadBuffer_.size())
            {
                co_return false;
            }
            std::copy(Input.begin(), Input.end(), PendingReadBuffer_.begin());
            auto Handler = std::move(*PendingRead_);
            PendingRead_.reset();
            PendingReadBuffer_ = {};
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Input.size(), {}});
            co_return true;
        }

        [[nodiscard]] auto WaitForPendingDataWrite() -> Net::awaitable<bool>
        {
            co_await Net::dispatch(Executor(), Net::use_awaitable);
            while (!PendingWriteHandler_)
            {
                boost::system::error_code Error;
                co_await PendingWriteNotify_.async_receive(
                    Net::redirect_error(Net::use_awaitable, Error));
                if (Error)
                {
                    co_return false;
                }
            }
            co_return true;
        }

        [[nodiscard]] auto ReleasePendingDataWrite() -> Net::awaitable<bool>
        {
            co_await Net::dispatch(Executor(), Net::use_awaitable);
            if (!PendingWriteHandler_)
            {
                co_return false;
            }
            HoldDataWrites_ = false;
            Written_.insert(
                Written_.end(), PendingWriteBytes_.begin(), PendingWriteBytes_.end());
            auto Handler = std::move(*PendingWriteHandler_);
            PendingWriteHandler_.reset();
            const auto Count = PendingWriteBytes_.size();
            PendingWriteBytes_.clear();
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {Count, {}});
            co_return true;
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_;
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadCount_;
            if (ReadDelivered_ && HoldOpenAfterInput_)
            {
                PendingReadBuffer_ = Buffer;
                PendingRead_.emplace(std::move(Handler));
                (void)PendingReadNotify_.try_send(boost::system::error_code{});
                return;
            }
            const auto Count = ReadDelivered_ ? 0U : (std::min)(Buffer.size(), Input_.size());
            if (!ReadDelivered_)
            {
                std::copy_n(Input_.begin(), Count, Buffer.begin());
                ReadDelivered_ = true;
            }
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {Count, {}});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            if (HoldDataWrites_ && ContainsFrameType(Buffer, 0U))
            {
                PendingWriteBytes_.assign(Buffer.begin(), Buffer.end());
                PendingWriteHandler_.emplace(std::move(Handler));
                (void)PendingWriteNotify_.try_send(boost::system::error_code{});
                return;
            }
            Written_.insert(Written_.end(), Buffer.begin(), Buffer.end());
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
            CompletePendingWrite({Prism::Fault::Code::Canceled});
            PendingReadNotify_.close();
            PendingWriteNotify_.close();
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
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

        auto CompletePendingRead(const Prism::Fault::Failure Failure) -> void
        {
            if (!PendingRead_)
            {
                return;
            }
            auto Handler = std::move(*PendingRead_);
            PendingRead_.reset();
            PendingReadBuffer_ = {};
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {0, Failure});
        }

        auto CompletePendingWrite(const Prism::Fault::Failure Failure) -> void
        {
            if (!PendingWriteHandler_)
            {
                return;
            }
            auto Handler = std::move(*PendingWriteHandler_);
            PendingWriteHandler_.reset();
            PendingWriteBytes_.clear();
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {0, Failure});
        }

        std::vector<std::byte> Input_;
        std::vector<std::byte> Written_;
        bool HoldOpenAfterInput_{false};
        bool HoldDataWrites_{false};
        Net::experimental::channel<void(boost::system::error_code)> PendingReadNotify_;
        Net::experimental::channel<void(boost::system::error_code)> PendingWriteNotify_;
        std::optional<Completion> PendingRead_;
        std::span<std::byte> PendingReadBuffer_;
        std::optional<Completion> PendingWriteHandler_;
        std::vector<std::byte> PendingWriteBytes_;
        bool ReadDelivered_{false};
        bool Closed_{false};
        std::size_t ReadCount_{0};
        std::size_t CloseCount_{0};
    };

    struct ScenarioResult final
    {
        bool Accepted{false};
        Prism::Fault::Failure AcceptFailure{};
        std::string Payload;
        Prism::IoResult MessageRead{};
        Prism::IoResult FirstTerminal{};
        Prism::IoResult SecondTerminal{};
        std::size_t CloseCountBeforeWrapperClose{0};
        Prism::IoResult ResponseWrite{};
        Prism::IoResult ShutdownResult{};
        bool ShutdownCompletedBeforeWriteRelease{false};
        bool ShutdownCompletionReceived{false};
        bool DataOnWire{false};
        bool EndStreamHeadersOnWire{false};
        bool EndStreamHeadersAfterData{false};
        bool CloseAccepted{false};
        bool DrainSucceeded{false};
        bool ActivityRetired{false};
        Prism::Fault::Failure DrainFailure{};
    };

    [[nodiscard]] auto MakeOpenRequestWire(Net::io_context &Io) -> std::vector<std::byte>
    {
        H2::Session Client(Io.get_executor(), false);
        Client.SendSettings();
        if (!Client.OpenStream(Grpc::MakeRequestHeaders("/GunService/Tun", "gun"), false))
        {
            return {};
        }
        std::vector<std::byte> Wire;
        return Client.Collect(Wire) ? Wire : std::vector<std::byte>{};
    }

    [[nodiscard]] auto MakeResetDataWire(
        Net::any_io_executor Executor,
        const std::string_view Payload) -> std::vector<std::byte>
    {
        H2::Session Client(std::move(Executor), false);
        Client.SendSettings();
        const auto Stream = Client.OpenStream(
            Grpc::MakeRequestHeaders("/GunService/Tun", "gun"), false);
        if (!Stream)
        {
            return {};
        }
        std::vector<std::byte> Initial;
        if (!Client.Collect(Initial))
        {
            return {};
        }
        const auto Message = Grpc::EncodeMessage(std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
        if (Client.SubmitData(*Stream, Message, false) != H2::SubmitDataStatus::Accepted)
        {
            return {};
        }
        std::vector<std::byte> Wire;
        if (!Client.Collect(Wire) || Wire.empty())
        {
            return {};
        }
        if (!Client.ResetStream(*Stream, H2::ErrorNoError))
        {
            return {};
        }
        std::vector<std::byte> Reset;
        if (!Client.Collect(Reset) || Reset.empty())
        {
            return {};
        }
        Wire.insert(Wire.end(), Reset.begin(), Reset.end());
        return Wire;
    }

    [[nodiscard]] auto FindFrameOffset(
        const std::span<const std::byte> Wire,
        const std::uint8_t Type,
        const std::uint8_t RequiredFlags = 0U) -> std::optional<std::size_t>
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
                return std::nullopt;
            }
            const auto Flags = std::to_integer<std::uint8_t>(Wire[Offset + 4U]);
            if (std::to_integer<std::uint8_t>(Wire[Offset + 3U]) == Type &&
                (Flags & RequiredFlags) == RequiredFlags)
            {
                return Offset;
            }
            Offset += 9U + Length;
        }
        return std::nullopt;
    }

    auto RunStreamRead(
        Prism::SharedTransmission Stream,
        ReadCompletion Completion) -> Net::awaitable<void>
    {
        std::array<std::byte, 128> Buffer{};
        *Completion.Result = co_await Stream->ReadSome(Buffer);
        const auto Count = (std::min)(Completion.Result->Bytes, Buffer.size());
        Completion.Bytes->assign(
            Buffer.begin(), Buffer.begin() + static_cast<std::ptrdiff_t>(Count));
        (void)Completion.Notify->try_send(boost::system::error_code{});
    }

    [[nodiscard]] auto RunResetScenario(
        const std::shared_ptr<ScriptedTransmission> &Lower,
        const std::string_view Payload) -> Net::awaitable<ScenarioResult>
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
        const bool LowerReadPending = co_await Lower->WaitForPendingRead();
        const auto ResetData = MakeResetDataWire(Stream->Executor(), Payload);
        if (!LowerReadPending || ResetData.empty())
        {
            Result.AcceptFailure = {Prism::Fault::Code::IoError};
            (void)Stream->Close();
            const auto Drained = co_await Stream->Activity()->Drain();
            Result.DrainSucceeded = static_cast<bool>(Drained);
            co_return Result;
        }

        auto ReadCapture = std::make_shared<Prism::IoResult>();
        auto ReadBytes = std::make_shared<std::vector<std::byte>>();
        auto ReadNotify = std::make_shared<ReadNotifyChannel>(Stream->Executor(), 1);
        Net::co_spawn(Stream->Executor(),
            RunStreamRead(Stream, ReadCompletion{ReadCapture, ReadBytes, ReadNotify}),
            Net::detached);
        co_await Net::post(Stream->Executor(), Net::use_awaitable);
        co_await Net::post(Stream->Executor(), Net::use_awaitable);
        const bool InputCompleted = co_await Lower->CompletePendingInput(ResetData);
        if (!InputCompleted)
        {
            Result.AcceptFailure = {Prism::Fault::Code::IoError};
            (void)Stream->Close();
            const auto Drained = co_await Stream->Activity()->Drain();
            Result.DrainSucceeded = static_cast<bool>(Drained);
            co_return Result;
        }
        boost::system::error_code ReadError;
        co_await ReadNotify->async_receive(Net::redirect_error(Net::use_awaitable, ReadError));
        Result.MessageRead = *ReadCapture;
        if (!ReadError)
        {
            Result.Payload.assign(
                reinterpret_cast<const char *>(ReadBytes->data()), ReadBytes->size());
        }
        std::array<std::byte, 1> TerminalBuffer{};
        Result.FirstTerminal = co_await Stream->ReadSome(TerminalBuffer);
        Result.SecondTerminal = co_await Stream->ReadSome(TerminalBuffer);
        Result.CloseCountBeforeWrapperClose = Lower->CloseCount();
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

    [[nodiscard]] auto RunShutdownScenario(
        const std::shared_ptr<ScriptedTransmission> &Lower) -> Net::awaitable<ScenarioResult>
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
        constexpr std::string_view Response{"shutdown-barrier-data"};
        const auto Bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Response.data()), Response.size());
        Result.ResponseWrite = co_await Stream->WriteSome(Bytes);
        if (!co_await Lower->WaitForPendingDataWrite())
        {
            Result.AcceptFailure = {Prism::Fault::Code::IoError};
            (void)Stream->Close();
            const auto Drained = co_await Stream->Activity()->Drain();
            Result.DrainSucceeded = static_cast<bool>(Drained);
            co_return Result;
        }

        auto ShutdownNotify = std::make_shared<Net::experimental::channel<
            void(boost::system::error_code, Prism::IoResult)>>(Stream->Executor(), 1);
        co_await Net::dispatch(Stream->Executor(), Net::use_awaitable);
        Stream->WriteShutdown(
            [ShutdownNotify](const Prism::IoResult Value)
            { (void)ShutdownNotify->try_send(boost::system::error_code{}, Value); });
        co_await Net::post(Stream->Executor(), Net::use_awaitable);
        co_await Net::post(Stream->Executor(), Net::use_awaitable);
        Result.ShutdownCompletedBeforeWriteRelease = ShutdownNotify->ready();
        if (!co_await Lower->ReleasePendingDataWrite())
        {
            Result.AcceptFailure = {Prism::Fault::Code::IoError};
            (void)Stream->Close();
            const auto Drained = co_await Stream->Activity()->Drain();
            Result.DrainSucceeded = static_cast<bool>(Drained);
            co_return Result;
        }
        boost::system::error_code ShutdownError;
        Result.ShutdownResult = co_await ShutdownNotify->async_receive(
            Net::redirect_error(Net::use_awaitable, ShutdownError));
        Result.ShutdownCompletionReceived = !ShutdownError;
        const auto &Wire = Lower->Written();
        const auto DataOffset = FindFrameOffset(Wire, 0U);
        const auto EndStreamOffset = FindFrameOffset(Wire, 1U, 1U);
        Result.DataOnWire = DataOffset.has_value();
        Result.EndStreamHeadersOnWire = EndStreamOffset.has_value();
        Result.EndStreamHeadersAfterData = DataOffset && EndStreamOffset &&
            *DataOffset < *EndStreamOffset;
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

    [[nodiscard]] auto RunInContext(
        Net::io_context &Io,
        Net::awaitable<ScenarioResult> Operation) -> ScenarioResult
    {
        std::optional<ScenarioResult> Result;
        std::exception_ptr Exception;
        Net::co_spawn(Io, std::move(Operation),
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
}

TEST(GunStreamTransportTerminal, CompleteMessagePrecedesHttp2ResetAndResetIsSticky)
{
    constexpr std::string_view Payload{"request-message-before-stream-reset"};
    Net::io_context Io;
    auto Wire = MakeOpenRequestWire(Io);
    ASSERT_FALSE(Wire.empty());
    auto Lower = std::make_shared<ScriptedTransmission>(
        Net::make_strand(Io.get_executor()),
        ScriptedInput{std::move(Wire), true, false});

    const auto Result = RunInContext(Io, RunResetScenario(Lower, Payload));

    ASSERT_TRUE(Result.Accepted) << static_cast<int>(Result.AcceptFailure.Code);
    EXPECT_EQ(Result.Payload, Payload);
    EXPECT_EQ(Result.MessageRead.Bytes, Payload.size());
    EXPECT_FALSE(Result.MessageRead.Failure.Failed());
    EXPECT_EQ(Result.FirstTerminal.Bytes, 0U);
    EXPECT_EQ(Result.FirstTerminal.Failure.Code, Prism::Fault::Code::ConnectionReset);
    EXPECT_EQ(Result.SecondTerminal.Bytes, 0U);
    EXPECT_EQ(Result.SecondTerminal.Failure.Code, Prism::Fault::Code::ConnectionReset);
    EXPECT_EQ(Result.CloseCountBeforeWrapperClose, 1U);
    EXPECT_EQ(Lower->ReadCount(), 2U);
    EXPECT_EQ(Lower->CloseCount(), 1U);
    EXPECT_TRUE(Result.CloseAccepted);
    EXPECT_FALSE(Result.DrainSucceeded);
    EXPECT_EQ(Result.DrainFailure.Code, Prism::Fault::Code::ConnectionReset);
    EXPECT_TRUE(Result.ActivityRetired);
}

TEST(GunStreamTransportTerminal, WriteShutdownCompletesAfterTrailersReachLower)
{
    Net::io_context Io;
    auto Wire = MakeOpenRequestWire(Io);
    ASSERT_FALSE(Wire.empty());
    auto Lower = std::make_shared<ScriptedTransmission>(
        Net::make_strand(Io.get_executor()),
        ScriptedInput{std::move(Wire), true, true});

    const auto Result = RunInContext(Io, RunShutdownScenario(Lower));

    ASSERT_TRUE(Result.Accepted) << static_cast<int>(Result.AcceptFailure.Code);
    EXPECT_EQ(Result.ResponseWrite.Bytes, std::string_view{"shutdown-barrier-data"}.size());
    EXPECT_FALSE(Result.ResponseWrite.Failure.Failed());
    EXPECT_FALSE(Result.ShutdownCompletedBeforeWriteRelease);
    EXPECT_TRUE(Result.ShutdownCompletionReceived);
    EXPECT_FALSE(Result.ShutdownResult.Failure.Failed());
    EXPECT_TRUE(Result.DataOnWire);
    EXPECT_TRUE(Result.EndStreamHeadersOnWire);
    EXPECT_TRUE(Result.EndStreamHeadersAfterData);
    EXPECT_TRUE(Result.CloseAccepted);
    EXPECT_TRUE(Result.DrainSucceeded);
    EXPECT_TRUE(Result.ActivityRetired);
    EXPECT_EQ(Lower->CloseCount(), 1U);
}
