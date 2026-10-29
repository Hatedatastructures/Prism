/**
 * @file ReadLoopTest.cpp
 * @brief HTTP/3 StreamProvider 读取终态到 Data/Fin 与 Error 的确定性映射。
 */

#include <Prism/Protocols/Http3/NativeClient.hpp>
#include <Prism/Protocols/Http3/NativeServer.hpp>
#include <Prism/Protocols/Http3/Detail/NativeClient.hpp>
#include <Prism/Protocols/Http3/Detail/NativeServer.hpp>
#include <TestSupport/Prism/Quic/StreamActivity.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <stdexcept>
#include <utility>
#include <vector>

namespace Prism::Http3::Detail
{
    enum class ReadLoopEventKind : std::uint8_t
    {
        None,
        Data,
        Error,
    };

    struct ReadLoopObservation final
    {
        ReadLoopEventKind Kind{ReadLoopEventKind::None};
        std::vector<std::byte> Data;
        std::error_code Error;
        Prism::Fault::Failure Failure;
        bool Fin{false};
        bool ClosedAfterRead{false};
        bool ClosedAtEnd{false};
        bool ProviderRetiredAtEnd{false};
    };

    struct Http3ReadLoopTestAccess final
    {
        [[nodiscard]] static auto RunServer(
            NativeServerSessionOwner &Owner,
            const Prism::Quic::SharedStreamProvider &Provider,
            const bool Unidirectional) -> Net::awaitable<ReadLoopObservation>
        {
            co_await Owner.ReadLoop(Provider, Unidirectional);
            ReadLoopObservation Result;
            Result.ClosedAfterRead = Owner.Closed_;
            Result.Failure = Owner.FirstFailure_;
            if (Owner.Events_)
            {
                const auto Event = co_await Owner.Events_->Receive();
                if (!Event)
                {
                    throw std::runtime_error("HTTP/3 read loop published a null event");
                }
                Result.Kind = Event->Type == NativeServerSessionOwner::EventType::Data
                    ? ReadLoopEventKind::Data
                    : ReadLoopEventKind::Error;
                Result.Data = std::move(Event->Data);
                Result.Error = Event->Error;
                Result.Fin = Event->Fin;
            }
            Owner.CloseOnExecutor();
            Result.ClosedAtEnd = Owner.Closed_;
            (void)Provider->Close();
            Result.ProviderRetiredAtEnd = Provider->Activity()->IsRetired();
            co_return Result;
        }

        [[nodiscard]] static auto RunClient(
            NativeClientSessionOwner &Owner,
            const Prism::Quic::SharedStreamProvider &Provider)
            -> Net::awaitable<ReadLoopObservation>
        {
            co_await Owner.ReadLoop(Provider);
            ReadLoopObservation Result;
            Result.ClosedAfterRead = Owner.Closed_;
            Result.Failure = Owner.FirstFailure_;
            if (Owner.Events_)
            {
                const auto Event = co_await Owner.Events_->Receive();
                if (!Event)
                {
                    throw std::runtime_error("HTTP/3 read loop published a null event");
                }
                Result.Kind = Event->Type == NativeClientSessionOwner::EventType::Data
                    ? ReadLoopEventKind::Data
                    : ReadLoopEventKind::Error;
                Result.Data = std::move(Event->Data);
                Result.Error = Event->Error;
                Result.Fin = Event->Fin;
            }
            Owner.CloseOnExecutor();
            Result.ClosedAtEnd = Owner.Closed_;
            (void)Provider->Close();
            Result.ProviderRetiredAtEnd = Provider->Activity()->IsRetired();
            co_return Result;
        }

    };
}

namespace
{
    namespace Net = boost::asio;
    using Prism::Http3::Detail::Http3ReadLoopTestAccess;
    using Prism::Http3::Detail::ReadLoopEventKind;
    using Prism::Http3::Detail::ReadLoopObservation;

    struct ReadLoopProviderOptions final
    {
        std::vector<std::byte> Data;
        std::error_code Error;
        std::optional<std::size_t> Count;
        std::int64_t StreamId{3};
    };

    class ReadLoopProvider final : public Prism::Quic::StreamProvider
    {
    public:
        ReadLoopProvider(Net::any_io_executor Executor, ReadLoopProviderOptions Options)
            : Executor_(std::move(Executor)), Data_(std::move(Options.Data)),
              Error_(std::move(Options.Error)), Count_(Options.Count), StreamId_(Options.StreamId),
              Activity_(std::make_shared<Prism::Testing::Quic::StreamProviderActivity>(Executor_))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto Read(std::span<std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            const auto Operation = Activity_->BeginOperation();
            ++ReadCalls_;
            if (!Operation || Closed_)
            {
                ErrorCode = std::make_error_code(std::errc::operation_canceled);
                co_return 0U;
            }
            const auto Count = Count_ ? (std::min)(Buffer.size(), *Count_) :
                (std::min)(Buffer.size(), Data_.size());
            std::copy_n(Data_.begin(), Count, Buffer.begin());
            ErrorCode = Error_;
            co_return Count;
        }

        [[nodiscard]] auto Write(std::span<const std::byte>, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            ErrorCode.clear();
            if (Closed_)
            {
                ErrorCode = std::make_error_code(std::errc::broken_pipe);
            }
            co_return 0U;
        }

        [[nodiscard]] auto Close() -> Prism::Quic::StreamProvider::ControlResult override
        {
            if (!Closed_)
            {
                Closed_ = true;
                Activity_->CompleteClose();
            }
            return {};
        }

        [[nodiscard]] auto ShutdownWrite()
            -> Net::awaitable<Prism::Quic::StreamProvider::ShutdownResult> override
        {
            co_return Prism::Quic::StreamProvider::ShutdownResult{};
        }

        [[nodiscard]] auto WaitForWriteAcknowledgement()
            -> Net::awaitable<Prism::Quic::StreamProvider::ShutdownResult> override
        {
            co_return Prism::Quic::StreamProvider::ShutdownResult{};
        }

        [[nodiscard]] auto StreamId() const noexcept -> std::int64_t override
        {
            return StreamId_;
        }

        [[nodiscard]] auto IsClosed() const noexcept -> bool override
        {
            return Closed_;
        }

        [[nodiscard]] auto ReadCalls() const noexcept -> std::size_t
        {
            return ReadCalls_;
        }

    private:
        Net::any_io_executor Executor_;
        std::vector<std::byte> Data_;
        std::error_code Error_;
        std::optional<std::size_t> Count_;
        std::int64_t StreamId_;
        std::shared_ptr<Prism::Testing::Quic::StreamProviderActivity> Activity_;
        std::size_t ReadCalls_{0U};
        bool Closed_{false};
    };

    [[nodiscard]] auto AsioEof() -> std::error_code
    {
        return static_cast<std::error_code>(
            boost::asio::error::make_error_code(boost::asio::error::eof));
    }

    template <typename Value>
    [[nodiscard]] auto RunAwaitable(Net::io_context &Io, Net::awaitable<Value> Work) -> Value
    {
        std::optional<Value> Result;
        std::exception_ptr Exception;
        Net::co_spawn(Io, std::move(Work), [&Result, &Exception](
            std::exception_ptr Error, Value ValueResult)
        {
            Exception = std::move(Error);
            Result.emplace(std::move(ValueResult));
        });
        Io.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
        if (!Result)
        {
            throw std::runtime_error("awaitable did not complete");
        }
        return std::move(*Result);
    }

    TEST(NativeHttp3ReadLoop, ClientAsioEofPublishesBufferedBytesWithFin)
    {
        Net::io_context Io;
        Prism::Http3::NativeClientSessionOptions Options;
        Options.Executor = Io.get_executor();
        auto Owner = std::make_shared<Prism::Http3::Detail::NativeClientSessionOwner>(
            std::move(Options));
        auto Provider = std::make_shared<ReadLoopProvider>(
            Io.get_executor(), ReadLoopProviderOptions{
                std::vector<std::byte>{std::byte{0x41}, std::byte{0x42}}, AsioEof(), 2U});

        const auto Result = RunAwaitable(
            Io, Http3ReadLoopTestAccess::RunClient(*Owner, Provider));

        EXPECT_EQ(Result.Kind, ReadLoopEventKind::Data);
        EXPECT_TRUE(Result.Fin);
        EXPECT_FALSE(Result.ClosedAfterRead);
        EXPECT_TRUE(Result.ClosedAtEnd);
        EXPECT_TRUE(Result.ProviderRetiredAtEnd);
        EXPECT_TRUE(Result.Failure.Succeeded());
        EXPECT_FALSE(Result.Error);
        EXPECT_EQ(Result.Data.size(), 2U);
        EXPECT_EQ(Result.Data[0], std::byte{0x41});
        EXPECT_EQ(Result.Data[1], std::byte{0x42});
        EXPECT_EQ(Provider->ReadCalls(), 1U);
    }

    TEST(NativeHttp3ReadLoop, ClientZeroLengthReadPublishesEmptyFin)
    {
        Net::io_context Io;
        Prism::Http3::NativeClientSessionOptions Options;
        Options.Executor = Io.get_executor();
        auto Owner = std::make_shared<Prism::Http3::Detail::NativeClientSessionOwner>(
            std::move(Options));
        auto Provider = std::make_shared<ReadLoopProvider>(
            Io.get_executor(), ReadLoopProviderOptions{});

        const auto Result = RunAwaitable(
            Io, Http3ReadLoopTestAccess::RunClient(*Owner, Provider));

        EXPECT_EQ(Result.Kind, ReadLoopEventKind::Data);
        EXPECT_TRUE(Result.Fin);
        EXPECT_FALSE(Result.ClosedAfterRead);
        EXPECT_TRUE(Result.ClosedAtEnd);
        EXPECT_TRUE(Result.ProviderRetiredAtEnd);
        EXPECT_TRUE(Result.Failure.Succeeded());
        EXPECT_FALSE(Result.Error);
        EXPECT_TRUE(Result.Data.empty());
        EXPECT_EQ(Provider->ReadCalls(), 1U);
    }

    TEST(NativeHttp3ReadLoop, ClientNonEofFailureWithNoBytesPublishesTerminalError)
    {
        Net::io_context Io;
        Prism::Http3::NativeClientSessionOptions Options;
        Options.Executor = Io.get_executor();
        auto Owner = std::make_shared<Prism::Http3::Detail::NativeClientSessionOwner>(
            std::move(Options));
        const auto Error = std::make_error_code(std::errc::connection_reset);
        auto Provider = std::make_shared<ReadLoopProvider>(
            Io.get_executor(), ReadLoopProviderOptions{
                std::vector<std::byte>{std::byte{0x43}}, Error, 0U});

        const auto Result = RunAwaitable(
            Io, Http3ReadLoopTestAccess::RunClient(*Owner, Provider));

        EXPECT_EQ(Result.Kind, ReadLoopEventKind::Error);
        EXPECT_FALSE(Result.Fin);
        EXPECT_FALSE(Result.ClosedAfterRead);
        EXPECT_TRUE(Result.ClosedAtEnd);
        EXPECT_TRUE(Result.ProviderRetiredAtEnd);
        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Result.Error, Error);
        EXPECT_TRUE(Result.Data.empty());
    }

    TEST(NativeHttp3ReadLoop, ClientNonEofFailureRetainsReturnedBytes)
    {
        Net::io_context Io;
        Prism::Http3::NativeClientSessionOptions Options;
        Options.Executor = Io.get_executor();
        auto Owner = std::make_shared<Prism::Http3::Detail::NativeClientSessionOwner>(
            std::move(Options));
        const auto Error = std::make_error_code(std::errc::connection_reset);
        auto Provider = std::make_shared<ReadLoopProvider>(
            Io.get_executor(), ReadLoopProviderOptions{
                std::vector<std::byte>{std::byte{0x47}, std::byte{0x48}}, Error, 2U});

        const auto Result = RunAwaitable(
            Io, Http3ReadLoopTestAccess::RunClient(*Owner, Provider));

        EXPECT_EQ(Result.Kind, ReadLoopEventKind::Error);
        EXPECT_FALSE(Result.Fin);
        EXPECT_FALSE(Result.ClosedAfterRead);
        EXPECT_TRUE(Result.ClosedAtEnd);
        EXPECT_TRUE(Result.ProviderRetiredAtEnd);
        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Result.Error, Error);
        ASSERT_EQ(Result.Data.size(), 2U);
        EXPECT_EQ(Result.Data[0], std::byte{0x47});
        EXPECT_EQ(Result.Data[1], std::byte{0x48});
        EXPECT_EQ(Provider->ReadCalls(), 1U);
    }

    TEST(NativeHttp3ReadLoop, ServerAsioEofPublishesBufferedBytesWithFin)
    {
        Net::io_context Io;
        Prism::Http3::NativeServerSessionOptions Options;
        Options.Executor = Io.get_executor();
        auto Owner = std::make_shared<Prism::Http3::Detail::NativeServerSessionOwner>(
            std::move(Options));
        auto Provider = std::make_shared<ReadLoopProvider>(
            Io.get_executor(), ReadLoopProviderOptions{
                std::vector<std::byte>{std::byte{0x44}, std::byte{0x45}}, AsioEof(), 2U});

        const auto Result = RunAwaitable(
            Io, Http3ReadLoopTestAccess::RunServer(*Owner, Provider, false));

        EXPECT_EQ(Result.Kind, ReadLoopEventKind::Data);
        EXPECT_TRUE(Result.Fin);
        EXPECT_FALSE(Result.ClosedAfterRead);
        EXPECT_TRUE(Result.ClosedAtEnd);
        EXPECT_TRUE(Result.ProviderRetiredAtEnd);
        EXPECT_TRUE(Result.Failure.Succeeded());
        EXPECT_FALSE(Result.Error);
        EXPECT_EQ(Result.Data.size(), 2U);
        EXPECT_EQ(Result.Data[0], std::byte{0x44});
        EXPECT_EQ(Result.Data[1], std::byte{0x45});
        EXPECT_EQ(Provider->ReadCalls(), 1U);
    }

    TEST(NativeHttp3ReadLoop, ServerZeroLengthReadPublishesEmptyFin)
    {
        Net::io_context Io;
        Prism::Http3::NativeServerSessionOptions Options;
        Options.Executor = Io.get_executor();
        auto Owner = std::make_shared<Prism::Http3::Detail::NativeServerSessionOwner>(
            std::move(Options));
        auto Provider = std::make_shared<ReadLoopProvider>(
            Io.get_executor(), ReadLoopProviderOptions{});

        const auto Result = RunAwaitable(
            Io, Http3ReadLoopTestAccess::RunServer(*Owner, Provider, false));

        EXPECT_EQ(Result.Kind, ReadLoopEventKind::Data);
        EXPECT_TRUE(Result.Fin);
        EXPECT_FALSE(Result.ClosedAfterRead);
        EXPECT_TRUE(Result.ClosedAtEnd);
        EXPECT_TRUE(Result.ProviderRetiredAtEnd);
        EXPECT_TRUE(Result.Failure.Succeeded());
        EXPECT_FALSE(Result.Error);
        EXPECT_TRUE(Result.Data.empty());
        EXPECT_EQ(Provider->ReadCalls(), 1U);
    }

    TEST(NativeHttp3ReadLoop, ServerNonEofFailureWithNoBytesPublishesTerminalError)
    {
        Net::io_context Io;
        Prism::Http3::NativeServerSessionOptions Options;
        Options.Executor = Io.get_executor();
        auto Owner = std::make_shared<Prism::Http3::Detail::NativeServerSessionOwner>(
            std::move(Options));
        const auto Error = std::make_error_code(std::errc::connection_reset);
        auto Provider = std::make_shared<ReadLoopProvider>(
            Io.get_executor(), ReadLoopProviderOptions{
                std::vector<std::byte>{std::byte{0x46}}, Error, 0U});

        const auto Result = RunAwaitable(
            Io, Http3ReadLoopTestAccess::RunServer(*Owner, Provider, false));

        EXPECT_EQ(Result.Kind, ReadLoopEventKind::Error);
        EXPECT_FALSE(Result.Fin);
        EXPECT_FALSE(Result.ClosedAfterRead);
        EXPECT_TRUE(Result.ClosedAtEnd);
        EXPECT_TRUE(Result.ProviderRetiredAtEnd);
        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Result.Error, Error);
        EXPECT_TRUE(Result.Data.empty());
    }

    TEST(NativeHttp3ReadLoop, ServerNonEofFailureRetainsReturnedBytes)
    {
        Net::io_context Io;
        Prism::Http3::NativeServerSessionOptions Options;
        Options.Executor = Io.get_executor();
        auto Owner = std::make_shared<Prism::Http3::Detail::NativeServerSessionOwner>(
            std::move(Options));
        const auto Error = std::make_error_code(std::errc::connection_reset);
        auto Provider = std::make_shared<ReadLoopProvider>(
            Io.get_executor(), ReadLoopProviderOptions{
                std::vector<std::byte>{std::byte{0x49}, std::byte{0x4A}}, Error, 2U});

        const auto Result = RunAwaitable(
            Io, Http3ReadLoopTestAccess::RunServer(*Owner, Provider, false));

        EXPECT_EQ(Result.Kind, ReadLoopEventKind::Error);
        EXPECT_FALSE(Result.Fin);
        EXPECT_FALSE(Result.ClosedAfterRead);
        EXPECT_TRUE(Result.ClosedAtEnd);
        EXPECT_TRUE(Result.ProviderRetiredAtEnd);
        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Result.Error, Error);
        ASSERT_EQ(Result.Data.size(), 2U);
        EXPECT_EQ(Result.Data[0], std::byte{0x49});
        EXPECT_EQ(Result.Data[1], std::byte{0x4A});
        EXPECT_EQ(Provider->ReadCalls(), 1U);
    }
} // namespace
