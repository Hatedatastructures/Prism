/**
 * @file ReadTest.cpp
 * @brief Prism Common Read 窗口和部分错误契约测试。
 */

#include <gtest/gtest.h>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <system_error>
#include <vector>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Common/ExactIo.hpp>
#include <Prism/Protocols/Common/Read.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Prism/MockTransport.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    using Prism::PrismMockTransport;

template <typename Factory>
    auto RunCoro(Net::io_context &IoContext, Factory FactoryFn) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(IoContext, FactoryFn(), [&](std::exception_ptr ErrorValue)
                      {
                          Failure = ErrorValue;
                          IoContext.stop();
                      });
        IoContext.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

class PartialErrorTransport final : public Prism::Transmission
    {
    public:
        explicit PartialErrorTransport(Net::any_io_executor Ex, const bool WriteMode = false)
            : Prism::Transmission(Ex), Ex_(std::move(Ex)), WriteMode_(WriteMode)
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Ex_;
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_;
        }

        [[nodiscard]] auto ReadCalls() const noexcept -> std::size_t
        {
            return ReadCalls_;
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(ReadWork{}, Ex_), Handler,
                ReadInput{std::static_pointer_cast<PartialErrorTransport>(
                              Prism::Transmission::shared_from_this()),
                          Buffer});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(WriteWork{}, Ex_), Handler,
                WriteInput{std::static_pointer_cast<PartialErrorTransport>(
                               Prism::Transmission::shared_from_this()),
                           Buffer});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Ex_, std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed_ = true;
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        struct ReadInput final
        {
            std::shared_ptr<PartialErrorTransport> Owner;
            std::span<std::byte> Buffer;
        };
        struct WriteInput final
        {
            std::shared_ptr<PartialErrorTransport> Owner;
            std::span<const std::byte> Buffer;
        };
        /** @brief 原协程体原位保留，新前门一次性映射正式结果。 */
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                std::error_code Error;
                auto [Exception, Count] = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadPartial(Input.Buffer, Error),
                    Net::as_tuple(Net::deferred));
                if (Exception)
                {
                    co_return std::tuple{Prism::IoResult{0,
                        Prism::Contract::InboundAdmission::ExceptionFailure(std::move(Exception))}};
                }
                co_return std::tuple{Prism::IoResult{Count, Prism::Fault::FromNative(Error)}};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                std::error_code Error;
                auto [Exception, Count] = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer, Error),
                    Net::as_tuple(Net::deferred));
                if (Exception)
                {
                    co_return std::tuple{Prism::IoResult{0,
                        Prism::Contract::InboundAdmission::ExceptionFailure(std::move(Exception))}};
                }
                co_return std::tuple{Prism::IoResult{Count, Prism::Fault::FromNative(Error)}};
            }
        };
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t>
        {
            ++ReadCalls_;
            if (WriteMode_)
            {
                Error = std::make_error_code(std::errc::connection_reset);
                co_return 0;
            }
            Error = std::make_error_code(std::errc::connection_reset);
            if (Consumed_ || Buffer.size() < Data_.size())
            {
                co_return 0;
            }
            std::copy(Data_.begin(), Data_.end(), Buffer.begin());
            Consumed_ = true;
            co_return Data_.size();
        }
        [[nodiscard]] auto WritePartial(std::span<const std::byte>, std::error_code &Error)
            -> Net::awaitable<std::size_t>
        {
            if (WriteMode_)
            {
                Error = std::make_error_code(std::errc::connection_reset);
                co_return Data_.size();
            }
            Error = std::make_error_code(std::errc::broken_pipe);
            co_return 0;
        }
        Net::any_io_executor Ex_;
        std::array<std::byte, 2> Data_{std::byte{0xA1}, std::byte{0xA2}};
        std::size_t ReadCalls_{0};
        bool WriteMode_{false};
        bool Consumed_{false};
        bool Closed_{false};
    };

    /** @brief 先交付有效前缀，再返回带 reset cause 的非法 overreport。 */
    class ExactIoOverreportTransport final : public Prism::Transmission
    {
    public:
        enum class Mode : std::uint8_t
        {
            AfterValidPrefix,
            FirstRead,
            FirstWrite
        };

        explicit ExactIoOverreportTransport(
            Net::any_io_executor Executor,
            Mode OverreportMode = Mode::AfterValidPrefix)
            : Prism::Transmission(Executor), Executor_(std::move(Executor)),
              OverreportMode_(OverreportMode)
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_;
        }

        [[nodiscard]] auto Written() const noexcept -> std::span<const std::uint8_t>
        {
            return Written_;
        }

        [[nodiscard]] auto ReadCalls() const noexcept -> std::size_t
        {
            return ReadCalls_;
        }

        [[nodiscard]] auto WriteCalls() const noexcept -> std::size_t
        {
            return WriteCalls_;
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadCalls_;
            if (ReadCalls_ == 1U && OverreportMode_ == Mode::FirstRead)
            {
                Prism::Transmission::PostResult(
                    Executor_, std::move(Handler), {Buffer.size() + 1U, ResetFailure()});
                return;
            }
            const auto Count = (std::min)(Buffer.size(), std::size_t{2});
            if (ReadCalls_ == 1U)
            {
                std::fill_n(Buffer.begin(), Count, std::byte{0xA1});
                Prism::Transmission::PostResult(Executor_, std::move(Handler), {Count, {}});
                return;
            }
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), {Buffer.size() + 1U, ResetFailure()});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            ++WriteCalls_;
            if (WriteCalls_ == 1U && OverreportMode_ == Mode::FirstWrite)
            {
                Prism::Transmission::PostResult(
                    Executor_, std::move(Handler), {Buffer.size() + 1U, ResetFailure()});
                return;
            }
            const auto Count = (std::min)(Buffer.size(), std::size_t{2});
            if (WriteCalls_ == 1U)
            {
                const auto *First = reinterpret_cast<const std::uint8_t *>(Buffer.data());
                Written_.insert(Written_.end(), First, First + Count);
                Prism::Transmission::PostResult(Executor_, std::move(Handler), {Count, {}});
                return;
            }
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), {Buffer.size() + 1U, ResetFailure()});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor_, std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed_ = true;
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        [[nodiscard]] static auto ResetFailure() -> Fault::Failure
        {
            return Fault::FromNative(std::make_error_code(std::errc::connection_reset));
        }

        Net::any_io_executor Executor_;
        Mode OverreportMode_;
        std::vector<std::uint8_t> Written_;
        std::size_t ReadCalls_{0};
        std::size_t WriteCalls_{0};
        bool Closed_{false};
    };
} // namespace

TEST(CommonRead, ExactIoRejectsOverreportedReadWithoutCountingInvalidBytes)
{
    Net::io_context Io;
    auto Raw = std::make_shared<ExactIoOverreportTransport>(Io.get_executor());
    std::array<std::uint8_t, 4> Buffer{};
    Prism::IoResult Result;

    RunCoro(Io, [&]() -> Net::awaitable<void>
    {
        Result = co_await Prism::Protocol::Common::ReadExactIo(Raw, Buffer);
    });

    EXPECT_EQ(Result.Bytes, 2U);
    EXPECT_EQ(Result.Failure.Code, Fault::Code::IoError);
    EXPECT_EQ(Result.Failure.Native, std::make_error_code(std::errc::connection_reset));
    EXPECT_EQ(Buffer[0], 0xA1U);
    EXPECT_EQ(Buffer[1], 0xA1U);
    EXPECT_EQ(Raw->ReadCalls(), 2U);
}

TEST(CommonRead, WriteAllIoRejectsOverreportedWriteWithoutCountingInvalidBytes)
{
    Net::io_context Io;
    auto Raw = std::make_shared<ExactIoOverreportTransport>(Io.get_executor());
    const std::array<std::uint8_t, 4> Buffer{0xB1, 0xB2, 0xB3, 0xB4};
    Prism::IoResult Result;

    RunCoro(Io, [&]() -> Net::awaitable<void>
    {
        Result = co_await Prism::Protocol::Common::WriteAllIo(Raw, Buffer);
    });

    EXPECT_EQ(Result.Bytes, 2U);
    EXPECT_EQ(Result.Failure.Code, Fault::Code::IoError);
    EXPECT_EQ(Result.Failure.Native, std::make_error_code(std::errc::connection_reset));
    EXPECT_EQ(Raw->WriteCalls(), 2U);
    ASSERT_EQ(Raw->Written().size(), 2U);
    EXPECT_EQ(Raw->Written()[0], Buffer[0]);
    EXPECT_EQ(Raw->Written()[1], Buffer[1]);
}

TEST(CommonRead, ExactIoRejectsFirstReadOverreportWithoutCountingInvalidBytes)
{
    Net::io_context Io;
    auto Raw = std::make_shared<ExactIoOverreportTransport>(
        Io.get_executor(), ExactIoOverreportTransport::Mode::FirstRead);
    std::array<std::uint8_t, 4> Buffer{};
    Prism::IoResult Result;

    RunCoro(Io, [&]() -> Net::awaitable<void>
    {
        Result = co_await Prism::Protocol::Common::ReadExactIo(Raw, Buffer);
    });

    EXPECT_EQ(Result.Bytes, 0U);
    EXPECT_EQ(Result.Failure.Code, Fault::Code::IoError);
    EXPECT_EQ(Result.Failure.Native, std::make_error_code(std::errc::connection_reset));
    EXPECT_EQ(Raw->ReadCalls(), 1U);
}

TEST(CommonRead, WriteAllIoRejectsFirstWriteOverreportWithoutCountingInvalidBytes)
{
    Net::io_context Io;
    auto Raw = std::make_shared<ExactIoOverreportTransport>(
        Io.get_executor(), ExactIoOverreportTransport::Mode::FirstWrite);
    const std::array<std::uint8_t, 4> Buffer{0xB1, 0xB2, 0xB3, 0xB4};
    Prism::IoResult Result;

    RunCoro(Io, [&]() -> Net::awaitable<void>
    {
        Result = co_await Prism::Protocol::Common::WriteAllIo(Raw, Buffer);
    });

    EXPECT_EQ(Result.Bytes, 0U);
    EXPECT_EQ(Result.Failure.Code, Fault::Code::IoError);
    EXPECT_EQ(Result.Failure.Native, std::make_error_code(std::errc::connection_reset));
    EXPECT_EQ(Raw->WriteCalls(), 1U);
    EXPECT_TRUE(Raw->Written().empty());
}

TEST(CommonRead, RejectsOverreportedReadMin)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PrismMockTransport>(Io.get_executor());
        Raw->OverreportRead = true;
        std::array<std::byte, 4> Buffer{};

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto [Code, Count] = co_await Prism::Protocol::Common::ReadMin(*Raw, Buffer, 2);
                    EXPECT_EQ(Code, Fault::Code::IoError);
                    EXPECT_EQ(Count, 0U);
                });
    }

TEST(CommonRead, PreservesPartialReadCountWhenReadMinReturnsError)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PartialErrorTransport>(Io.get_executor());
        std::array<std::byte, 2> Buffer{};

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto [Code, Count] = co_await Prism::Protocol::Common::ReadMin(*Raw, Buffer, 2);
                    EXPECT_EQ(Code, Fault::Code::ConnectionReset);
                    EXPECT_EQ(Count, 2U);
                    EXPECT_EQ(Buffer, (std::array<std::byte, 2>{std::byte{0xA1}, std::byte{0xA2}}));
                });
        EXPECT_EQ(Raw->ReadCalls(), 1U);
    }

TEST(CommonRead, RejectsOverreportedReadRemaining)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PrismMockTransport>(Io.get_executor());
        Raw->OverreportRead = true;
        std::array<std::byte, 4> Buffer{};

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto [Code, Count] = co_await Prism::Protocol::Common::ReadRemaining(
                        Prism::Protocol::Common::RemainingOpts{*Raw, Buffer, 0, 2});
                    EXPECT_EQ(Code, Fault::Code::IoError);
                    EXPECT_EQ(Count, 0U);
        });
    }

TEST(CommonRead, PreservesPartialReadCountWhenReadRemainingReturnsError)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PartialErrorTransport>(Io.get_executor());
        std::array<std::byte, 2> Buffer{};

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto [Code, Count] = co_await Prism::Protocol::Common::ReadRemaining(
                        Prism::Protocol::Common::RemainingOpts{*Raw, Buffer, 0, 2});
                    EXPECT_EQ(Code, Fault::Code::ConnectionReset);
                    EXPECT_EQ(Count, 2U);
                    EXPECT_EQ(Buffer, (std::array<std::byte, 2>{std::byte{0xA1}, std::byte{0xA2}}));
                });
        EXPECT_EQ(Raw->ReadCalls(), 1U);
    }

TEST(CommonRead, TransmissionAsyncReadPreservesPartialCountWhenReturningError)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PartialErrorTransport>(Io.get_executor());
        std::array<std::byte, 2> Buffer{};
        std::error_code Error;
        std::size_t Count = 0;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Result = co_await Raw->ReadExact(Buffer);
                    Error = Prism::Fault::ToNative(Result.Failure);
                    Count = Result.Bytes;
                });

        EXPECT_EQ(Count, 2U);
        EXPECT_EQ(Error, std::make_error_code(std::errc::connection_reset));
    }

TEST(CommonRead, TransmissionAsyncWritePreservesPartialCountWhenReturningError)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PartialErrorTransport>(Io.get_executor(), true);
        const std::array<std::byte, 2> Buffer{std::byte{0xB1}, std::byte{0xB2}};
        std::error_code Error;
        std::size_t Count = 0;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Result = co_await Raw->WriteExact(Buffer);
                    Error = Prism::Fault::ToNative(Result.Failure);
                    Count = Result.Bytes;
                });

        EXPECT_EQ(Count, 2U);
        EXPECT_EQ(Error, std::make_error_code(std::errc::connection_reset));
    }

TEST(CommonRead, RejectsInvalidReadWindowBeforeSubspan)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PrismMockTransport>(Io.get_executor());
        std::array<std::byte, 4> Buffer{};

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto [Code, Count] = co_await Prism::Protocol::Common::ReadRemaining(
                        Prism::Protocol::Common::RemainingOpts{*Raw, Buffer, 5, 5});
                    EXPECT_EQ(Code, Fault::Code::IoError);
                    EXPECT_EQ(Count, 5U);
                    EXPECT_EQ(Raw->ReadsDone, 0U);
                });
    }
