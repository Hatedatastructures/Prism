/**
 * @file CommonReadTest.cpp
 * @brief Prism Common Read 窗口和部分错误契约测试。
 */

#include <gtest/gtest.h>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <array>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <system_error>
#include <vector>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Common/Read.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>

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
            Prism::Transport::Detail::PostResult(Ex_, std::move(Handler), {});
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
                Prism::Transport::Detail::ConfigureIo(Operation);
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
                Prism::Transport::Detail::ConfigureIo(Operation);
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
        bool WriteMode_{false};
        bool Consumed_{false};
        bool Closed_{false};
    };
} // namespace

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
