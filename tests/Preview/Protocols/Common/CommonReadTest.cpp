/**
 * @file CommonReadTest.cpp
 * @brief Preview Common Read 窗口和部分错误契约测试。
 */

#include <gtest/gtest.h>
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
#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Common/Read.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Fault = Preview::Fault;
    using Preview::PreviewMockTransport;

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

class PartialErrorTransport final : public Preview::Transmission
    {
    public:
        explicit PartialErrorTransport(Net::any_io_executor Ex, const bool WriteMode = false)
            : Preview::Transmission(Ex), Ex_(std::move(Ex)), WriteMode_(WriteMode)
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
            Net::async_initiate<Completion, void(Preview::IoResult)>(
                Net::co_composed<void(Preview::IoResult)>(ReadWork{}, Ex_), Handler,
                ReadInput{std::static_pointer_cast<PartialErrorTransport>(
                              Preview::Transmission::shared_from_this()),
                          Buffer});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Preview::IoResult)>(
                Net::co_composed<void(Preview::IoResult)>(WriteWork{}, Ex_), Handler,
                WriteInput{std::static_pointer_cast<PartialErrorTransport>(
                               Preview::Transmission::shared_from_this()),
                           Buffer});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(std::move(Handler), {});
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
                Preview::Transport::Detail::ConfigureIo(Operation);
                std::error_code Error;
                const auto Count = co_await Input.Owner->ReadPartial(Input.Buffer, Error);
                co_return std::tuple{Preview::IoResult{Count, Preview::Fault::FromNative(Error)}};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                std::error_code Error;
                const auto Count = co_await Input.Owner->WritePartial(Input.Buffer, Error);
                co_return std::tuple{Preview::IoResult{Count, Preview::Fault::FromNative(Error)}};
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
        auto Raw = std::make_shared<PreviewMockTransport>(Io.get_executor());
        Raw->OverreportRead = true;
        std::array<std::byte, 4> Buffer{};

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto [Code, Count] = co_await Preview::Protocol::Common::ReadMin(*Raw, Buffer, 2);
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
                    const auto [Code, Count] = co_await Preview::Protocol::Common::ReadMin(*Raw, Buffer, 2);
                    EXPECT_EQ(Code, Fault::Code::ConnectionReset);
                    EXPECT_EQ(Count, 2U);
                    EXPECT_EQ(Buffer, (std::array<std::byte, 2>{std::byte{0xA1}, std::byte{0xA2}}));
                });
    }

TEST(CommonRead, RejectsOverreportedReadRemaining)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PreviewMockTransport>(Io.get_executor());
        Raw->OverreportRead = true;
        std::array<std::byte, 4> Buffer{};

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto [Code, Count] = co_await Preview::Protocol::Common::ReadRemaining(
                        Preview::Protocol::Common::RemainingOpts{*Raw, Buffer, 0, 2});
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
                    const auto [Code, Count] = co_await Preview::Protocol::Common::ReadRemaining(
                        Preview::Protocol::Common::RemainingOpts{*Raw, Buffer, 0, 2});
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
                    Error = Preview::Fault::ToNative(Result.Failure);
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
                    Error = Preview::Fault::ToNative(Result.Failure);
                    Count = Result.Bytes;
                });

        EXPECT_EQ(Count, 2U);
        EXPECT_EQ(Error, std::make_error_code(std::errc::connection_reset));
    }

TEST(CommonRead, RejectsInvalidReadWindowBeforeSubspan)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PreviewMockTransport>(Io.get_executor());
        std::array<std::byte, 4> Buffer{};

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto [Code, Count] = co_await Preview::Protocol::Common::ReadRemaining(
                        Preview::Protocol::Common::RemainingOpts{*Raw, Buffer, 5, 5});
                    EXPECT_EQ(Code, Fault::Code::IoError);
                    EXPECT_EQ(Count, 5U);
                    EXPECT_EQ(Raw->ReadsDone, 0U);
                });
    }
