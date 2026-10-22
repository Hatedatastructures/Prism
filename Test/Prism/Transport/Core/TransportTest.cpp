/**
 * @file TransportTest.cpp
 * @brief ReadExact 与 WriteExact 组合算法测试。
 * @details 验证流原语调用、越界进度及 timeout、cancel、native error 结果保留。
 */

#include "TransportResources.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Transport/StreamAlgorithms.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    /** @brief 在本地 io_context 驱动单个算法协程并传播真实异常。 */
    template <typename A>
    auto RunCoro(Net::io_context &Ioc, A Coro) -> void
    {
        std::exception_ptr Exception;
        Ioc.restart();
        Net::co_spawn(Ioc, std::move(Coro),
                      [&](std::exception_ptr Error)
                      {
                          Exception = Error;
                      });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    class AlgorithmStream final : public Prism::Transmission
    {
    public:
        AlgorithmStream(Net::any_io_executor Ex, std::vector<std::uint8_t> Input)
            : Prism::Transmission(Ex), Ex_(std::move(Ex)), Input_(std::move(Input))
        {
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            std::error_code Ec;
            if (!ReadFailureConsumed && ReadFailure)
            {
                ReadFailureConsumed = true;
                const auto Count = (std::min)(ReadFailureBytes, Input_.size() - Offset_);
                if (Count > 0)
                {
                    std::memcpy(Buffer.data(), Input_.data() + Offset_, Count);
                    Offset_ += Count;
                }
                Ec = ReadFailure;
                { std::move(Handler)(Prism::IoResult{Count, Prism::Fault::FromNative(Ec)}); return; }
            }
            const auto Count = (std::min)(Buffer.size(), Input_.size() - Offset_);
            if (Count == 0)
            {
                Ec.clear();
                { std::move(Handler)(Prism::IoResult{0, Prism::Fault::FromNative(Ec)}); return; }
            }
            std::memcpy(Buffer.data(), Input_.data() + Offset_, Count);
            Offset_ += Count;
            Ec.clear();
            if (OverreportRead && Count != 0)
            {
                { std::move(Handler)(Prism::IoResult{Count + 1U, Prism::Fault::FromNative(Ec)}); return; }
            }
            { std::move(Handler)(Prism::IoResult{Count, Prism::Fault::FromNative(Ec)}); return; }
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            std::error_code Ec;
            if (!WriteFailureConsumed && WriteFailure)
            {
                WriteFailureConsumed = true;
                const auto Count = (std::min)(WriteFailureBytes, Buffer.size());
                Ec = WriteFailure;
                { std::move(Handler)(Prism::IoResult{Count, Prism::Fault::FromNative(Ec)}); return; }
            }
            Ec.clear();
            if (OverreportWrite && !Buffer.empty())
            {
                { std::move(Handler)(Prism::IoResult{Buffer.size() + 1U, Prism::Fault::FromNative(Ec)}); return; }
            }
            { std::move(Handler)(Prism::IoResult{Buffer.size(), Prism::Fault::FromNative(Ec)}); return; }
        }

        auto OnClose() -> ControlResult override { Closed_ = true; return {}; }
        auto OnCancel() -> ControlResult override { Canceled_ = true; return {}; }
        [[nodiscard]] auto IsOpen() const -> bool { return !Closed_; }
        [[nodiscard]] auto Executor() const -> Net::any_io_executor { return Ex_; }

    private:
        Net::any_io_executor Ex_;
        std::vector<std::uint8_t> Input_;
        std::size_t Offset_{0};
        bool Closed_{false};
        bool Canceled_{false};

    public:
        bool OverreportRead{false};
        bool OverreportWrite{false};
        std::error_code ReadFailure{};
        std::size_t ReadFailureBytes{0};
        std::error_code WriteFailure{};
        std::size_t WriteFailureBytes{0};

    private:
        bool ReadFailureConsumed{false};
        bool WriteFailureConsumed{false};
        auto StartWriteShutdown(Completion Handler) -> void override { Prism::Transmission::PostResult(Executor(), std::move(Handler), {}); }
    };

    static_assert(Prism::Stream<AlgorithmStream>);

    /**
     * @brief 验证 ReadExact 通过流原语读取完整输入并等待关闭退栈。
     * @param Loop 驱动传输协程和最终 Drain 的执行器。
     * @return 完成读取结果与关闭回执断言的异步操作。
     */
    auto RunAlgorithmReadExactUsesStreamPrimitives(Net::io_context &Loop)
        -> Net::awaitable<void>
    {
        auto TransportOwner84 = std::make_shared<AlgorithmStream>(Loop.get_executor(), std::vector<std::uint8_t>{0x01, 0x02, 0x03});
        auto& Stream = *TransportOwner84;
        std::array<std::uint8_t, 3> Buffer{};
        const auto Ec = (co_await Prism::ReadExact(Stream, Buffer)).Failure;
        EXPECT_TRUE(Ec.Succeeded());
        EXPECT_EQ(Buffer, (std::array<std::uint8_t, 3>{0x01, 0x02, 0x03}));
        const auto CloseReceipt84 = co_await Prism::Testing::CloseFixture(TransportOwner84);
        Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipt84);
    }

    /**
     * @brief 验证 WriteExact 通过流原语提交完整输入并等待关闭退栈。
     * @param Loop 驱动传输协程和最终 Drain 的执行器。
     * @return 完成写入结果与关闭回执断言的异步操作。
     */
    auto RunAlgorithmWriteExactUsesStreamPrimitives(Net::io_context &Loop)
        -> Net::awaitable<void>
    {
        auto TransportOwner83 = std::make_shared<AlgorithmStream>(Loop.get_executor(), std::vector<std::uint8_t>{});
        auto& Stream = *TransportOwner83;
        const std::array<std::uint8_t, 3> Buffer{0x01, 0x02, 0x03};
        const auto Ec = (co_await Prism::WriteExact(Stream, Buffer)).Failure;
        EXPECT_TRUE(Ec.Succeeded());
        const auto CloseReceipt83 = co_await Prism::Testing::CloseFixture(TransportOwner83);
        Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipt83);
    }

    /**
     * @brief 验证 ReadExact 将超报进度映射为 InvalidArgument。
     * @param Loop 驱动传输协程和最终 Drain 的执行器。
     * @return 完成超报错误与关闭回执断言的异步操作。
     */
    auto RunAlgorithmReadExactRejectsOverreport(Net::io_context &Loop)
        -> Net::awaitable<void>
    {
        auto TransportOwner82 = std::make_shared<AlgorithmStream>(Loop.get_executor(), std::vector<std::uint8_t>{0x01, 0x02, 0x03});
        auto& Stream = *TransportOwner82;
        Stream.OverreportRead = true;
        std::array<std::uint8_t, 2> Buffer{};
        const auto Ec = (co_await Prism::ReadExact(Stream, Buffer)).Failure;
        EXPECT_EQ(Ec.Code, Prism::Fault::Code::InvalidArgument);
        const auto CloseReceipt82 = co_await Prism::Testing::CloseFixture(TransportOwner82);
        Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipt82);
    }

    /**
     * @brief 验证 ReadExact 精确保留 timeout 错误分类。
     * @param Ioc 驱动传输协程和最终 Drain 的执行器。
     * @return 完成 timeout 与关闭回执断言的异步操作。
     */
    auto RunAlgorithmReadExactPreservesTimeout(Net::io_context &Ioc)
        -> Net::awaitable<void>
    {
        auto TransportOwner81 = std::make_shared<AlgorithmStream>(Ioc.get_executor(), std::vector<std::uint8_t>{0x01U});
        auto& Stream = *TransportOwner81;
        Stream.ReadFailure = std::make_error_code(std::errc::timed_out);
        std::array<std::uint8_t, 1> Buffer{};
        const auto ErrorCode = (co_await Prism::ReadExact(Stream, Buffer)).Failure;
        EXPECT_EQ(ErrorCode.Code, Prism::Fault::Code::Timeout);
        const auto CloseReceipt81 = co_await Prism::Testing::CloseFixture(TransportOwner81);
        Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipt81);
    }

    /**
     * @brief 验证 ReadExact 精确保留 canceled 错误分类。
     * @param Ioc 驱动传输协程和最终 Drain 的执行器。
     * @return 完成 canceled 与关闭回执断言的异步操作。
     */
    auto RunAlgorithmReadExactPreservesCanceled(Net::io_context &Ioc)
        -> Net::awaitable<void>
    {
        auto TransportOwner80 = std::make_shared<AlgorithmStream>(Ioc.get_executor(), std::vector<std::uint8_t>{0x01U});
        auto& Stream = *TransportOwner80;
        Stream.ReadFailure = std::make_error_code(std::errc::operation_canceled);
        std::array<std::uint8_t, 1> Buffer{};
        const auto ErrorCode = (co_await Prism::ReadExact(Stream, Buffer)).Failure;
        EXPECT_EQ(ErrorCode.Code, Prism::Fault::Code::Canceled);
        const auto CloseReceipt80 = co_await Prism::Testing::CloseFixture(TransportOwner80);
        Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipt80);
    }

    /**
     * @brief 验证 WriteExact 原样保留 broken pipe 的 native 错误。
     * @param Ioc 驱动传输协程和最终 Drain 的执行器。
     * @return 完成 native 错误与关闭回执断言的异步操作。
     */
    auto RunAlgorithmWriteExactPreservesBrokenPipe(Net::io_context &Ioc)
        -> Net::awaitable<void>
    {
        auto TransportOwner79 = std::make_shared<AlgorithmStream>(Ioc.get_executor(), std::vector<std::uint8_t>{});
        auto& Stream = *TransportOwner79;
        Stream.WriteFailure = std::make_error_code(std::errc::broken_pipe);
        const std::array<std::uint8_t, 1> Buffer{0x01U};
        const auto ErrorCode = (co_await Prism::WriteExact(Stream, Buffer)).Failure;
        EXPECT_EQ(ErrorCode.Native, std::make_error_code(std::errc::broken_pipe));
        const auto CloseReceipt79 = co_await Prism::Testing::CloseFixture(TransportOwner79);
        Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipt79);
    }

    /**
     * @brief 验证 WriteExact 将超报进度映射为 InvalidArgument。
     * @param Loop 驱动传输协程和最终 Drain 的执行器。
     * @return 完成超报错误与关闭回执断言的异步操作。
     */
    auto RunAlgorithmWriteExactRejectsOverreport(Net::io_context &Loop)
        -> Net::awaitable<void>
    {
        auto TransportOwner78 = std::make_shared<AlgorithmStream>(Loop.get_executor(), std::vector<std::uint8_t>{});
        auto& Stream = *TransportOwner78;
        Stream.OverreportWrite = true;
        const std::array<std::uint8_t, 2> Buffer{0x01, 0x02};
        const auto Ec = (co_await Prism::WriteExact(Stream, Buffer)).Failure;
        EXPECT_EQ(Ec.Code, Prism::Fault::Code::InvalidArgument);
        const auto CloseReceipt78 = co_await Prism::Testing::CloseFixture(TransportOwner78);
        Prism::Testing::ExpectFixtureCloseReceipt(CloseReceipt78);
    }

    TEST(Transport, AlgorithmReadExactUsesStreamPrimitives)
    {
        Net::io_context Loop;
        RunCoro(Loop, RunAlgorithmReadExactUsesStreamPrimitives(Loop));
    }

    TEST(Transport, AlgorithmWriteExactUsesStreamPrimitives)
    {
        Net::io_context Loop;
        RunCoro(Loop, RunAlgorithmWriteExactUsesStreamPrimitives(Loop));
    }

    TEST(Transport, AlgorithmReadExactRejectsOverreport)
    {
        Net::io_context Loop;
        RunCoro(Loop, RunAlgorithmReadExactRejectsOverreport(Loop));
    }

    TEST(Transport, AlgorithmReadExactPreservesTimeout)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, RunAlgorithmReadExactPreservesTimeout(Ioc));
    }

    TEST(Transport, AlgorithmReadExactPreservesCanceled)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, RunAlgorithmReadExactPreservesCanceled(Ioc));
    }

    TEST(Transport, AlgorithmWriteExactPreservesBrokenPipe)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, RunAlgorithmWriteExactPreservesBrokenPipe(Ioc));
    }

    TEST(Transport, AlgorithmWriteExactRejectsOverreport)
    {
        Net::io_context Loop;
        RunCoro(Loop, RunAlgorithmWriteExactRejectsOverreport(Loop));
    }
} // namespace
