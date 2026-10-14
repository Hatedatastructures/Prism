/**
 * @file HttpTestSupport.hpp
 * @brief HTTP/1 测试共享的有界资源、typed I/O 与生命周期 owner。
 * @details 每个异步用例在原 executor 上运行协程；结束或异常后对其声明的共享传输
 *          依次取消、关闭并等待 Activity Drain。测试 I/O 先记录已完成字节，再处理失败。
 */
#pragma once

#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace Preview::Testing::Http11
{
    namespace Net = boost::asio;
    using SharedTransmission = Preview::SharedTransmission;
    using IoFailure = Preview::Fault::Failure;
    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    /** @brief 两个真正共享拥有的 MemoryStream 端点。 */
    struct MemoryPair final
    {
        std::shared_ptr<Preview::MemoryStream> First;
        std::shared_ptr<Preview::MemoryStream> Second;
    };

    /** @brief 一项 co_spawn 子任务及其单次完成通知。 */
    struct TaskState final
    {
        std::shared_ptr<CompletionChannel> Done;
        std::shared_ptr<std::exception_ptr> Exception;
        std::shared_ptr<bool> CompletionAccepted;
    };

    /** @brief 一次关闭尝试的三个独立真实结果。 */
    struct TransmissionCloseResult final
    {
        Preview::Transmission::ControlResult Cancel;
        Preview::Transmission::ControlResult Close;
        Preview::Transmission::ControlResult Drain;
    };

    /** @brief 完整读取的真实字节与本次终止 typed failure；EOF 不折叠成成功。 */
    struct ReadUntilEofResult final
    {
        std::string Bytes;
        IoFailure Failure;
    };

    /** @brief exact 写入的已完成字节数及唯一终态。 */
    struct WriteCheckResult final
    {
        std::size_t Bytes{0};
        std::error_code Error;
    };

    /** @brief ReadSome 结果已完成字节数及对应终态。 */
    struct ReadCheckResult final
    {
        std::size_t Bytes{0};
        std::error_code Error;
    };

    /** @brief 为一个 HTTP fixture 显式创建并共享有界字节池。 */
    [[nodiscard]] inline auto MakeBytePool() -> std::shared_ptr<Preview::Memory::BytePool>
    {
        return std::make_shared<Preview::Memory::BytePool>(
            Preview::Memory::BytePoolOptions{64U * 1024U, 64U});
    }

    /** @brief 以 shared_ptr 持有配对端点，满足 Transmission 的异步 self owner 合同。 */
    [[nodiscard]] inline auto MakeOwnedMemoryPair(Net::any_io_executor Executor) -> MemoryPair
    {
        auto [FirstValue, SecondValue] = Preview::MakeMemoryPair(std::move(Executor));
        return {std::make_shared<Preview::MemoryStream>(std::move(FirstValue)),
                std::make_shared<Preview::MemoryStream>(std::move(SecondValue))};
    }

    /** @brief 启动一项由共享完成通道观测的协程任务。 */
    template <typename Awaitable>
    [[nodiscard]] auto SpawnTask(Net::any_io_executor Executor, Awaitable Operation) -> TaskState
    {
        TaskState State;
        State.Done = std::make_shared<CompletionChannel>(Executor, 1U);
        State.Exception = std::make_shared<std::exception_ptr>();
        State.CompletionAccepted = std::make_shared<bool>(false);
        auto Completion = [State](std::exception_ptr ErrorValue) -> void
        {
            *State.Exception = std::move(ErrorValue);
            *State.CompletionAccepted = static_cast<bool>(
                State.Done->try_send(boost::system::error_code{}));
        };
        Net::co_spawn(std::move(Executor), std::move(Operation), std::move(Completion));
        return State;
    }

    /** @brief 等待子任务退栈，通道错误作为测试失败值呈现，致命异常继续传播。 */
    inline auto WaitForTask(TaskState State) -> Net::awaitable<void>
    {
        boost::system::error_code WaitError;
        (void)co_await State.Done->async_receive(
            Net::redirect_error(Net::use_awaitable, WaitError));
        if (WaitError)
        {
            ADD_FAILURE() << "HTTP fixture completion channel failed: " << WaitError.message();
            co_return;
        }
        EXPECT_TRUE(*State.CompletionAccepted) << "HTTP fixture completion was not queued";
        if (*State.Exception)
        {
            std::rethrow_exception(*State.Exception);
        }
    }

    /** @brief 将 typed exact-write 结果拆成已完成字节和错误，不丢同次 partial bytes。 */
    [[nodiscard]] inline auto InspectExactWrite(
        const Preview::IoResult &Result,
        const std::size_t ExpectedBytes) -> WriteCheckResult
    {
        WriteCheckResult Checked{Result.Bytes, {}};
        if (Result.Bytes > ExpectedBytes)
        {
            Checked.Error = std::make_error_code(std::errc::protocol_error);
            return Checked;
        }
        if (Result.Failure.Failed())
        {
            Checked.Error = Preview::Fault::ToNative(Result.Failure);
            return Checked;
        }
        if (Result.Bytes != ExpectedBytes)
        {
            Checked.Error = std::make_error_code(std::errc::io_error);
        }
        return Checked;
    }

    /** @brief 将协程半关闭结果保留为原生错误值。 */
    [[nodiscard]] inline auto InspectControl(
        const Preview::Transmission::ControlResult &Result) -> std::error_code
    {
        if (Result)
        {
            return {};
        }
        return Preview::Fault::ToNative(Result.error());
    }

    /** @brief 保留一次 ReadSome 的已完成字节，再转换其唯一 typed failure。 */
    inline auto CaptureRead(
        ReadUntilEofResult &Capture,
        const Preview::IoResult &Result,
        std::span<const std::byte> Buffer) -> void
    {
        if (Result.Bytes > Buffer.size())
        {
            Capture.Failure = Preview::Fault::FromNative(
                std::make_error_code(std::errc::protocol_error));
            return;
        }
        if (Result.Bytes != 0U)
        {
            Capture.Bytes.append(
                reinterpret_cast<const char *>(Buffer.data()), Result.Bytes);
        }
        Capture.Failure = Result.Failure;
    }

    /** @brief 将 ReadSome 的有效字节先追加到捕获，再返回同次失败。 */
    [[nodiscard]] inline auto AppendRead(
        std::string &Output,
        const Preview::IoResult &Result,
        std::span<const std::byte> Buffer) -> ReadCheckResult
    {
        if (Result.Bytes > Buffer.size())
        {
        return {Result.Bytes, std::make_error_code(std::errc::protocol_error)};
        }
        if (Result.Bytes != 0U)
        {
            Output.append(reinterpret_cast<const char *>(Buffer.data()), Result.Bytes);
        }
        return {Result.Bytes, Preview::Fault::ToNative(Result.Failure)};
    }

    /** @brief 顺序读取直到 EOF；先累计当前 completion 的字节，再结束或报告其他失败。 */
    [[nodiscard]] inline auto ReadUntilEof(SharedTransmission Transport)
        -> Net::awaitable<ReadUntilEofResult>
    {
        ReadUntilEofResult Result;
        if (!Transport)
        {
            Result.Failure = Preview::Fault::FromNative(
                std::make_error_code(std::errc::bad_file_descriptor));
            co_return Result;
        }
        std::array<std::byte, 64> Buffer{};
        while (true)
        {
            const auto Part = co_await Transport->ReadSome(Buffer);
            CaptureRead(Result, Part, Buffer);
            if (Part.Bytes > Buffer.size())
            {
                co_return Result;
            }
            if (Part.Bytes == 0U && !Part.Failure.Failed())
            {
                Result.Failure = IoFailure{Preview::Fault::Code::WouldBlock};
                co_return Result;
            }
            if (Part.Failure.Failed())
            {
                Result.Failure = Part.Failure;
                co_return Result;
            }
        }
    }

    /** @brief 请求 Cancel、Close 并等待真实 activity 退栈，分别保留每项结果。 */
    [[nodiscard]] inline auto CloseTransmission(SharedTransmission Transport)
        -> Net::awaitable<TransmissionCloseResult>
    {
        if (!Transport)
        {
            const Preview::Fault::Failure Failure{Preview::Fault::Code::InvalidArgument};
            co_return TransmissionCloseResult{
                std::unexpected(Failure), std::unexpected(Failure), std::unexpected(Failure)};
        }
        auto CancelResult = Transport->Cancel();
        auto CloseResult = Transport->Close();
        auto DrainResult = co_await Transport->Activity()->Drain();
        co_return TransmissionCloseResult{
            std::move(CancelResult), std::move(CloseResult), std::move(DrainResult)};
    }

    /** @brief 将控制拒绝和 Drain 失败分别转成 GoogleTest 断言。 */
    inline auto CheckTransmissionClose(const TransmissionCloseResult &Result) -> void
    {
        if (!Result.Cancel)
        {
            ADD_FAILURE() << "Cancel rejected: "
                          << Preview::Fault::ToNative(Result.Cancel.error()).message();
        }
        if (!Result.Close)
        {
            ADD_FAILURE() << "Close rejected: "
                          << Preview::Fault::ToNative(Result.Close.error()).message();
        }
        if (!Result.Drain)
        {
            ADD_FAILURE() << "Activity Drain failed: "
                          << Preview::Fault::ToNative(Result.Drain.error()).message();
        }
    }

    /** @brief 在当前 io_context 完整驱动一次传输的 Cancel、Close 与 Drain。 */
    [[nodiscard]] inline auto DriveCloseTransmission(
        Net::io_context &Context,
        SharedTransmission Transport) -> TransmissionCloseResult
    {
        if (Context.stopped())
        {
            Context.restart();
        }
        std::exception_ptr Fatal;
        bool Completed = false;
        TransmissionCloseResult Result;
        auto Completion = [&Fatal, &Completed, &Result](
                              std::exception_ptr ErrorValue,
                              TransmissionCloseResult Value) -> void
        {
            Fatal = std::move(ErrorValue);
            Result = std::move(Value);
            Completed = true;
        };
        Net::co_spawn(Context, CloseTransmission(std::move(Transport)), std::move(Completion));
        Context.run();
        if (Fatal)
        {
            std::rethrow_exception(Fatal);
        }
        EXPECT_TRUE(Completed) << "HTTP fixture close coroutine did not complete";
        return Result;
    }

    /** @brief 运行测试协程；completion 不 stop executor，也不丢排队的 close/drain 工作。 */
    template <typename Awaitable>
    auto RunCoroutine(Net::io_context &Context, Awaitable Operation) -> void
    {
        std::exception_ptr Fatal;
        auto Completion = [&Fatal](std::exception_ptr ErrorValue) -> void
        {
            Fatal = std::move(ErrorValue);
        };
        Net::co_spawn(Context, std::move(Operation), std::move(Completion));
        Context.run();
        if (Fatal)
        {
            std::rethrow_exception(Fatal);
        }
    }

    /** @brief 运行用户协程，再关闭并排空列出的共享传输。 */
    template <typename Awaitable>
    auto RunOwnedCaseRoot(
        Awaitable Operation,
        std::vector<SharedTransmission> Transports,
        std::shared_ptr<std::exception_ptr> Fatal) -> Net::awaitable<void>
    {
        try
        {
            co_await std::move(Operation);
        }
        catch (...)
        {
            *Fatal = std::current_exception();
        }
        std::exception_ptr CleanupFatal;
        for (const auto &Transport : Transports)
        {
            try
            {
                CheckTransmissionClose(co_await CloseTransmission(Transport));
            }
            catch (...)
            {
                if (!CleanupFatal)
                {
                    CleanupFatal = std::current_exception();
                }
            }
        }
        if (!*Fatal && CleanupFatal)
        {
            *Fatal = std::move(CleanupFatal);
        }
        if (*Fatal)
        {
            std::rethrow_exception(*Fatal);
        }
    }

    /** @brief 在测试协程结束后关闭并排空本用例的传输 owner。 */
    template <typename Awaitable>
    auto RunOwnedCase(
        Net::io_context &Context,
        std::vector<SharedTransmission> Transports,
        Awaitable Operation) -> void
    {
        auto Fatal = std::make_shared<std::exception_ptr>();
        auto Completion = [Fatal](std::exception_ptr ErrorValue) -> void
        {
            if (ErrorValue && !*Fatal)
            {
                *Fatal = std::move(ErrorValue);
            }
        };
        Net::co_spawn(Context,
            RunOwnedCaseRoot(std::move(Operation), std::move(Transports), Fatal),
            std::move(Completion));
        Context.run();
        if (*Fatal)
        {
            std::rethrow_exception(*Fatal);
        }
    }

    /** @brief 使用两个共享内存端点运行用例并完整关闭双方。 */
    template <typename Awaitable>
    auto RunMemoryCase(
        Net::io_context &Context,
        const MemoryPair &Pair,
        Awaitable Operation) -> void
    {
        RunOwnedCase(Context, {Pair.First, Pair.Second}, std::move(Operation));
    }
}
