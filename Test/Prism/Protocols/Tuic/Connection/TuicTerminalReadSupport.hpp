/**
 * @file TuicTerminalReadSupport.hpp
 * @brief TUIC 终态读取测试共享的脚本传输与生命周期驱动。
 */
#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Test::TuicTerminalRead
{
    namespace Net = boost::asio;

    struct ReadStep final
    {
        std::vector<std::uint8_t> Bytes{};
        Prism::Fault::Failure Failure{};
    };

    /** @brief 回放 ReadSome 字节；只在完整消费脚本步后交付其 terminal。 */
    class ScriptedTransport final : public Prism::Transmission
    {
    public:
        ScriptedTransport(
            Net::any_io_executor Executor,
            const Type Transport,
            std::deque<ReadStep> ReadSteps)
            : Transmission(Executor),
              Executor_(std::move(Executor)),
              Transport_(Transport),
              ReadSteps_(std::move(ReadSteps))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Transport_;
        }

        std::size_t ReadsDone{0};

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadsDone;
            Prism::IoResult Result{};
            if (ReadSteps_.empty())
            {
                Result.Failure = {Prism::Fault::Code::Eof};
            }
            else
            {
                const auto &Step = ReadSteps_.front();
                const auto Remaining = Step.Bytes.size() - ReadOffset_;
                Result.Bytes = (std::min)(Buffer.size(), Remaining);
                if (Result.Bytes != 0U)
                {
                    std::memcpy(
                        Buffer.data(), Step.Bytes.data() + ReadOffset_, Result.Bytes);
                }
                ReadOffset_ += Result.Bytes;
                if (ReadOffset_ == Step.Bytes.size())
                {
                    Result.Failure = Step.Failure;
                    ReadSteps_.pop_front();
                    ReadOffset_ = 0;
                }
            }
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), Result);
        }

        auto StartWrite(
            std::span<const std::byte> Buffer,
            Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), Prism::IoResult{Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor_, std::move(Handler), {});
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
        Net::any_io_executor Executor_;
        Type Transport_;
        std::deque<ReadStep> ReadSteps_;
        std::size_t ReadOffset_{0};
    };

    inline auto RunCoroutine(
        Net::io_context &IoContext,
        Net::awaitable<void> Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(
            IoContext,
            std::move(Coroutine),
            [&Exception](std::exception_ptr ErrorValue)
            { Exception = std::move(ErrorValue); });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    inline auto DrainActivity(Prism::Transmission &Carrier)
        -> Net::awaitable<bool>
    {
        const auto Activity = Carrier.Activity();
        if (!Activity)
        {
            co_return false;
        }
        const auto Drained = co_await Activity->Drain();
        co_return Drained.has_value() && Activity->IsRetired();
    }

    inline auto CloseAndDrain(Prism::Transmission &Carrier)
        -> Net::awaitable<bool>
    {
        const auto Closed = Carrier.Close();
        if (!Closed)
        {
            co_return false;
        }
        co_return co_await DrainActivity(Carrier);
    }
} // namespace Prism::Test::TuicTerminalRead
