/** @file SinkSet.hpp
 * @brief 单 epoch 的输出策略与共享物理路径 owner 视图。
 */
#pragma once

#include <Preview/Foundation/Utility/Diagnose/Detail/PathSinkOwner.hpp>

#include <atomic>
#include <cstdint>
#include <expected>
#include <iostream>
#include <memory>
#include <string_view>
#include <utility>

namespace Preview::Diagnose::Detail
{
    /** @brief 只保存本 epoch 的 console policy，共享文件句柄由 PathSinkOwner 唯一拥有。 */
    class SinkSet final
    {
    public:
        [[nodiscard]] static auto Create(
            std::shared_ptr<PathSinkOwner> Owner, const bool Console)
            -> std::expected<std::shared_ptr<SinkSet>, BackendError>
        {
            if (!Owner)
            {
                return std::unexpected(BackendError{
                    BackendErrorCode::ResourceUnavailable, {}, "Diagnose path owner is unavailable"});
            }
            return std::shared_ptr<SinkSet>(new SinkSet(std::move(Owner), Console));
        }

        [[nodiscard]] auto Write(
            const LogLevel Level, const std::string_view Payload, const PathWritePolicy &Policy) -> bool
        {
            const auto Owner = Owner_.load(std::memory_order_acquire);
            if (!Owner)
            {
                return false;
            }
            bool Succeeded = Owner->Write(Payload, Policy);
            if (Console_)
            {
                std::cout.write(Payload.data(), static_cast<std::streamsize>(Payload.size()));
                std::cout.put('\n');
                if (!std::cout.good())
                {
                    ConsoleFailures_.fetch_add(1U, std::memory_order_relaxed);
                    Succeeded = false;
                }
            }
            if (Level == LogLevel::Warn || Level == LogLevel::Error || Level == LogLevel::Critical)
            {
                Succeeded = Flush() && Succeeded;
            }
            return Succeeded;
        }

        [[nodiscard]] auto Flush() -> bool
        {
            const auto Owner = Owner_.load(std::memory_order_acquire);
            if (!Owner)
            {
                return false;
            }
            bool Succeeded = Owner->Flush();
            if (Console_)
            {
                const auto ConsoleSucceeded = FlushConsole();
                if (!ConsoleSucceeded)
                {
                    ConsoleFailures_.fetch_add(1U, std::memory_order_relaxed);
                }
                Succeeded = ConsoleSucceeded && Succeeded;
            }
            return Succeeded;
        }

        [[nodiscard]] static auto FlushConsole() -> bool
        {
            std::cout.flush();
            return std::cout.good();
        }

        /** @brief 最终控制 owner 在 worker join 后释放本 epoch 对物理输出的引用。 */
        [[nodiscard]] auto Close() noexcept -> bool
        {
            const auto Owner = Owner_.exchange({}, std::memory_order_acq_rel);
            if (!Owner)
            {
                return CloseSucceeded_.load(std::memory_order_acquire);
            }
            const auto Succeeded = Owner->Close();
            OwnerErrors_.store(Owner->ErrorCount(), std::memory_order_relaxed);
            CloseSucceeded_.store(Succeeded, std::memory_order_release);
            return Succeeded;
        }

        [[nodiscard]] auto Owner() const noexcept -> std::shared_ptr<PathSinkOwner>
        {
            return Owner_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto ConsoleEnabled() const noexcept -> bool
        {
            return Console_;
        }

        [[nodiscard]] auto ConsoleErrors() const noexcept -> std::uint64_t
        {
            return ConsoleFailures_.load(std::memory_order_relaxed);
        }

        [[nodiscard]] auto ErrorCount() const noexcept -> std::uint64_t
        {
            const auto Owner = Owner_.load(std::memory_order_acquire);
            return (Owner ? Owner->ErrorCount() : OwnerErrors_.load(std::memory_order_relaxed)) +
                ConsoleErrors();
        }

    private:
        SinkSet(std::shared_ptr<PathSinkOwner> Owner, const bool Console)
            : Owner_(std::move(Owner)), Console_(Console)
        {
        }

        std::atomic<std::shared_ptr<PathSinkOwner>> Owner_;
        const bool Console_{false};
        std::atomic<std::uint64_t> ConsoleFailures_{0U};
        std::atomic<std::uint64_t> OwnerErrors_{0U};
        std::atomic<bool> CloseSucceeded_{true};
    };
}
