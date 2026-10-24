/**
 * @file Mailbox.hpp
 * @brief Worker 专用固定容量 MPSC mailbox 私有状态。
 */
#pragma once

#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Runtime/GenerationPublication.hpp>
#include <Prism/Runtime/WorkerDispatchResult.hpp>

#include <atomic>
#include <cstddef>
#include <memory>

namespace Prism::Runtime::Detail
{
    class Mailbox final
    {
    public:
        using Command = WorkerDispatchCommand;

        struct Options final
        {
            std::size_t Capacity{64};
            Prism::GenerationId Generation{};
            std::shared_ptr<GenerationPublication> Publication;
        };

        Mailbox();
        explicit Mailbox(Options Value);
        ~Mailbox() noexcept;
        Mailbox(const Mailbox&) = delete;
        auto operator=(const Mailbox&) -> Mailbox& = delete;
        Mailbox(Mailbox&&) = delete;
        auto operator=(Mailbox&&) -> Mailbox& = delete;

        [[nodiscard]] auto Post(Prism::GenerationId Generation, Command CommandValue) noexcept
            -> WorkerDispatchResult;
        [[nodiscard]] auto TryReceive(Command& CommandValue) noexcept -> bool;
        auto Close() noexcept -> void;
        [[nodiscard]] auto IsClosed() const noexcept -> bool;
        [[nodiscard]] auto Capacity() const noexcept -> std::size_t;
        [[nodiscard]] auto Size() const noexcept -> std::size_t;
        [[nodiscard]] auto Generation() const noexcept -> Prism::GenerationId;

    private:
        struct Slot final
        {
            std::atomic<std::size_t> Sequence{0};
            Command Value{};
        };

        const std::size_t Capacity_;
        const Prism::GenerationId Generation_;
        std::shared_ptr<GenerationPublication> Publication_;
        std::unique_ptr<Slot[]> Slots_;
        std::atomic<std::size_t> Head_{0};
        std::atomic<std::size_t> Tail_{0};
        std::atomic<bool> Closed_{false};
    };
}
