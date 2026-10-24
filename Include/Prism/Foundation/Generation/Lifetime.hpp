/** @file Lifetime.hpp @brief 配置代次的材料保活与唯一活动预约。 */
#pragma once
#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>
#include <utility>

namespace Prism::Foundation
{
    /** @brief 只暴露代次标识；无服务查找或 I/O，由最后一个共享 owner 释放。 */
    class GenerationLifetime
    {
    public:
        virtual ~GenerationLifetime() = default;
        [[nodiscard]] virtual auto Id() const noexcept -> Prism::GenerationId = 0;
    };
    using GenerationPin = std::shared_ptr<const GenerationLifetime>;

    class GenerationUseState;

    /**
     * @brief 可移动、不可复制的单次活动预约；移动交接不分配、不增加活动计数。
     * @details 不拥有 generation 服务图，仅保活活动计数 owner。取消或半关闭不归还预约；
     *          持有预约的 packet、association 或 root 在实际退栈后释放或移动清空。
     *          释放不访问 executor，任意线程析构都精确归还一次。
     */
    class GenerationUseLease final
    {
    public:
        GenerationUseLease() noexcept = default;
        ~GenerationUseLease() noexcept;
        GenerationUseLease(const GenerationUseLease&) = delete;
        auto operator=(const GenerationUseLease&) -> GenerationUseLease& = delete;
        GenerationUseLease(GenerationUseLease&&) noexcept = default;
        auto operator=(GenerationUseLease&& Other) noexcept -> GenerationUseLease&;

        [[nodiscard]] explicit operator bool() const noexcept
        {
            return Owner_ != nullptr;
        }

    private:
        friend class GenerationUseState;
        explicit GenerationUseLease(std::shared_ptr<GenerationUseState> Owner) noexcept;
        auto Release() noexcept -> void;
        std::shared_ptr<GenerationUseState> Owner_;
    };

    /** @brief 独立代次活动计数，不反向拥有快照、服务或目录。 */
    class GenerationUseState final : public std::enable_shared_from_this<GenerationUseState>
    {
    public:
        /**
         * @brief 原子取得一次活动预约；仅复制已存在的 owner 控制块，不创建 ticket。
         * @return 已封止、计数额度耗尽或此状态没有共享 owner 时返回 ResourceUnavailable。
         * @note 同步操作不执行 I/O、取消或关闭，无 executor 要求；CAS 与封止操作互斥。
         */
        [[nodiscard]] auto Acquire() noexcept
            -> std::expected<GenerationUseLease, Prism::Fault::Failure>;

        /** @brief 无活动预约时原子封止新准入；活动仍在途则不改变准入状态。 */
        [[nodiscard]] auto CloseAdmissionIfUnused() noexcept -> bool;

        [[nodiscard]] auto AdmissionOpen() const noexcept -> bool
        {
            return (State_.load(std::memory_order_acquire) & AdmissionClosed) == 0U;
        }

        [[nodiscard]] auto Outstanding() const noexcept -> std::uint64_t
        {
            return State_.load(std::memory_order_acquire) & UseCountMask;
        }

    private:
        friend class GenerationUseLease;
        static constexpr std::uint64_t AdmissionClosed{std::uint64_t{1} << 63U};
        static constexpr std::uint64_t UseCountMask{AdmissionClosed - 1U};
        auto Release() noexcept -> void;
        std::atomic<std::uint64_t> State_{0U};
    };

}
