/**
 * @file ActiveTransports.hpp
 * @brief 会话当前传输的跨 executor 所有权快照。
 */
#pragma once

#include <atomic>
#include <memory>
#include <utility>

#include <Preview/Transport/Transmission.hpp>

namespace Preview::Runtime
{

    struct ActiveTransportSnapshot final
    {
        Preview::SharedTransmission Inbound;
        Preview::SharedTransmission Outbound;
    };

    /**
     * @class ActiveTransports
     * @brief 以原子 shared_ptr 发布当前入站/出站传输。
     * @details Session 协程与取消/关闭回调可能运行在不同 executor；
     *          普通 shared_ptr 成员不能被一边赋值、一边复制。
     */
    class ActiveTransports final
    {
    public:
        auto StoreInbound(Preview::SharedTransmission Value) noexcept -> void
        {
            Inbound_.store(std::move(Value), std::memory_order_release);
        }

        auto StoreOutbound(Preview::SharedTransmission Value) noexcept -> void
        {
            Outbound_.store(std::move(Value), std::memory_order_release);
        }

        [[nodiscard]] auto LoadInbound() const noexcept -> Preview::SharedTransmission
        {
            return Inbound_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto LoadOutbound() const noexcept -> Preview::SharedTransmission
        {
            return Outbound_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Load() const noexcept -> ActiveTransportSnapshot
        {
            return ActiveTransportSnapshot{LoadInbound(), LoadOutbound()};
        }

    private:
        std::atomic<Preview::SharedTransmission> Inbound_{};
        std::atomic<Preview::SharedTransmission> Outbound_{};
    };

} // namespace Preview::Runtime
