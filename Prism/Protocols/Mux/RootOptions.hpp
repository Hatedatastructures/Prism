/** @file RootOptions.hpp @brief Mux root 的正式 wire、service 与代次选项。 */
#pragma once
#include <Prism/Contract/Services/Stream.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Lifecycle/TaskRegistry.hpp>
#include <Prism/Net/Relay/Relay.hpp>
#include <Prism/Account/Lease.hpp>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string_view>

namespace Prism::Mux
{
    /** @brief 根 wire 类型；Auto 在根接纳后按握手模式选择，不改变 wire 字节。 */
    enum class Mode : std::uint8_t { Auto, Smux, Yamux, H2Mux };

    [[nodiscard]] inline auto ParseMode(const std::string_view Value) noexcept
        -> std::optional<Mode>
    {
        if (Value == "Smux") return Mode::Smux;
        if (Value == "Yamux") return Mode::Yamux;
        if (Value == "H2Mux") return Mode::H2Mux;
        return {};
    }

    [[nodiscard]] inline auto ModeName(const Mode Value) noexcept -> std::string_view
    {
        switch (Value)
        {
        case Mode::Auto: return "Auto";
        case Mode::Smux: return "Smux";
        case Mode::Yamux: return "Yamux";
        case Mode::H2Mux: return "H2Mux";
        }
        return "Unknown";
    }

    /** @brief 已完成子流的正式观察结果；不转移 child 或其资源所有权。 */
    struct ChildReport final
    {
        Prism::Lifecycle::TaskIdentity Identity;
        Prism::Network::Target Target;
        Prism::Network::Relay::Result Relay;
    };

    /**
     * @brief 绑定时固定的 root engine 选项。
     * @details Services、Admission 与 GenerationUseState 属于同一已编译代次；
     *          Observe 只接收已终结的值报告，不拥有任何活动 root/child。
     */
    struct RootOptions final
    {
        Mode Wire{Mode::Auto};
        std::size_t MaxStreams{256};
        Prism::Contract::StreamServices Services;
        Prism::Account::StreamAdmission Admission;
        std::shared_ptr<Prism::Foundation::GenerationUseState> GenerationUseState;
        std::function<void(ChildReport)> Observe;
    };
}
