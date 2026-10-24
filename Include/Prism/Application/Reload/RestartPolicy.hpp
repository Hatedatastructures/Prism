/** @file RestartPolicy.hpp @brief 根据真实配置字段差异决定必须重启的字段。 */
#pragma once
#include <Prism/Application/Configuration/PrismConfiguration.hpp>
#include <string>
#include <vector>
namespace Prism::Application::Reload::RestartPolicy
{
    namespace Configuration=Prism::Application::Configuration;
    [[nodiscard]] auto SameListenerShape(
        const std::vector<Configuration::ListenerEndpoint> &Left,
        const std::vector<Configuration::ListenerEndpoint> &Right) noexcept -> bool;
    [[nodiscard]] auto SameQuicEngineKinds(
        const Configuration::PrismConfiguration &Left,
        const Configuration::PrismConfiguration &Right) noexcept -> bool;
    /** @brief 同步借用当前和候选 immutable 配置；本次调用不保存引用。 */
    struct Input final
    {
        const Configuration::PrismConfiguration& Current;
        const Configuration::PrismConfiguration& Candidate;
    };
    /**
     * @brief 唯一重启差异owner；非空结果既是判定也是提供给管理端的实际字段列表。
     * @details 统计 collector 启用状态是 process-scoped；输出仅有字段名称，不含值或 secret。
     *          冷准备可能分配。取消、半关闭、
     *          最终关闭与executor均不适用本同步值计算，不启动任何进程或异步操作。
     */
    [[nodiscard]] auto RestartRequiredFields(const Input Request) -> std::vector<std::string>;
}
