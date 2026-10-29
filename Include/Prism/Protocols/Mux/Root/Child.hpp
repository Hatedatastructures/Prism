/** @file Child.hpp @brief Mux root 子流生命周期操作的窄接口。 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/awaitable.hpp>

#include <memory>

namespace Prism::Mux::Detail
{

    struct RootState;
    struct ChildState;

    /** @brief root 关闭后 retained child 的真实关闭与 Activity 排空结果。 */
    struct RetainedChildDrainReceipt final
    {
        bool Retired{true};
        Prism::Fault::Failure Failure;
    };

    /**
     * @brief 注册并启动单个 wire child 的生命周期 owner。
     * @param DeferStart 为 true 时只登记 child 任务，必须由调用方在 catalog 提交后
     *                   OpenChildStart 才释放数据面；用于 H2 先登记后回 200。
     */
    auto StartChild(
        std::shared_ptr<RootState> Root,
        std::shared_ptr<ChildState> Child,
        bool DeferStart = false) -> bool;

    /** @brief 放行一个已登记 child 的数据面；重复调用无副作用。 */
    auto OpenChildStart(const std::shared_ptr<ChildState> &Child) noexcept -> void;

    /** @brief root engine 退休后排空并释放所有 retained child。 */
    auto DrainRetainedChildren(
        const std::shared_ptr<RootState> &Root,
        bool EngineRetired)
        -> boost::asio::awaitable<RetainedChildDrainReceipt>;

    /** @brief 在多个 child drain 错误中保留首个实质失败。 */
    auto PreserveChildDrainFailure(
        Prism::Fault::Failure &Primary,
        const Prism::Fault::Failure &Next) noexcept -> void;

}
