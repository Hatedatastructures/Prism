/** @file CarrierCatalogOwner.hpp @brief 类型化 carrier 回调目录的最终关闭与退休契约。 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/awaitable.hpp>

#include <expected>

namespace Prism::Contract
{
    /** @brief 已发布回调及其捕获资源的唯一 owner，物理退休由 Close 与 Drain 回执共同确认。
     * @details 调用者保活 owner 至 Drain 返回；取消不提前释放尚在执行的回调，
     *          本契约没有流方向半关闭。最终关闭者为具体目录 owner，各回调仍在其绑定 executor 执行。
     */
    class CarrierCatalogOwner
    {
    public:
        virtual ~CarrierCatalogOwner() = default;

        /** @brief 封止新回调准入；在途回调必须继续保活并真实退栈。 */
        virtual auto Close() noexcept -> void = 0;

        /** @brief 等待真实回调帧退栈并释放捕获资源；失败完整保留 Code 与 Native，未知资源继续持有。 */
        [[nodiscard]] virtual auto Drain()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> = 0;

        /** @brief 仅当已关闭准入、全部回调完成且捕获资源释放后返回 true。 */
        [[nodiscard]] virtual auto IsRetired() const noexcept -> bool = 0;
    };
}
