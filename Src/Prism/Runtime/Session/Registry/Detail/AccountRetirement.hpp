/**
 * @file AccountRetirement.hpp
 * @brief AccountRuntime 下会话的拒绝准入、取消与真实退栈协调。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Runtime/Session/Control.hpp>
#include <Prism/Runtime/Session/Registry/Model.hpp>
#include <Prism/Runtime/Session/Registry/Retirement.hpp>
#include <Prism/Runtime/Session/Registry/Storage.hpp>

namespace Prism::Runtime::Detail
{

    /** @brief 拥有 AccountRuntime 退休顺序，确保先封止注册，再取消并等待 owner 退栈。 */
    class SessionRegistryAccountRetirement final
    {
    public:
        [[nodiscard]] static auto CancelAndDrain(
            std::shared_ptr<SessionRegistryState> State,
            const Prism::AccountId Account,
            const Prism::Account::AccountRuntimeIdentity Runtime)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;

        [[nodiscard]] static auto ReleaseGate(
            const std::shared_ptr<SessionRegistryState> &State,
            const Prism::AccountId Account,
            const Prism::Account::AccountRuntimeIdentity Runtime)
            -> std::expected<void, Prism::Fault::Failure>;
    };

} // namespace Prism::Runtime::Detail
