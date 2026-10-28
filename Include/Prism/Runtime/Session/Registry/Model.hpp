/**
 * @file Model.hpp
 * @brief SessionRegistry 的公开值模型。
 */

#pragma once

#include <Prism/Account/Runtime.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>

#include <cstdint>
#include <string>

namespace Prism::Runtime
{

    /**
     * @struct SessionInfo
     * @brief 会话信息（值语义 POD，快照可整体拷贝）。
     */
    struct SessionInfo
    {
        std::uint64_t Id{0};         ///< 会话 Id
        Prism::AccountId AccountId{}; ///< typed 账户身份
        Prism::Account::AccountRuntimeIdentity AccountRuntime{}; ///< 真实 lease 所属 runtime 身份
        std::string identity{};      ///< 用户标识
        std::string peer{};          ///< 远端地址
        std::string Target{};        ///< 目标地址
        std::uint16_t Protocol{0};   ///< 检测协议
        std::uint64_t StartedAt{0};  ///< steady_clock 原始 tick，仅供进程内耗时，不得对外序列化。
        std::uint64_t StartedAtUnixMilliseconds{0}; ///< TCP accept 的 UTC Unix 毫秒时间戳。
        Prism::WorkerId Worker{};  ///< listener 选定的真实 worker
        Prism::GenerationId Generation{}; ///< 注册所属配置代次
    };

} // namespace Prism::Runtime
