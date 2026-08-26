/**
 * @file Types.hpp
 * @brief ECH 伪装方案类型定义
 * @details 配置为空结构（ECH 密钥由调用方生成并注入 SSL 上下文）。
 */

#pragma once

#include <common/Core/Memory/Container.hpp>

namespace Preview::Ech
{

    /**
     * @struct Config
     * @brief ECH 方案配置
     * @details 当前无配置项（密钥经 keygen 生成后由调用方注册）。
     */
    struct Config
    {
        /// 方案是否启用（由调用方决定挂载）
        [[nodiscard]] auto Enabled() const noexcept -> bool
        {
            return true;
        }
    };

} // namespace Preview::Ech
