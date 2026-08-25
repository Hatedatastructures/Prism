/**
 * @file SchemeExecutor.hpp
 * @brief 伪装方案执行器（传输装饰器注册表）
 * @details 将 recognition 识别出的 scheme 名映射为传输包装函数，
 *          在 Session 识别后、协议 Accept 前对 inbound 做 TLS/伪装包装。
 *          对应生产库 handshake::scheme + Recognition::route 的 Preview 化。
 */

#pragma once

#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>

#include <common/Core/Transmission.hpp>

namespace Preview::Recognition
{

    namespace net = boost::asio;

    /**
     * @class SchemeExecutor
     * @brief 伪装方案注册与执行
     * @details 线程安全：注册仅在启动时进行，执行为只读并发。
     */
    class SchemeExecutor
    {
    public:
        /// 方案包装函数：inbound → 包装后传输（失败返回 nullptr）
        using SchemeFn = std::function<net::awaitable<SharedTransmission>(SharedTransmission)>;

        /**
         * @brief 注册方案
         * @param Name 方案名（如 "anytls", "reality"）
         * @param fn 包装函数
         * @return 已存在返回 false
         */
        auto RegisterScheme(std::string Name, SchemeFn fn) -> bool
        {
            return registry_.emplace(std::move(Name), std::move(fn)).second;
        }

        /**
         * @brief 执行方案包装
         * @param scheme 方案名（空表示不包装）
         * @param inbound 待包装传输
         * @return 包装后传输；scheme 为空或未注册返回原 inbound；失败返回 nullptr
         */
        [[nodiscard]] auto Execute(std::string_view scheme, SharedTransmission inbound)
            -> net::awaitable<SharedTransmission>
        {
            if (scheme.empty() || !inbound)
            {
                co_return inbound;
            }
            const auto it = registry_.find(std::string(scheme));
            if (it == registry_.end())
            {
                co_return inbound;
            }
            co_return co_await it->second(std::move(inbound));
        }

        /**
         * @brief 是否已注册某方案
         */
        [[nodiscard]] auto Has(std::string_view scheme) const -> bool
        {
            return registry_.find(std::string(scheme)) != registry_.end();
        }

        /**
         * @brief 已注册方案数
         */
        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return registry_.size();
        }

    private:
        std::unordered_map<std::string, SchemeFn> registry_;
    };

} // namespace Preview::Recognition
