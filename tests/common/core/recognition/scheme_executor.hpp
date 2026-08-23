/**
 * @file scheme_executor.hpp
 * @brief 伪装方案执行器（传输装饰器注册表）
 * @details 将 recognition 识别出的 scheme 名映射为传输包装函数，
 *          在 session 识别后、协议 accept 前对 inbound 做 TLS/伪装包装。
 *          对应生产库 handshake::scheme + recognition::route 的 preview 化。
 */

#pragma once

#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>

#include <common/core/transmission.hpp>

namespace preview::recognition
{

    namespace net = boost::asio;

    /**
     * @class scheme_executor
     * @brief 伪装方案注册与执行
     * @details 线程安全：注册仅在启动时进行，执行为只读并发。
     */
    class scheme_executor
    {
    public:
        /// 方案包装函数：inbound → 包装后传输（失败返回 nullptr）
        using scheme_fn = std::function<net::awaitable<shared_transmission>(shared_transmission)>;

        /**
         * @brief 注册方案
         * @param name 方案名（如 "anytls", "reality"）
         * @param fn 包装函数
         * @return 已存在返回 false
         */
        auto register_scheme(std::string name, scheme_fn fn) -> bool
        {
            return registry_.emplace(std::move(name), std::move(fn)).second;
        }

        /**
         * @brief 执行方案包装
         * @param scheme 方案名（空表示不包装）
         * @param inbound 待包装传输
         * @return 包装后传输；scheme 为空或未注册返回原 inbound；失败返回 nullptr
         */
        [[nodiscard]] auto execute(std::string_view scheme, shared_transmission inbound)
            -> net::awaitable<shared_transmission>
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
        [[nodiscard]] auto has(std::string_view scheme) const -> bool
        {
            return registry_.find(std::string(scheme)) != registry_.end();
        }

        /**
         * @brief 已注册方案数
         */
        [[nodiscard]] auto size() const noexcept -> std::size_t
        {
            return registry_.size();
        }

    private:
        std::unordered_map<std::string, scheme_fn> registry_;
    };

} // namespace preview::recognition
