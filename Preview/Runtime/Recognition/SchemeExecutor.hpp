/**
 * @file SchemeExecutor.hpp
 * @brief 伪装方案执行器（传输装饰器注册表）
 * @details 将 recognition 识别出的 scheme 名映射为传输包装函数，
 *          在 Session 识别后、协议 Accept 前对 Inbound 做 TLS/伪装包装。
 *          对应生产库 handshake::scheme + Recognition::route 的 Preview 化。
 */

#pragma once

#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>

#include <Preview/Transport/Transmission.hpp>

namespace Preview::Recognition
{

    namespace Net = boost::asio;

    /**
     * @class SchemeExecutor
     * @brief 伪装方案注册与执行
     * @details 线程安全：注册仅在启动时进行，执行为只读并发。
     */
    class SchemeExecutor
    {
    public:
        /// 方案包装函数：Inbound → 包装后传输（失败返回 nullptr）
        using SchemeFn = std::function<Net::awaitable<SharedTransmission>(SharedTransmission)>;

        /**
         * @brief 注册方案
         * @param Name 方案名（如 "anytls", "reality"）
         * @param fn 包装函数
         * @return 已存在返回 false
         */
        auto RegisterScheme(std::string Name, SchemeFn Function) -> bool
        {
            Name = Normalize(Name);
            if (Name.empty() || !Function)
            {
                return false;
            }
            return Registry_.emplace(std::move(Name), std::move(Function)).second;
        }

        /**
         * @brief 执行方案包装
         * @param scheme 方案名（空表示不包装）
         * @param Inbound 待包装传输
         * @return 包装后传输；scheme 为空返回原 Inbound，未注册或执行失败返回 nullptr
         */
        [[nodiscard]] auto Execute(std::string_view Scheme, SharedTransmission Inbound)
            -> Net::awaitable<SharedTransmission>
        {
            if (Scheme.empty() || !Inbound)
            {
                co_return Inbound;
            }
            const auto It = Registry_.find(Normalize(Scheme));
            if (It == Registry_.end())
            {
                co_return SharedTransmission{};
            }
            co_return co_await It->second(std::move(Inbound));
        }

        /**
         * @brief 是否已注册某方案
         */
        [[nodiscard]] auto Has(std::string_view Scheme) const -> bool
        {
            return Registry_.find(Normalize(Scheme)) != Registry_.end();
        }

        /**
         * @brief 已注册方案数
         */
        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return Registry_.size();
        }

    private:
        [[nodiscard]] static auto Normalize(std::string_view Value) -> std::string
        {
            std::string Result;
            Result.reserve(Value.size());
            for (const auto Character : Value)
            {
                const auto Byte = static_cast<unsigned char>(Character);
                auto NormalizedByte = Byte;
                if (Byte >= 'A' && Byte <= 'Z')
                {
                    NormalizedByte = static_cast<unsigned char>(Byte + ('a' - 'A'));
                }
                Result.push_back(static_cast<char>(NormalizedByte));
            }
            return Result;
        }

        std::unordered_map<std::string, SchemeFn> Registry_;
    };

} // namespace Preview::Recognition
