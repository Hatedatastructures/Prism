/**
 * @file ResolvedSecrets.hpp
 * @brief Preview 配置 generation 的安全 SecretRef 存储。
 * @details 只拥有零化字节，并通过只读视图提供查找结果。
 */
#pragma once

#include <Preview/Account/SecureBytes.hpp>

#include <cstddef>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace Preview::Application::Configuration
{

    class GenerationBuilder;

    /** @brief 已解析 SecretRef 的不可变存储。 */
    class ResolvedSecrets final
    {
    public:
        using View = std::span<const std::byte>;

        ResolvedSecrets() = default;
        ResolvedSecrets(const ResolvedSecrets &) = delete;
        auto operator=(const ResolvedSecrets &) -> ResolvedSecrets & = delete;
        ResolvedSecrets(ResolvedSecrets &&) = delete;
        auto operator=(ResolvedSecrets &&) -> ResolvedSecrets & = delete;

        /**
         * @brief 按引用名查找解析后的字节视图。
         * @param Reference SecretRef 名称
         * @return 只读秘密字节；未找到时为空视图
         */
        [[nodiscard]] auto Lookup(std::string_view Reference) const -> View
        {
            const auto It = Values_.find(std::string(Reference));
            if (It == Values_.end())
            {
                return {};
            }
            return It->second.View();
        }

    private:
        friend class GenerationBuilder;

        auto Add(std::string Reference, Preview::Account::SecureBytes Value) -> void
        {
            Values_.try_emplace(std::move(Reference), std::move(Value));
        }

        std::map<std::string, Preview::Account::SecureBytes> Values_;
    };

} // namespace Preview::Application::Configuration
