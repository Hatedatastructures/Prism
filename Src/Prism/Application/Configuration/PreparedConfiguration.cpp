/** @file PreparedConfiguration.cpp @brief 配置 secret 解析、清理和结果移交实现。 */
#include <Prism/Application/Configuration/PreparedConfiguration.hpp>
#include <Prism/Application/Configuration/Detail/Secrets.hpp>

#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <utility>

namespace Prism::Application::Configuration
{

    namespace
    {

        auto WipeString(std::string &Value) noexcept -> void
        {
            volatile char *Bytes = Value.data();
            for (std::size_t Index = 0; Index < Value.size(); ++Index)
            {
                Bytes[Index] = '\0';
            }
            Value.clear();
        }

        [[nodiscard]] auto CopySecret(const ResolvedSecrets::View Value)
            -> std::optional<std::string>
        {
            if (Value.empty())
            {
                return std::nullopt;
            }
            return std::string(reinterpret_cast<const char *>(Value.data()), Value.size());
        }

    } // namespace

    auto ResolvedSecrets::Lookup(const std::string_view Reference) const -> View
    {
        const auto It = Values_.find(std::string(Reference));
        if (It == Values_.end())
        {
            return {};
        }
        return It->second.View();
    }

    auto ResolvedSecrets::Add(
        std::string Reference,
        Prism::Account::SecureBytes Value) -> void
    {
        Values_.try_emplace(std::move(Reference), std::move(Value));
    }

    Detail::SensitiveStringWiper::SensitiveStringWiper(std::string &Value) noexcept
        : Value_(&Value)
    {
    }

    Detail::SensitiveStringWiper::~SensitiveStringWiper()
    {
        if (Value_)
        {
            WipeString(*Value_);
        }
    }

    Detail::SensitiveStringMapWiper::SensitiveStringMapWiper(
        std::map<std::string, std::string> &Values) noexcept : Values_(&Values)
    {
    }

    Detail::SensitiveStringMapWiper::~SensitiveStringMapWiper()
    {
        if (Values_)
        {
            for (auto &[Key, Value] : *Values_)
            {
                (void)Key;
                WipeString(Value);
            }
            Values_->clear();
        }
    }

    auto Detail::SensitiveStringMapWiper::Release() noexcept -> void
    {
        Values_ = nullptr;
    }

    Detail::SecretResolutionTransaction::SecretResolutionTransaction(
        std::map<std::string, std::string> &&InlineValues,
        SecretRefResolver::Callback ExternalResolver)
        : ExternalResolver_(std::move(ExternalResolver))
    {
        Detail::SensitiveStringMapWiper Wiper(InlineValues);
        for (auto &[Reference, Value] : InlineValues)
        {
            Detail::SensitiveStringWiper ValueWiper(Value);
            if (!Value.empty())
            {
                InlineValues_.try_emplace(
                    Reference, Prism::Account::SecureBytes(std::string_view(Value)));
            }
        }
    }

    Detail::SecretResolutionTransaction::SecretResolutionTransaction(
        const std::map<std::string, std::string> &InlineValues,
        SecretRefResolver::Callback ExternalResolver)
        : ExternalResolver_(std::move(ExternalResolver))
    {
        for (const auto &[Reference, Value] : InlineValues)
        {
            if (!Value.empty())
            {
                InlineValues_.try_emplace(
                    Reference, Prism::Account::SecureBytes(std::string_view(Value)));
            }
        }
    }

    Detail::SecretResolutionTransaction::~SecretResolutionTransaction()
    {
        Seal();
    }

    auto Detail::SecretResolutionTransaction::Resolve(const std::string_view Reference)
        -> ResolvedSecrets::View
    {
        if (Sealed_)
        {
            return Lookup(Reference);
        }

        auto [It, Inserted] = Resolved_.try_emplace(std::string(Reference));
        if (!Inserted)
        {
            return It->second ? It->second->View() : ResolvedSecrets::View{};
        }

        if (const auto Inline = InlineValues_.find(It->first); Inline != InlineValues_.end())
        {
            if (Inline->second.Size() != 0U)
            {
                It->second.emplace(std::move(Inline->second));
                InlineValues_.erase(Inline);
                return It->second->View();
            }
            InlineValues_.erase(Inline);
        }

        if (!ExternalResolver_)
        {
            return {};
        }

        std::optional<std::string> Value;
        try
        {
            Value = ExternalResolver_(Reference);
        }
        catch (...)
        {
            return {};
        }
        if (!Value)
        {
            return {};
        }

        Detail::SensitiveStringWiper Wiper(*Value);
        if (Value->empty())
        {
            return {};
        }
        It->second.emplace(std::string_view(*Value));
        return It->second->View();
    }

    auto Detail::SecretResolutionTransaction::Lookup(const std::string_view Reference) const
        -> ResolvedSecrets::View
    {
        const auto It = Resolved_.find(std::string(Reference));
        return It != Resolved_.end() && It->second ? It->second->View()
                                                   : ResolvedSecrets::View{};
    }

    auto Detail::SecretResolutionTransaction::Seal() noexcept -> void
    {
        if (Sealed_)
        {
            return;
        }
        InlineValues_.clear();
        ExternalResolver_ = {};
        Sealed_ = true;
    }

    auto Detail::SecretResolutionTransaction::TakeResolvedSecrets()
        -> std::unique_ptr<ResolvedSecrets>
    {
        Seal();
        auto Result = std::make_unique<ResolvedSecrets>();
        for (auto &[Reference, Value] : Resolved_)
        {
            if (Value && Value->Size() != 0U)
            {
                Result->Add(Reference, std::move(*Value));
            }
        }
        Resolved_.clear();
        return Result;
    }

    PreparedConfiguration::PreparedConfiguration(
        PrismConfiguration Configuration,
        std::unique_ptr<Detail::SecretResolutionTransaction> Resolution)
        : Configuration_(std::move(Configuration)), Resolution_(std::move(Resolution))
    {
        Detail::SensitiveStringMapWiper Wiper(Configuration_.Secrets);
    }

    PreparedConfiguration::PreparedConfiguration(PreparedConfiguration &&) noexcept = default;

    auto PreparedConfiguration::operator=(PreparedConfiguration &&) noexcept
        -> PreparedConfiguration & = default;

    PreparedConfiguration::~PreparedConfiguration() = default;

    auto PreparedConfiguration::Resolution() noexcept -> Detail::SecretResolutionTransaction &
    {
        return *Resolution_;
    }

    auto PreparedConfiguration::TakeResolvedSecrets() && -> std::unique_ptr<ResolvedSecrets>
    {
        auto Result = Resolution_->TakeResolvedSecrets();
        Resolution_.reset();
        return Result;
    }

    MapSecretRefResolver::MapSecretRefResolver(std::map<std::string, std::string> Values)
    {
        Detail::SensitiveStringMapWiper Wiper(Values);
        auto State = std::unique_ptr<Detail::SecretResolutionTransaction>(
            new Detail::SecretResolutionTransaction(std::move(Values), SecretRefResolver::Callback{}));
        Resolution_ = std::shared_ptr<Detail::SecretResolutionTransaction>(std::move(State));
    }

    auto MapSecretRefResolver::Resolve(const std::string_view Reference) const
        -> std::optional<std::string>
    {
        return CopySecret(Resolution_->Resolve(Reference));
    }

    auto MapSecretRefResolver::CallbackValue() const -> SecretRefResolver::Callback
    {
        const auto Resolution = Resolution_;
        return [Resolution](const std::string_view Reference)
            -> std::optional<std::string>
        { return CopySecret(Resolution->Resolve(Reference)); };
    }

    auto MakeChainedSecretResolver(std::map<std::string, std::string> InlineValues,
                                   SecretRefResolver::Callback Fallback)
        -> SecretRefResolver::Callback
    {
        Detail::SensitiveStringMapWiper Wiper(InlineValues);
        auto State = std::unique_ptr<Detail::SecretResolutionTransaction>(
            new Detail::SecretResolutionTransaction(std::move(InlineValues), std::move(Fallback)));
        const auto Resolution = std::shared_ptr<Detail::SecretResolutionTransaction>(std::move(State));
        return [Resolution](const std::string_view Reference)
            -> std::optional<std::string>
        { return CopySecret(Resolution->Resolve(Reference)); };
    }

} // namespace Prism::Application::Configuration
