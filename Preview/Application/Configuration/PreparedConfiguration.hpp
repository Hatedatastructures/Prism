/**
 * @file PreparedConfiguration.hpp
 * @brief 配置校验阶段到 generation 构造阶段的安全密钥交接。
 */
#pragma once

#include <Preview/Application/Configuration/PreviewConfiguration.hpp>
#include <Preview/Application/Configuration/ResolvedSecrets.hpp>
#include <Preview/Application/Configuration/SecretRefResolver.hpp>

#include <map>
#include <cstddef>
#include <utility>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace Preview::Application::Configuration
{

    class ConfigurationParser;
    class GenerationBuilder;

    namespace Detail
    {

        class SensitiveStringWiper final
        {
        public:
            explicit SensitiveStringWiper(std::string &Value) noexcept;
            ~SensitiveStringWiper();

            SensitiveStringWiper(const SensitiveStringWiper &) = delete;
            auto operator=(const SensitiveStringWiper &) -> SensitiveStringWiper & = delete;

        private:
            std::string *Value_;
        };

        class SensitiveStringMapWiper final
        {
        public:
            explicit SensitiveStringMapWiper(std::map<std::string, std::string> &Values) noexcept;
            ~SensitiveStringMapWiper();

            SensitiveStringMapWiper(const SensitiveStringMapWiper &) = delete;
            auto operator=(const SensitiveStringMapWiper &) -> SensitiveStringMapWiper & = delete;

            auto Release() noexcept -> void;

        private:
            std::map<std::string, std::string> *Values_;
        };

    } // namespace Detail

    class SecretResolutionTransaction final
    {
    public:
        SecretResolutionTransaction(std::map<std::string, std::string> &&InlineValues,
                                    SecretRefResolver::Callback ExternalResolver);
        SecretResolutionTransaction(const std::map<std::string, std::string> &InlineValues,
                                    SecretRefResolver::Callback ExternalResolver);
        ~SecretResolutionTransaction();

        SecretResolutionTransaction(const SecretResolutionTransaction &) = delete;
        auto operator=(const SecretResolutionTransaction &) -> SecretResolutionTransaction & = delete;
        SecretResolutionTransaction(SecretResolutionTransaction &&) = delete;
        auto operator=(SecretResolutionTransaction &&) -> SecretResolutionTransaction & = delete;

        [[nodiscard]] auto Resolve(std::string_view Reference) -> ResolvedSecrets::View;
        [[nodiscard]] auto Lookup(std::string_view Reference) const -> ResolvedSecrets::View;
        auto Seal() noexcept -> void;
        [[nodiscard]] auto TakeResolvedSecrets() -> std::unique_ptr<ResolvedSecrets>;

    private:
        std::map<std::string, Preview::Account::SecureBytes> InlineValues_;
        std::map<std::string, std::optional<Preview::Account::SecureBytes>> Resolved_;
        SecretRefResolver::Callback ExternalResolver_;
        bool Sealed_{false};
    };

    class PreparedConfiguration final
    {
    public:
        PreparedConfiguration(const PreparedConfiguration &) = delete;
        auto operator=(const PreparedConfiguration &) -> PreparedConfiguration & = delete;
        PreparedConfiguration(PreparedConfiguration &&) noexcept = default;
        auto operator=(PreparedConfiguration &&) noexcept -> PreparedConfiguration & = default;
        ~PreparedConfiguration() = default;

        [[nodiscard]] auto Configuration() const noexcept -> const PreviewConfiguration &;

    private:
        friend class ConfigurationParser;
        friend class GenerationBuilder;

        PreparedConfiguration(PreviewConfiguration Configuration,
                              std::unique_ptr<SecretResolutionTransaction> Resolution);
        [[nodiscard]] auto Resolution() noexcept -> SecretResolutionTransaction &;
        [[nodiscard]] auto TakeConfiguration() && -> PreviewConfiguration;
        [[nodiscard]] auto TakeResolvedSecrets() && -> std::unique_ptr<ResolvedSecrets>;

        PreviewConfiguration Configuration_;
        std::unique_ptr<SecretResolutionTransaction> Resolution_;
    };


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

    inline Detail::SensitiveStringWiper::SensitiveStringWiper(std::string &Value) noexcept
        : Value_(&Value)
    {
    }

    inline Detail::SensitiveStringWiper::~SensitiveStringWiper()
    {
        if (Value_)
        {
            WipeString(*Value_);
        }
    }

    inline Detail::SensitiveStringMapWiper::SensitiveStringMapWiper(
        std::map<std::string, std::string> &Values) noexcept : Values_(&Values)
    {
    }

    inline Detail::SensitiveStringMapWiper::~SensitiveStringMapWiper()
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

    inline auto Detail::SensitiveStringMapWiper::Release() noexcept -> void
    {
        Values_ = nullptr;
    }

    inline SecretResolutionTransaction::SecretResolutionTransaction(
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
                    Reference, Preview::Account::SecureBytes(std::string_view(Value)));
            }
        }
    }

    inline SecretResolutionTransaction::SecretResolutionTransaction(
        const std::map<std::string, std::string> &InlineValues,
        SecretRefResolver::Callback ExternalResolver)
        : ExternalResolver_(std::move(ExternalResolver))
    {
        for (const auto &[Reference, Value] : InlineValues)
        {
            if (!Value.empty())
            {
                InlineValues_.try_emplace(
                    Reference, Preview::Account::SecureBytes(std::string_view(Value)));
            }
        }
    }

    inline SecretResolutionTransaction::~SecretResolutionTransaction()
    {
        Seal();
    }

    inline auto SecretResolutionTransaction::Resolve(const std::string_view Reference)
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

    inline auto SecretResolutionTransaction::Lookup(const std::string_view Reference) const
        -> ResolvedSecrets::View
    {
        const auto It = Resolved_.find(std::string(Reference));
        return It != Resolved_.end() && It->second ? It->second->View()
                                                   : ResolvedSecrets::View{};
    }

    inline auto SecretResolutionTransaction::Seal() noexcept -> void
    {
        if (Sealed_)
        {
            return;
        }
        InlineValues_.clear();
        ExternalResolver_ = {};
        Sealed_ = true;
    }

    inline auto SecretResolutionTransaction::TakeResolvedSecrets() -> std::unique_ptr<ResolvedSecrets>
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

    inline PreparedConfiguration::PreparedConfiguration(
        PreviewConfiguration Configuration,
        std::unique_ptr<SecretResolutionTransaction> Resolution)
        : Configuration_(std::move(Configuration)), Resolution_(std::move(Resolution))
    {
        Detail::SensitiveStringMapWiper Wiper(Configuration_.Secrets);
    }

    inline auto PreparedConfiguration::Configuration() const noexcept -> const PreviewConfiguration &
    {
        return Configuration_;
    }

    inline auto PreparedConfiguration::Resolution() noexcept -> SecretResolutionTransaction &
    {
        return *Resolution_;
    }

    inline auto PreparedConfiguration::TakeConfiguration() && -> PreviewConfiguration
    {
        return std::move(Configuration_);
    }

    inline auto PreparedConfiguration::TakeResolvedSecrets() && -> std::unique_ptr<ResolvedSecrets>
    {
        auto Result = Resolution_->TakeResolvedSecrets();
        Resolution_.reset();
        return Result;
    }

    inline MapSecretRefResolver::MapSecretRefResolver(std::map<std::string, std::string> Values)
    {
        Detail::SensitiveStringMapWiper Wiper(Values);
        auto State = std::unique_ptr<SecretResolutionTransaction>(
            new SecretResolutionTransaction(std::move(Values), SecretRefResolver::Callback{}));
        Resolution_ = std::shared_ptr<SecretResolutionTransaction>(std::move(State));
    }

    inline auto MapSecretRefResolver::Resolve(const std::string_view Reference) const
        -> std::optional<std::string>
    {
        return CopySecret(Resolution_->Resolve(Reference));
    }

    inline auto MapSecretRefResolver::CallbackValue() const -> SecretRefResolver::Callback
    {
        const auto Resolution = Resolution_;
        return [Resolution](const std::string_view Reference)
            -> std::optional<std::string>
        { return CopySecret(Resolution->Resolve(Reference)); };
    }

    inline auto MakeChainedSecretResolver(std::map<std::string, std::string> InlineValues,
                                   SecretRefResolver::Callback Fallback)
        -> SecretRefResolver::Callback
    {
        Detail::SensitiveStringMapWiper Wiper(InlineValues);
        auto State = std::unique_ptr<SecretResolutionTransaction>(
            new SecretResolutionTransaction(std::move(InlineValues), std::move(Fallback)));
        const auto Resolution = std::shared_ptr<SecretResolutionTransaction>(std::move(State));
        return [Resolution](const std::string_view Reference)
            -> std::optional<std::string>
        { return CopySecret(Resolution->Resolve(Reference)); };
    }

} // namespace Preview::Application::Configuration
