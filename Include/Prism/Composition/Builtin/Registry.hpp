#pragma once

#include <cstddef>
#include <expected>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <Prism/Composition/Builtin/Snapshot.hpp>

namespace Prism::Composition::Builtin
{

    /** @brief 注册表构造时可提供的外部能力。 */
    struct RegistryOptions
    {
        CapabilitySet InitialCapabilities{};
    };

    /** @brief 显式注册 builtin 并一次性冻结为不可变快照。 */
    class Registry final
    {
    public:
        explicit Registry(const RegistryOptions Options = {})
            : Capabilities_(Options.InitialCapabilities)
        {
        }

        [[nodiscard]] auto Register(BuiltinDescriptor Descriptor)
            -> Prism::Foundation::Expected<Prism::BuiltinId>;

        [[nodiscard]] auto Freeze(FreezeRequest Request)
            -> Prism::Foundation::Expected<std::shared_ptr<const BuiltinSnapshot>>;

        [[nodiscard]] auto IsFrozen() const noexcept -> bool
        {
            return Frozen_;
        }

        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return Entries_.size();
        }

        [[nodiscard]] auto Capabilities() const noexcept -> CapabilitySet
        {
            return Capabilities_;
        }

        [[nodiscard]] auto Snapshot() const noexcept -> std::shared_ptr<const BuiltinSnapshot>
        {
            return Snapshot_;
        }

    private:
        using Key = std::pair<std::string, std::string>;

        std::vector<RegisteredBuiltin> Entries_;
        std::set<Key> Keys_;
        CapabilitySet Capabilities_{};
        std::shared_ptr<const BuiltinSnapshot> Snapshot_{};
        bool Frozen_{false};
    };

} // namespace Prism::Composition::Builtin
