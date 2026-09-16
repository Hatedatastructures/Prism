#pragma once

#include <memory>
#include <cstdint>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <Preview/Composition/Builtin/Snapshot.hpp>

namespace Preview::Composition::Builtin
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
            -> Preview::Foundation::Expected<Preview::BuiltinId>
        {
            if (Frozen_)
            {
                return std::unexpected(Preview::Foundation::Error::Frozen);
            }
            if (Descriptor.Kind.Empty() || Descriptor.Name.Empty() || !Descriptor.Callback)
            {
                return std::unexpected(Preview::Foundation::Error::InvalidDescriptor);
            }

            const Key KeyValue{std::string(Descriptor.Kind.Value()), std::string(Descriptor.Name.Value())};
            if (Keys_.contains(KeyValue))
            {
                return std::unexpected(Preview::Foundation::Error::Duplicate);
            }
            if (!Capabilities_.Includes(Descriptor.Requires))
            {
                return std::unexpected(Preview::Foundation::Error::MissingCapability);
            }

            const auto Id = Preview::BuiltinId{static_cast<std::uint64_t>(Entries_.size() + 1U)};
            Entries_.push_back(RegisteredBuiltin{Id, std::move(Descriptor)});
            Keys_.insert(std::move(KeyValue));
            Capabilities_ |= Entries_.back().Descriptor.Provides;
            return Id;
        }

        [[nodiscard]] auto Freeze(FreezeRequest Request)
            -> Preview::Foundation::Expected<std::shared_ptr<const BuiltinSnapshot>>
        {
            if (Frozen_)
            {
                return std::unexpected(Preview::Foundation::Error::AlreadyFrozen);
            }
            if (!Capabilities_.Includes(Request.RequiredCapabilities))
            {
                return std::unexpected(Preview::Foundation::Error::MissingCapability);
            }

            auto ImmutableSnapshot =
                BuiltinSnapshot::Make(Entries_, Detail::SnapshotContext{Capabilities_, std::move(Request)});
            Snapshot_ = ImmutableSnapshot;
            Frozen_ = true;
            return ImmutableSnapshot;
        }

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

} // namespace Preview::Composition::Builtin
