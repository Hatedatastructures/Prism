/** @file Snapshot.cpp @brief builtin 快照身份与调用实现。 */

#include <Prism/Composition/Builtin/Snapshot.hpp>

#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

namespace Prism::Composition::Builtin
{
    namespace
    {
        auto MixByte(std::uint64_t& Hash, const std::uint8_t Value) noexcept -> void
        {
            Hash ^= Value;
            Hash *= 1099511628211ULL;
        }

        auto MixUint64(std::uint64_t& Hash, const std::uint64_t Value) noexcept -> void
        {
            for (std::size_t Index = 0; Index < sizeof(Value); ++Index)
            {
                MixByte(Hash, static_cast<std::uint8_t>(Value >> (Index * 8U)));
            }
        }

        auto MixText(std::uint64_t& Hash, const std::string_view Value) noexcept -> void
        {
            MixUint64(Hash, static_cast<std::uint64_t>(Value.size()));
            for (const auto Character : Value)
            {
                MixByte(Hash, static_cast<std::uint8_t>(Character));
            }
        }

        auto MixDescriptor(std::uint64_t& Hash, const RegisteredBuiltin& Entry) noexcept -> void
        {
            MixUint64(Hash, Entry.Id.Value());
            MixText(Hash, Entry.Descriptor.Kind.Value());
            MixText(Hash, Entry.Descriptor.Name.Value());
            MixUint64(Hash, Entry.Descriptor.Provides.DeclaredMask());
            MixUint64(Hash, Entry.Descriptor.Provides.Mask());
            MixUint64(Hash, Entry.Descriptor.Requires.DeclaredMask());
            MixUint64(Hash, Entry.Descriptor.Requires.Mask());
            MixUint64(Hash, static_cast<std::uint64_t>(Entry.Descriptor.MemoryDomain));
            MixUint64(Hash, static_cast<std::uint64_t>(Entry.Descriptor.ExecutorAffinity));
            MixUint64(Hash, static_cast<std::uint64_t>(Entry.Descriptor.CancellationMode));
        }

        auto MakeSnapshotId(const std::vector<RegisteredBuiltin>& Entries,
            const CapabilitySet Capabilities, const FreezeRequest& Request) noexcept
            -> Prism::BuiltinSnapshotId
        {
            std::uint64_t Hash = 1469598103934665603ULL;
            MixText(Hash, Request.Identity);
            MixUint64(Hash, Request.RequiredCapabilities.DeclaredMask());
            MixUint64(Hash, Request.RequiredCapabilities.Mask());
            MixUint64(Hash, Request.Generation.Value());
            MixUint64(Hash, Capabilities.DeclaredMask());
            MixUint64(Hash, Capabilities.Mask());
            MixUint64(Hash, static_cast<std::uint64_t>(Entries.size()));
            for (const auto& Entry : Entries)
            {
                MixDescriptor(Hash, Entry);
            }
            if (Hash == 0)
            {
                Hash = 1;
            }
            return Prism::BuiltinSnapshotId{Hash};
        }
    }

    auto BuiltinSnapshot::Find(const Prism::BuiltinId Id) const noexcept -> const Entry*
    {
        for (const auto& EntryValue : Entries_)
        {
            if (EntryValue.Id == Id)
            {
                return &EntryValue;
            }
        }
        return nullptr;
    }

    auto BuiltinSnapshot::Invoke(const InvocationRequest& Request) const
        -> Prism::Foundation::Expected<void>
    {
        const auto* EntryValue = Find(Request.Id);
        if (!EntryValue)
        {
            return std::unexpected(Prism::Foundation::Error::NotFound);
        }
        if (!EntryValue->Descriptor.Callback)
        {
            return std::unexpected(Prism::Foundation::Error::InvalidDescriptor);
        }

        const BuiltinRequest CallbackRequest{
            .Id = EntryValue->Id,
            .Generation = Generation_,
            .Capabilities = Capabilities_,
            .MemoryDomain = EntryValue->Descriptor.MemoryDomain,
            .ExecutorAffinity = EntryValue->Descriptor.ExecutorAffinity,
            .CancellationMode = EntryValue->Descriptor.CancellationMode,
        };
        try
        {
            return EntryValue->Descriptor.Callback(CallbackRequest);
        }
        catch (...)
        {
            return std::unexpected(Prism::Foundation::Error::CallbackException);
        }
    }

    auto BuiltinSnapshot::Make(std::vector<Entry> Entries, const CapabilitySet Capabilities,
        FreezeRequest Request) -> std::shared_ptr<const BuiltinSnapshot>
    {
        std::shared_ptr<BuiltinSnapshot> Mutable(new BuiltinSnapshot(
            std::move(Entries), Capabilities, std::move(Request)));
        return Mutable;
    }

    BuiltinSnapshot::BuiltinSnapshot(std::vector<Entry> Entries, const CapabilitySet Capabilities,
        FreezeRequest Request)
        : Entries_(std::move(Entries)), Capabilities_(Capabilities),
          Generation_(Request.Generation), Identity_(MakeSnapshotId(Entries_, Capabilities_, Request))
    {
    }

} // namespace Prism::Composition::Builtin
