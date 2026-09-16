#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include <Preview/Composition/Builtin/Descriptor.hpp>
#include <Preview/Composition/Builtin/Freeze.hpp>

namespace Preview::Composition::Builtin
{

    class Registry;

    namespace Detail
    {

        struct SnapshotContext
        {
            CapabilitySet Capabilities{};
            FreezeRequest Request{};
        };

        inline void MixByte(std::uint64_t &Hash, const std::uint8_t Value) noexcept
        {
            Hash ^= Value;
            Hash *= 1099511628211ULL;
        }

        inline void MixUint64(std::uint64_t &Hash, const std::uint64_t Value) noexcept
        {
            for (std::size_t Index = 0; Index < sizeof(Value); ++Index)
            {
                MixByte(Hash, static_cast<std::uint8_t>(Value >> (Index * 8U)));
            }
        }

        inline void MixText(std::uint64_t &Hash, const std::string_view Value) noexcept
        {
            MixUint64(Hash, static_cast<std::uint64_t>(Value.size()));
            for (const auto Character : Value)
            {
                MixByte(Hash, static_cast<std::uint8_t>(Character));
            }
        }

        inline void MixDescriptor(std::uint64_t &Hash, const RegisteredBuiltin &Entry) noexcept
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

        inline auto MakeSnapshotId(const std::vector<RegisteredBuiltin> &Entries,
                                   const SnapshotContext &Context) noexcept -> Preview::BuiltinSnapshotId
        {
            std::uint64_t Hash = 1469598103934665603ULL;
            MixText(Hash, Context.Request.Identity);
            MixUint64(Hash, Context.Request.RequiredCapabilities.DeclaredMask());
            MixUint64(Hash, Context.Request.RequiredCapabilities.Mask());
            MixUint64(Hash, Context.Request.Generation.Value());
            MixUint64(Hash, Context.Capabilities.DeclaredMask());
            MixUint64(Hash, Context.Capabilities.Mask());
            MixUint64(Hash, static_cast<std::uint64_t>(Entries.size()));
            for (const auto &Entry : Entries)
            {
                MixDescriptor(Hash, Entry);
            }
            if (Hash == 0)
            {
                Hash = 1;
            }
            return Preview::BuiltinSnapshotId{Hash};
        }

    } // namespace Detail

    /** @brief 注册完成后只读的 builtin 快照。 */
    class BuiltinSnapshot final
    {
    public:
        using Entry = RegisteredBuiltin;

        [[nodiscard]] auto Identity() const noexcept -> Preview::BuiltinSnapshotId
        {
            return Identity_;
        }

        [[nodiscard]] auto Id() const noexcept -> Preview::BuiltinSnapshotId
        {
            return Identity();
        }

        [[nodiscard]] auto Entries() const noexcept -> std::span<const Entry>
        {
            return Entries_;
        }

        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return Entries_.size();
        }

        [[nodiscard]] auto Capabilities() const noexcept -> CapabilitySet
        {
            return Capabilities_;
        }

        [[nodiscard]] auto Find(const Preview::BuiltinId Id) const noexcept -> const Entry *
        {
            for (const auto &EntryValue : Entries_)
            {
                if (EntryValue.Id == Id)
                {
                    return &EntryValue;
                }
            }
            return nullptr;
        }

        [[nodiscard]] auto Invoke(const InvocationRequest &Request) const -> Preview::Foundation::Expected<void>
        {
            const auto *EntryValue = Find(Request.Id);
            if (!EntryValue)
            {
                return std::unexpected(Preview::Foundation::Error::NotFound);
            }
            if (!EntryValue->Descriptor.Callback)
            {
                return std::unexpected(Preview::Foundation::Error::InvalidDescriptor);
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
                return std::unexpected(Preview::Foundation::Error::CallbackException);
            }
        }

    private:
        friend class Registry;

        [[nodiscard]] static auto Make(std::vector<Entry> Entries, Detail::SnapshotContext Context)
            -> std::shared_ptr<const BuiltinSnapshot>
        {
            std::shared_ptr<BuiltinSnapshot> Mutable(
                new BuiltinSnapshot(std::move(Entries), std::move(Context)));
            return Mutable;
        }

        BuiltinSnapshot(std::vector<Entry> Entries, Detail::SnapshotContext Context)
            : Entries_(std::move(Entries)), Capabilities_(Context.Capabilities),
              Generation_(Context.Request.Generation), Identity_(Detail::MakeSnapshotId(Entries_, Context))
        {
        }

        std::vector<Entry> Entries_;
        CapabilitySet Capabilities_{};
        Preview::GenerationId Generation_{};
        Preview::BuiltinSnapshotId Identity_{};
    };

} // namespace Preview::Composition::Builtin
