#pragma once

#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <Prism/Composition/Builtin/Descriptor.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>

namespace Prism::Composition::Builtin
{

    /** @brief 将注册表冻结为不可变快照时使用的值请求。 */
    struct FreezeRequest
    {
        CapabilitySet RequiredCapabilities{};
        std::string Identity{};
        Prism::GenerationId Generation{};
    };

    class Registry;

    /** @brief 注册完成后只读的 builtin 快照。 */
    class BuiltinSnapshot final
    {
    public:
        using Entry = RegisteredBuiltin;

        [[nodiscard]] auto Identity() const noexcept -> Prism::BuiltinSnapshotId
        {
            return Identity_;
        }

        [[nodiscard]] auto Id() const noexcept -> Prism::BuiltinSnapshotId
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

        [[nodiscard]] auto Find(const Prism::BuiltinId Id) const noexcept -> const Entry *;

        [[nodiscard]] auto Invoke(const InvocationRequest &Request) const
            -> Prism::Foundation::Expected<void>;

    private:
        friend class Registry;

        [[nodiscard]] static auto Make(std::vector<Entry> Entries, CapabilitySet Capabilities,
            FreezeRequest Request) -> std::shared_ptr<const BuiltinSnapshot>;

        BuiltinSnapshot(std::vector<Entry> Entries, CapabilitySet Capabilities,
            FreezeRequest Request);

        std::vector<Entry> Entries_;
        CapabilitySet Capabilities_{};
        Prism::GenerationId Generation_{};
        Prism::BuiltinSnapshotId Identity_{};
    };

} // namespace Prism::Composition::Builtin
