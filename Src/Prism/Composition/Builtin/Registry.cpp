/** @file Registry.cpp @brief builtin 注册表与冻结事务实现。 */

#include <Prism/Composition/Builtin/Registry.hpp>

#include <cstdint>
#include <string>
#include <utility>

namespace Prism::Composition::Builtin
{

    auto Registry::Register(BuiltinDescriptor Descriptor)
        -> Prism::Foundation::Expected<Prism::BuiltinId>
    {
        if (Frozen_)
        {
            return std::unexpected(Prism::Foundation::Error::Frozen);
        }
        if (Descriptor.Kind.Empty() || Descriptor.Name.Empty() || !Descriptor.Callback)
        {
            return std::unexpected(Prism::Foundation::Error::InvalidDescriptor);
        }

        const Key KeyValue{
            std::string(Descriptor.Kind.Value()), std::string(Descriptor.Name.Value())};
        if (Keys_.contains(KeyValue))
        {
            return std::unexpected(Prism::Foundation::Error::Duplicate);
        }
        if (!Capabilities_.Includes(Descriptor.Requires))
        {
            return std::unexpected(Prism::Foundation::Error::MissingCapability);
        }

        const auto Id = Prism::BuiltinId{static_cast<std::uint64_t>(Entries_.size() + 1U)};
        Entries_.push_back(RegisteredBuiltin{Id, std::move(Descriptor)});
        Keys_.insert(std::move(KeyValue));
        Capabilities_ |= Entries_.back().Descriptor.Provides;
        return Id;
    }

    auto Registry::Freeze(FreezeRequest Request)
        -> Prism::Foundation::Expected<std::shared_ptr<const BuiltinSnapshot>>
    {
        if (Frozen_)
        {
            return std::unexpected(Prism::Foundation::Error::AlreadyFrozen);
        }
        if (!Capabilities_.Includes(Request.RequiredCapabilities))
        {
            return std::unexpected(Prism::Foundation::Error::MissingCapability);
        }

        auto ImmutableSnapshot = BuiltinSnapshot::Make(
            Entries_, Capabilities_, std::move(Request));
        Snapshot_ = ImmutableSnapshot;
        Frozen_ = true;
        return ImmutableSnapshot;
    }

} // namespace Prism::Composition::Builtin
