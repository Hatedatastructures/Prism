/** @file ProtocolCatalog.cpp @brief 协议与载体静态目录查询实现。 */

#include <Prism/Composition/Protocol/ProtocolCatalog.hpp>

#include <algorithm>

namespace Prism::Composition::Protocol
{

    auto ProtocolCatalog::Find(const std::string_view Name) noexcept
        -> std::optional<ProtocolDescriptor>
    {
        auto CanonicalName = Name;
        if (Name == "websocket") CanonicalName = "ws";
        const auto It = std::find_if(Descriptors_.begin(), Descriptors_.end(),
            [CanonicalName](const ProtocolDescriptor& Descriptor)
            {
                return Descriptor.Name == CanonicalName;
            });
        if (It == Descriptors_.end())
        {
            return std::nullopt;
        }
        return *It;
    }

    auto ProtocolCatalog::Find(const Prism::Contract::ProtocolType Id) noexcept
        -> std::optional<ProtocolDescriptor>
    {
        const auto It = std::find_if(Descriptors_.begin(), Descriptors_.end(),
            [Id](const ProtocolDescriptor& Descriptor)
            {
                return Descriptor.Kind == DescriptorKind::Protocol && Descriptor.Id == Id;
            });
        if (It == Descriptors_.end())
        {
            return std::nullopt;
        }
        return *It;
    }

    auto ProtocolCatalog::Find(const ProviderKey& Key) noexcept
        -> std::optional<ProtocolDescriptor>
    {
        const auto It = std::find_if(Descriptors_.begin(), Descriptors_.end(),
            [&Key](const ProtocolDescriptor& Descriptor)
            {
                return Descriptor.Slot() == Key;
            });
        if (It == Descriptors_.end())
        {
            return std::nullopt;
        }
        return *It;
    }

    auto ProtocolCatalog::Find(const CarrierKind Kind) noexcept
        -> std::optional<ProtocolDescriptor>
    {
        return Find(ProviderKey{ProviderCategory::TlsCarrier, Kind});
    }

    auto ProtocolCatalog::CarrierName(const CarrierKind Kind) noexcept -> std::string_view
    {
        if (Kind == CarrierKind::TrustTunnel)
        {
            const auto Descriptor = Find(Prism::Contract::ProtocolType::TrustTunnel);
            if (Descriptor) return Descriptor->Name;
            return {};
        }
        const auto Descriptor = Find(Kind);
        if (Descriptor) return Descriptor->Name;
        return {};
    }

    auto ProtocolCatalog::Supports(const std::string_view Name,
        const Prism::Composition::Recognition::OperationScope Scope) noexcept -> bool
    {
        const auto Descriptor = Find(Name);
        if (!Descriptor)
        {
            return false;
        }
        switch (Scope)
        {
        case Prism::Composition::Recognition::OperationScope::TcpRecognition:
            return Descriptor->SupportsTcp;
        case Prism::Composition::Recognition::OperationScope::DatagramAssociation:
            return Descriptor->SupportsUdp;
        case Prism::Composition::Recognition::OperationScope::QuicBinding:
            return Descriptor->SupportsQuic;
        default:
            return true;
        }
    }

} // namespace Prism::Composition::Protocol
