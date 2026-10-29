PrismAddInterfaceTarget(PrismIoContracts HEADERS
    "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Io/CarrierActivity.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Io/CarrierCloseReceipt.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Io/IoResult.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Io/PacketTransferResult.hpp"
)

PrismAddInterfaceTarget(PrismIngressModel HEADERS
    "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Ingress/Protocol.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Ingress/ProtocolConfiguration.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Ingress/RequestMetadata.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Ingress/ProviderFailure.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Ingress/CarrierConfiguration.hpp"
)

PrismAddStaticTarget(PrismDatagramContract
    SOURCES
        Ingress/Datagram/Raw.cpp
    HEADERS
        "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Ingress/Datagram/Raw.hpp"
        "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Services/Datagram.hpp"
        "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Services/Datagram/Egress.hpp"
)

PrismAddInterfaceTarget(PrismStreamContract HEADERS
    "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Services/FirstTransferObserver.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Services/Stream.hpp"
)

PrismAddStaticTarget(PrismIngressContract
    SOURCES
        Ingress/Admission/Transport/Retirement.cpp
        Ingress/AdmissionRetirement.cpp
        Ingress/InboundAdmission.cpp
        Ingress/MuxRootCreateRequest.cpp
        Ingress/QuicConnection.cpp
        Ingress/StreamCatalog.cpp
    HEADERS
        "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Ingress/Admission/Transport/Retirement.hpp"
        "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Ingress/CarrierCatalogOwner.hpp"
        "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Ingress/Datagram/Selection.hpp"
        "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Ingress/Datagram/Session.hpp"
        "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Ingress/DataPlane.hpp"
        "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Ingress/InboundAdmission.hpp"
        "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Ingress/MuxRootCreateRequest.hpp"
        "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Ingress/MuxSession.hpp"
        "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Ingress/QuicConnection.hpp"
        "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Ingress/StreamCatalog.hpp"
        "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Ingress/StreamFactory.hpp"
        "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Services/Authentication.hpp"
        "${PROJECT_SOURCE_DIR}/Include/Prism/Contract/Services/Quic.hpp"
    PRIVATE_HEADERS
        Ingress/Detail/AdmissionRetirementState.hpp
)
