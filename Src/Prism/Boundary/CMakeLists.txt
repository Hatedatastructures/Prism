set(PrismBoundaryPublicHeaders
    "${PROJECT_SOURCE_DIR}/Include/Prism/Boundary/Contract/BoundaryDispatcher.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Boundary/Datagram/DatagramAssociation.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Boundary/Datagram/DatagramClassifier.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Boundary/Datagram/DatagramListener.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Boundary/Quic/QuicAdmissionBudget.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Boundary/Quic/QuicConnectionRegistry.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Boundary/Quic/QuicConnectionRegistryTypes.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Boundary/Quic/QuicPacketGateway.hpp"
)
set(PrismBoundaryPrivateHeaders
    "${CMAKE_CURRENT_SOURCE_DIR}/Quic/Detail/QuicConnectionRegistryCloseOwner.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/Quic/Detail/QuicConnectionRegistryState.hpp"
)

PrismAddStaticTarget(PrismBoundary
    SOURCES
        Datagram/DatagramAssociation.cpp
        Datagram/DatagramListener.cpp
        Datagram/DatagramClassifier.cpp
        Contract/BoundaryDispatcher.cpp
        Quic/QuicPacketGateway.cpp
        Quic/QuicAdmissionBudget.cpp
        Quic/QuicConnectionRegistryCloseOwner.cpp
        Quic/QuicConnectionRegistryAdmission.cpp
        Quic/QuicConnectionRegistry.cpp
    HEADERS ${PrismBoundaryPublicHeaders}
    PRIVATE_HEADERS ${PrismBoundaryPrivateHeaders})
