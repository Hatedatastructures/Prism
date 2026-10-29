set(PrismBoundaryPublicHeaders
    "${PROJECT_SOURCE_DIR}/Include/Prism/Boundary/Contract/BoundaryDispatcher.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Boundary/Datagram/Association.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Boundary/Datagram/Classifier.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Boundary/Datagram/Listener.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Boundary/Quic/QuicAdmissionBudget.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Boundary/Quic/Connection/Registry.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Boundary/Quic/Connection/Types.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Boundary/Quic/QuicPacketGateway.hpp"
)
set(PrismBoundaryPrivateHeaders
    "${CMAKE_CURRENT_SOURCE_DIR}/Quic/Connection/Detail/CloseOwner.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/Quic/Connection/Detail/State.hpp"
)

PrismAddStaticTarget(PrismBoundary
    SOURCES
        Datagram/Association.cpp
        Datagram/Listener.cpp
        Datagram/Classifier.cpp
        Contract/BoundaryDispatcher.cpp
        Quic/QuicPacketGateway.cpp
        Quic/QuicAdmissionBudget.cpp
        Quic/Connection/CloseOwner.cpp
        Quic/Connection/Admission.cpp
        Quic/Connection/Registry.cpp
    HEADERS ${PrismBoundaryPublicHeaders}
    PRIVATE_HEADERS ${PrismBoundaryPrivateHeaders})
