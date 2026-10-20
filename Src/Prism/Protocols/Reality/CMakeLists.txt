set(PrismProtocolRealityHeaders
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Reality/CarrierPreparation.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Reality/CarrierTypes.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Reality/Prepared.hpp"
)
set(PrismProtocolRealityPrivateHeaders
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Reality/Detail/CarrierHandshake.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Reality/Detail/CarrierRecord.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Reality/Detail/CarrierStream.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Reality/Detail/Handshake.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Reality/Detail/KeyMaterial.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Reality/Detail/SessionId.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Reality/Detail/Tls13.hpp"
)
PrismAddStaticTarget(PrismProtocolReality
    SOURCES
        RealityAdmission.cpp
        RealityPreparation.cpp
    HEADERS ${PrismProtocolRealityHeaders}
    PRIVATE_HEADERS ${PrismProtocolRealityPrivateHeaders}
)
