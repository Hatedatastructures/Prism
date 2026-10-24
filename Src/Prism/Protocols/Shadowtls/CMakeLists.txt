set(PrismProtocolShadowtlsHeaders
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Shadowtls/Shadowtls.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Shadowtls/Types.hpp"
)
set(PrismProtocolShadowtlsPrivateHeaders
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Shadowtls/Detail/CarrierWire.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Shadowtls/Detail/ClientHello.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Shadowtls/Detail/Conn.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Shadowtls/Detail/RecordProtector.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Shadowtls/Detail/Retirement.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Shadowtls/Detail/ServerSession.hpp"
)
PrismAddStaticTarget(PrismProtocolShadowtls
    SOURCES
        Shadowtls.cpp
        ShadowtlsTypes.cpp
    HEADERS ${PrismProtocolShadowtlsHeaders}
    PRIVATE_HEADERS ${PrismProtocolShadowtlsPrivateHeaders}
)
