set(PrismProtocolEchHeaders
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Ech/Detail/Key.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Ech/Detail/ServerKeyMaterial.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Ech/ServerKeys.hpp"
)
set(PrismProtocolEchPrivateHeaders
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Ech/Detail/Hello.hpp"
)
PrismAddStaticTarget(PrismProtocolEch
    SOURCES
        Ech.cpp
    HEADERS ${PrismProtocolEchHeaders}
    PRIVATE_HEADERS ${PrismProtocolEchPrivateHeaders}
)
target_link_libraries(PrismProtocolEch PRIVATE OpenSSL::SSL OpenSSL::Crypto)
