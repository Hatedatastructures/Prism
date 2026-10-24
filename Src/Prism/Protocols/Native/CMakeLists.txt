set(PrismProtocolNativeHeaders
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Native/Native.hpp"
)
set(PrismProtocolNativePrivateHeaders
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Native/Detail/Tls.hpp"
)
PrismAddStaticTarget(PrismProtocolNative
    SOURCES
        Native.cpp
    HEADERS ${PrismProtocolNativeHeaders}
    PRIVATE_HEADERS ${PrismProtocolNativePrivateHeaders}
)
