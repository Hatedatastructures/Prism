set(PrismProtocolRestlsHeaders
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Restls/Restls.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Restls/Types.hpp"
)
set(PrismProtocolRestlsPrivateHeaders
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Restls/Detail/Codec.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Restls/Detail/Conn.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Restls/Detail/Retirement.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Restls/Detail/ServerSession.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Restls/Detail/WireIo.hpp"
)
PrismAddStaticTarget(PrismProtocolRestls
    SOURCES
        Restls.cpp
        RestlsTypes.cpp
    HEADERS ${PrismProtocolRestlsHeaders}
    PRIVATE_HEADERS ${PrismProtocolRestlsPrivateHeaders}
)
