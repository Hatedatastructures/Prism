set(PrismProtocolGunHeaders
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Gun/Codec.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Gun/CodecTypes.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Gun/Conn.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Gun/Grpc.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Gun/GrpcEndpoint.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Gun/GrpcFraming.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Gun/Gun.hpp"
)
set(PrismProtocolGunPrivateHeaders
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Gun/Detail/GrpcStreamActivity.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Gun/Detail/GrpcStreamDriver.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Gun/Detail/GrpcStreamFactory.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Gun/Detail/GrpcStreamOwner.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Gun/Detail/GrpcSession.hpp"
)
PrismAddStaticTarget(PrismProtocolGun
    SOURCES
        Codec.cpp
        GrpcEndpoint.cpp
        GrpcFraming.cpp
        GrpcSession.cpp
    HEADERS ${PrismProtocolGunHeaders}
    PRIVATE_HEADERS ${PrismProtocolGunPrivateHeaders}
)
