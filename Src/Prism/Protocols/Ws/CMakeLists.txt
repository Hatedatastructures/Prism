set(PrismProtocolWsHeaders
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Ws/Ws.hpp"
)
set(PrismProtocolWsPrivateHeaders
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Ws/Detail/Codec.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Ws/Detail/ConnClose.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Ws/Detail/ConnFrame.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Ws/Detail/ConnHandshake.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Ws/Detail/ConnSession.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Ws/Detail/ConnStream.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Ws/Detail/ConnTransport.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Ws/Detail/FrameWriteGate.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Ws/Detail/StreamOwner.hpp"
)
PrismAddStaticTarget(PrismProtocolWs
    SOURCES
        Ws.cpp
        WsCodec.cpp
    HEADERS ${PrismProtocolWsHeaders}
    PRIVATE_HEADERS ${PrismProtocolWsPrivateHeaders}
)
