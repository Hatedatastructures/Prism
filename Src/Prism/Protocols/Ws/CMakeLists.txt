set(PrismProtocolWsHeaders
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Ws/Ws.hpp"
)
set(PrismProtocolWsPrivateHeaders
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Ws/Detail/Codec.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Ws/Detail/Connection/Close.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Ws/Detail/Connection/Frame.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Ws/Detail/Connection/Handshake.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Ws/Detail/Connection/Session.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Ws/Detail/Connection/Stream.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Ws/Detail/Connection/Transport.hpp"
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
