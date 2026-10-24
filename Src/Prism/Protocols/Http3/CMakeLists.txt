set(PrismProtocolHttp3CoreHeaders
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Http3/Auth.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Http3/Decoder.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Http3/Encoder.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Http3/HeaderLimits.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Http3/Qpack.hpp"
)
set(PrismProtocolHttp3CorePrivateHeaders
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Http3/Detail/StaticTable.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Http3/Detail/Varint.hpp"
)
PrismAddStaticTarget(PrismProtocolHttp3Core
    SOURCES
        Auth.cpp
        Http3Codec.cpp
    HEADERS ${PrismProtocolHttp3CoreHeaders}
    PRIVATE_HEADERS ${PrismProtocolHttp3CorePrivateHeaders}
)

set(PrismProtocolHttp3Headers
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Http3/NativeClient.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Http3/NativeServer.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Http3/Server.hpp"
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/Http3/Session.hpp"
)
set(PrismProtocolHttp3PrivateHeaders
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Http3/Detail/BoundedEventQueue.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Http3/Detail/NativeClient.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Http3/Detail/NativeClientCallbackApi.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Http3/Detail/NativeServer.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Http3/Detail/SessionContract.hpp"
    "${PROJECT_SOURCE_DIR}/Src/Prism/Protocols/Http3/Detail/TrackedSessionTasks.hpp"
)
PrismAddStaticTarget(PrismProtocolHttp3
    SOURCES
        NativeClientCallbacks.cpp
        NativeClient.cpp
        NativeClientLifecycle.cpp
        NativeServer.cpp
        NativeServerLifecycle.cpp
        NativeServerOutputDriver.cpp
        Server.cpp
        SessionCallbacks.cpp
        SessionInput.cpp
        SessionLifecycle.cpp
        SessionOutput.cpp
        Session.cpp
    HEADERS ${PrismProtocolHttp3Headers}
    PRIVATE_HEADERS ${PrismProtocolHttp3PrivateHeaders}
)
