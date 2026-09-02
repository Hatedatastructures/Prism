target_sources(PrismStaticLibrary
        PRIVATE
        balancer.cpp
        listener.cpp
        quic_gateway.cpp
)

target_sources(PrismStaticLibrary
        PUBLIC
        FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/prism/runtime/front/balancer.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/runtime/front/listener.hpp
            ${PROJECT_SOURCE_DIR}/include/prism/runtime/front/quic_gateway.hpp
)
