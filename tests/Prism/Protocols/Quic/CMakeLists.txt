AddPrismTest(QuicOwnershipTest.cpp)
target_link_libraries(QuicOwnershipTest PRIVATE
    PrismFoundation PrismIngressContract PrismTransport PrismProtocolQuic PrismProtocolQuicNative)
target_sources(QuicOwnershipTest PRIVATE ../../../TestSupport/Prism/QuicFactory.hpp)
target_include_directories(QuicOwnershipTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
AddPrismTest(NativeQuicLoopback.cpp)
target_sources(NativeQuicLoopback PRIVATE NativeQuicLoopbackSupport.hpp)
target_link_libraries(NativeQuicLoopback PRIVATE
    PrismFoundation PrismIngressContract PrismProtocolQuic PrismProtocolQuicNative
    OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
AddPrismTest(NativeQuicLoopbackOwnershipTest.cpp)
target_link_libraries(NativeQuicLoopbackOwnershipTest PRIVATE
    PrismFoundation PrismIngressContract PrismIoContracts PrismLifecycle
    PrismProtocolQuic PrismProtocolQuicNative
    OpenSSL::SSL OpenSSL::Crypto)
target_sources(NativeQuicLoopbackOwnershipTest PRIVATE
    NativeQuicLoopbackSupport.hpp ../../../TestSupport/Prism/QuicFactory.hpp)
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        # Match the unoptimized PrismProtocolQuicNative library used by Debug builds.
        target_compile_options(NativeQuicLoopback PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(NativeQuicLoopbackOwnershipTest PRIVATE -U_FORTIFY_SOURCE)
    else()
        # Match the optimized Release QUIC library ABI.
        target_compile_options(NativeQuicLoopback PRIVATE -O3)
        target_compile_options(NativeQuicLoopbackOwnershipTest PRIVATE -O3)
    endif()
endif()
AddPrismTest(QuicStreamAdapterHalfCloseTest.cpp)
target_link_libraries(QuicStreamAdapterHalfCloseTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismNet PrismProtocolQuic
    PrismProtocolQuicNative)
AddPrismTest(NativeDatagramInboxTest.cpp)
target_link_libraries(NativeDatagramInboxTest PRIVATE
    PrismFoundation PrismProtocolQuic PrismProtocolQuicNative PrismTestSupport)
