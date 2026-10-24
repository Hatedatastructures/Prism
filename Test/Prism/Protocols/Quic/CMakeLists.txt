AddPrismTest(Connection/QuicOwnershipTest.cpp)
target_link_libraries(QuicOwnershipTest PRIVATE
    PrismFoundation PrismIngressContract PrismTransport PrismProtocolQuic PrismProtocolQuicNative)
target_sources(QuicOwnershipTest PRIVATE ../../../TestSupport/Prism/QuicFactory.hpp)
target_include_directories(QuicOwnershipTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
AddPrismTest(Core/NativeQuicLoopback.cpp)
target_sources(NativeQuicLoopback PRIVATE Core/NativeQuicLoopbackSupport.hpp)
target_link_libraries(NativeQuicLoopback PRIVATE
    PrismFoundation PrismIngressContract PrismProtocolQuic PrismProtocolQuicNative
    OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
AddPrismTest(Connection/QuicLoopbackOwnerTest.cpp)
target_link_libraries(QuicLoopbackOwnerTest PRIVATE
    PrismFoundation PrismIngressContract PrismIoContracts PrismLifecycle
    PrismProtocolQuic PrismProtocolQuicNative
    OpenSSL::SSL OpenSSL::Crypto)
target_sources(QuicLoopbackOwnerTest PRIVATE
    Core/NativeQuicLoopbackSupport.hpp ../../../TestSupport/Prism/QuicFactory.hpp)
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        # Match the unoptimized PrismProtocolQuicNative library used by Debug builds.
        target_compile_options(NativeQuicLoopback PRIVATE -U_FORTIFY_SOURCE)
        target_compile_options(QuicLoopbackOwnerTest PRIVATE -U_FORTIFY_SOURCE)
    else()
        # Match the optimized Release QUIC library ABI.
        target_compile_options(NativeQuicLoopback PRIVATE -O3)
        target_compile_options(QuicLoopbackOwnerTest PRIVATE -O3)
    endif()
endif()
AddPrismTest(Connection/QuicAdapterHalfCloseTest.cpp)
target_link_libraries(QuicAdapterHalfCloseTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismNet PrismProtocolQuic
    PrismProtocolQuicNative)
AddPrismTest(Datagram/NativeDatagramInboxTest.cpp)
target_link_libraries(NativeDatagramInboxTest PRIVATE
    PrismFoundation PrismProtocolQuic PrismProtocolQuicNative PrismTestSupport)
