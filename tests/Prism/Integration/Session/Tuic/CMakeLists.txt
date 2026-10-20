AddPrismTest(TuicFactoryAccountLeaseTest.cpp)
target_sources(TuicFactoryAccountLeaseTest PRIVATE
    ${CMAKE_SOURCE_DIR}/tests/TestSupport/Prism/TuicFactoryFixture.hpp)
target_link_libraries(TuicFactoryAccountLeaseTest PRIVATE
    PrismFoundation PrismAccount PrismTransport PrismNet PrismRuntime
    PrismProtocolQuic PrismProtocolQuicNative PrismProtocolTuic PrismTestSupport)

AddPrismTest(TuicConnectionLeaseTest.cpp)
target_sources(TuicConnectionLeaseTest PRIVATE
    ${CMAKE_SOURCE_DIR}/tests/TestSupport/Prism/TuicFactoryFixture.hpp)
target_link_libraries(TuicConnectionLeaseTest PRIVATE
    PrismFoundation PrismAccount PrismTransport PrismNet PrismRuntime
    PrismProtocolQuic PrismProtocolQuicNative PrismProtocolTuic PrismTestSupport)

AddPrismTest(TuicUdpAdmissionTest.cpp)
target_sources(TuicUdpAdmissionTest PRIVATE
    ${CMAKE_SOURCE_DIR}/tests/TestSupport/Prism/TuicFactoryFixture.hpp)
target_link_libraries(TuicUdpAdmissionTest PRIVATE
    PrismApplication PrismFoundation PrismAccount PrismTransport PrismNet PrismRuntime
    PrismProtocolQuic PrismProtocolQuicNative PrismProtocolTuic PrismTestSupport)
