AddPrismTest(TuicFactoryLeaseTest.cpp)
target_sources(TuicFactoryLeaseTest PRIVATE
    ${PROJECT_SOURCE_DIR}/Test/TestSupport/Prism/TuicFactoryFixture.hpp)
target_link_libraries(TuicFactoryLeaseTest PRIVATE
    PrismFoundation PrismAccount PrismTransport PrismNet PrismRuntime
    PrismProtocolQuic PrismProtocolQuicNative PrismProtocolTuic PrismTestSupport)

AddPrismTest(TuicConnectionLeaseTest.cpp)
target_sources(TuicConnectionLeaseTest PRIVATE
    ${PROJECT_SOURCE_DIR}/Test/TestSupport/Prism/TuicFactoryFixture.hpp)
target_link_libraries(TuicConnectionLeaseTest PRIVATE
    PrismFoundation PrismAccount PrismTransport PrismNet PrismRuntime
    PrismProtocolQuic PrismProtocolQuicNative PrismProtocolTuic PrismTestSupport)

AddPrismTest(TuicUdpAdmissionTest.cpp)
target_sources(TuicUdpAdmissionTest PRIVATE
    ${PROJECT_SOURCE_DIR}/Test/TestSupport/Prism/TuicFactoryFixture.hpp)
target_link_libraries(TuicUdpAdmissionTest PRIVATE
    PrismApplication PrismFoundation PrismAccount PrismTransport PrismNet PrismRuntime
    PrismProtocolQuic PrismProtocolQuicNative PrismProtocolTuic PrismTestSupport)
