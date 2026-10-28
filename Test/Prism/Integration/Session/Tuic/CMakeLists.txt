AddPrismTest(FactoryLeaseTest.cpp TuicFactoryLeaseTest)
target_sources(TuicFactoryLeaseTest PRIVATE
    ${PROJECT_SOURCE_DIR}/Test/TestSupport/Prism/TuicFactoryFixture.hpp)
target_link_libraries(TuicFactoryLeaseTest PRIVATE
    PrismFoundation PrismAccount PrismTransport PrismNet PrismRuntime
    PrismProtocolQuic PrismProtocolQuicNative PrismProtocolTuic PrismTestSupport)

AddPrismTest(ConnectionLeaseTest.cpp TuicConnectionLeaseTest)
target_sources(TuicConnectionLeaseTest PRIVATE
    ${PROJECT_SOURCE_DIR}/Test/TestSupport/Prism/TuicFactoryFixture.hpp)
target_link_libraries(TuicConnectionLeaseTest PRIVATE
    PrismFoundation PrismAccount PrismTransport PrismNet PrismRuntime
    PrismProtocolQuic PrismProtocolQuicNative PrismProtocolTuic PrismTestSupport)

AddPrismTest(UdpAdmissionTest.cpp TuicUdpAdmissionTest)
target_sources(TuicUdpAdmissionTest PRIVATE
    ${PROJECT_SOURCE_DIR}/Test/TestSupport/Prism/TuicFactoryFixture.hpp)
target_link_libraries(TuicUdpAdmissionTest PRIVATE
    PrismApplication PrismFoundation PrismAccount PrismTransport PrismNet PrismRuntime
    PrismProtocolQuic PrismProtocolQuicNative PrismProtocolTuic PrismTestSupport)
