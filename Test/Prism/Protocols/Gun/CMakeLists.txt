AddPrismTest(Codec/Deep.cpp GunCodecDeep)
target_link_libraries(GunCodecDeep PRIVATE PrismFoundation PrismTransport PrismProtocolGun)

AddPrismTest(Core/GrpcContractTest.cpp GunGrpcContractTest)
target_sources(GunGrpcContractTest PRIVATE
    Connection/StreamEndTest.cpp
    Connection/StreamCloseTest.cpp
    Connection/GrpcReadTest.cpp)
target_include_directories(GunGrpcContractTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(GunGrpcContractTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismIngressContract PrismLifecycle Threads::Threads
    PrismProtocolGun PrismProtocolHttp2)

AddPrismTest(Connection/ClientPriorityTest.cpp GunClientPriorityTest)
target_include_directories(GunClientPriorityTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(GunClientPriorityTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolGun PrismProtocolHttp2)

AddPrismTest(Connection/TerminalPriorityTest.cpp GunTerminalPriorityTest)
target_include_directories(GunTerminalPriorityTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(GunTerminalPriorityTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolGun PrismProtocolHttp2)

AddPrismTest(Connection/TerminalReadTest.cpp GunConnTerminalReadTest)
target_link_libraries(GunConnTerminalReadTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolGun)

AddPrismTest(Codec/FrameCodecTest.cpp GunFrameCodecTest)
target_link_libraries(GunFrameCodecTest PRIVATE PrismProtocolGun)
