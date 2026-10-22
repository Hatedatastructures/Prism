AddPrismTest(Codec/GunCodecDeep.cpp)
target_link_libraries(GunCodecDeep PRIVATE PrismFoundation PrismTransport PrismProtocolGun)

AddPrismTest(Core/GunGrpcContractTest.cpp)
target_sources(GunGrpcContractTest PRIVATE
    Connection/GunStreamEndTest.cpp
    Connection/GunStreamCloseTest.cpp
    Connection/GunGrpcReadCompletionTest.cpp)
target_include_directories(GunGrpcContractTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(GunGrpcContractTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismIngressContract PrismLifecycle Threads::Threads
    PrismProtocolGun PrismProtocolHttp2)

AddPrismTest(Connection/GunClientPriorityTest.cpp)
target_include_directories(GunClientPriorityTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(GunClientPriorityTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolGun PrismProtocolHttp2)

AddPrismTest(Connection/GunTerminalPriorityTest.cpp)
target_include_directories(GunTerminalPriorityTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(GunTerminalPriorityTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolGun PrismProtocolHttp2)

AddPrismTest(Connection/GunConnTerminalReadTest.cpp)
target_link_libraries(GunConnTerminalReadTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolGun)

AddPrismTest(Codec/GunFrameCodecTest.cpp)
target_link_libraries(GunFrameCodecTest PRIVATE PrismProtocolGun)
