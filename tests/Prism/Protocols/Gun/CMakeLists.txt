AddPrismTest(GunCodecDeep.cpp)
target_link_libraries(GunCodecDeep PRIVATE PrismFoundation PrismTransport PrismProtocolGun)

AddPrismTest(GunGrpcContractTest.cpp)
target_sources(GunGrpcContractTest PRIVATE
    GunStreamTransportTerminalTest.cpp
    GunStreamTransportReadCloseBarrierTest.cpp
    GunGrpcReadCompletionTest.cpp)
target_include_directories(GunGrpcContractTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(GunGrpcContractTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismIngressContract PrismLifecycle Threads::Threads
    PrismProtocolGun PrismProtocolHttp2)

AddPrismTest(GunClientTerminalPriorityTest.cpp)
target_include_directories(GunClientTerminalPriorityTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(GunClientTerminalPriorityTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolGun PrismProtocolHttp2)

AddPrismTest(GunTerminalFailurePriorityTest.cpp)
target_include_directories(GunTerminalFailurePriorityTest PRIVATE ${PROJECT_SOURCE_DIR}/Src)
target_link_libraries(GunTerminalFailurePriorityTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolGun PrismProtocolHttp2)

AddPrismTest(GunConnTerminalReadTest.cpp)
target_link_libraries(GunConnTerminalReadTest PRIVATE
    PrismFoundation PrismIoContracts PrismTransport PrismProtocolGun)

AddPrismTest(GunFrameCodecTest.cpp)
target_link_libraries(GunFrameCodecTest PRIVATE PrismProtocolGun)
