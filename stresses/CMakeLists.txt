if(NOT PRISM_ENABLE_STRESS)
    message(STATUS "Stress tools disabled (PRISM_ENABLE_STRESS=OFF)")
    return()
endif()

add_executable(MemoryStress MemoryStress.cpp)
target_link_libraries(MemoryStress PRIVATE ${PROJECT_NAME}_static_library)

add_executable(PoolContentionStress PoolContentionStress.cpp)
target_link_libraries(PoolContentionStress PRIVATE ${PROJECT_NAME}_static_library)

add_executable(ArenaOverflowStress ArenaOverflowStress.cpp)
target_link_libraries(ArenaOverflowStress PRIVATE ${PROJECT_NAME}_static_library)

add_executable(MuxStress MuxStress.cpp)
target_link_libraries(MuxStress PRIVATE ${PROJECT_NAME}_static_library)

add_executable(TunnelStress TunnelStress.cpp)
target_link_libraries(TunnelStress PRIVATE ${PROJECT_NAME}_static_library)

add_executable(ConnectionStormStress ConnectionStormStress.cpp)
target_link_libraries(ConnectionStormStress PRIVATE ${PROJECT_NAME}_static_library)

add_executable(StabilityStress StabilityStress.cpp)
target_link_libraries(StabilityStress PRIVATE ${PROJECT_NAME}_static_library)
if(WIN32)
    target_link_libraries(StabilityStress PRIVATE psapi)
endif()

# 注意：ProtocolSessionStress 引用更早版本的测试协议库接口（client::open、
# bench_latency、message::valid 等，ba457ca 重构后已不存在）。修复后取消注释即可。
# add_executable(ProtocolSessionStress ProtocolSessionStress.cpp)
# target_link_libraries(ProtocolSessionStress PRIVATE ${PROJECT_NAME}_static_library prism_test_common)

# 注意：MuxTunnelStress 依赖 tests/common/mux（当前重构中间态，模板成员未用 this-> 限定，
# GCC 编译失败）。待 tests/common/mux 修复后取消注释即可。
# add_executable(MuxTunnelStress MuxTunnelStress.cpp)
# target_link_libraries(MuxTunnelStress PRIVATE ${PROJECT_NAME}_static_library prism_test_common)

add_executable(TlsTunnelStress TlsTunnelStress.cpp)
target_link_libraries(TlsTunnelStress PRIVATE ${PROJECT_NAME}_static_library)

add_executable(UdpRelayStress UdpRelayStress.cpp)
target_link_libraries(UdpRelayStress PRIVATE ${PROJECT_NAME}_static_library)

add_executable(LatencyStress LatencyStress.cpp)
target_link_libraries(LatencyStress PRIVATE ${PROJECT_NAME}_static_library)

add_executable(ResourceCurveStress ResourceCurveStress.cpp)
target_link_libraries(ResourceCurveStress PRIVATE ${PROJECT_NAME}_static_library)
if(WIN32)
    target_link_libraries(ResourceCurveStress PRIVATE psapi)
endif()

if(MINGW)
    foreach(target_name IN ITEMS MemoryStress PoolContentionStress ArenaOverflowStress MuxStress TunnelStress ConnectionStormStress StabilityStress ProtocolSessionStress TlsTunnelStress UdpRelayStress LatencyStress ResourceCurveStress)
        if(TARGET ${target_name})
            target_compile_options(${target_name} PRIVATE -Wa,-mbig-obj)
        endif()
    endforeach()
endif()

