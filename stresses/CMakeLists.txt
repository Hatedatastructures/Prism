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

if(MINGW)
    foreach(target_name IN ITEMS MemoryStress PoolContentionStress ArenaOverflowStress MuxStress)
        if(TARGET ${target_name})
            target_compile_options(${target_name} PRIVATE -Wa,-mbig-obj)
        endif()
    endforeach()
endif()
