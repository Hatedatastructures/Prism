if(NOT PRISM_ENABLE_STRESS)
    message(STATUS "Stress tools disabled (PRISM_ENABLE_STRESS=OFF)")
    return()
endif()

add_executable(memory_stress MemoryStress.cpp)
target_link_libraries(memory_stress PRIVATE ${PROJECT_NAME}_static_library)

add_executable(pool_contention_stress PoolContentionStress.cpp)
target_link_libraries(pool_contention_stress PRIVATE ${PROJECT_NAME}_static_library)

add_executable(arena_overflow_stress ArenaOverflowStress.cpp)
target_link_libraries(arena_overflow_stress PRIVATE ${PROJECT_NAME}_static_library)

add_executable(mux_stress MuxStress.cpp)
target_link_libraries(mux_stress PRIVATE ${PROJECT_NAME}_static_library)

if(MINGW)
    foreach(target_name IN ITEMS memory_stress pool_contention_stress arena_overflow_stress mux_stress)
        if(TARGET ${target_name})
            target_compile_options(${target_name} PRIVATE -Wa,-mbig-obj)
        endif()
    endforeach()
endif()
