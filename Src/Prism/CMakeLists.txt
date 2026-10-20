include(CMake/PrismTargets.cmake)
include(CMake/PrismBoundary.cmake)
include(CMake/PrismSqlite.cmake)

add_subdirectory(Foundation)
add_subdirectory(Account)
add_subdirectory(Lifecycle)
add_subdirectory(Resource)
add_subdirectory(Statistics)
add_subdirectory(Operations)
add_subdirectory(Contract)
add_subdirectory(Transport)
add_subdirectory(Net)
add_subdirectory(Runtime)
add_subdirectory(Boundary)
add_subdirectory(Composition)
add_subdirectory(Protocols)
add_subdirectory(Application)

add_executable(Prism Application/Main/PrismMain.cpp)
target_include_directories(Prism PRIVATE
    "${PROJECT_SOURCE_DIR}/Include"
    "${PROJECT_SOURCE_DIR}/Src")
set_target_properties(Prism PROPERTIES
    OUTPUT_NAME "Prism"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/src")
foreach(_PrismConfiguration IN ITEMS Debug Release RelWithDebInfo MinSizeRel)
    string(TOUPPER "${_PrismConfiguration}" _PrismConfigurationUpper)
    set_target_properties(Prism PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY_${_PrismConfigurationUpper} "${CMAKE_BINARY_DIR}/src")
endforeach()
add_custom_command(TARGET Prism POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "${PROJECT_SOURCE_DIR}/Include/Prism/Application/Configuration/PrismConfiguration.json"
        "$<TARGET_FILE_DIR:Prism>/PrismConfiguration.json"
    VERBATIM)

include(CMake/PrismLinks.cmake)
include(CMake/PrismWeb.cmake)

CollectPrismDirectoryTargets("${CMAKE_CURRENT_SOURCE_DIR}" _PrismProductionTargets)
foreach(_PrismTarget IN LISTS _PrismProductionTargets)
    if(_PrismTarget MATCHES "^Prism" AND NOT _PrismTarget STREQUAL "PrismSqlite")
        AssertPrismTargetSources(${_PrismTarget})
        AssertPrismTargetIncludes(${_PrismTarget})
    endif()
endforeach()
AssertPrismTargetGraph()
AssertPrismStandaloneClosure(Prism)
AssertPrismDiagnoseBackendBoundary()
