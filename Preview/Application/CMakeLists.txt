add_library(PreviewApplication STATIC
        Application.cpp
)
target_sources(PreviewApplication PRIVATE Application.hpp)

target_include_directories(PreviewApplication
        PUBLIC
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
)
AssertPreviewDependency(PreviewApplication PreviewFoundation)
AssertPreviewDependency(PreviewApplication PreviewLifecycle)
AssertPreviewDependency(PreviewApplication PreviewRuntime)
AssertPreviewDependency(PreviewApplication PreviewAccount)
AssertPreviewDependency(PreviewApplication PreviewResource)
AssertPreviewDependency(PreviewApplication PreviewScheduler)
AssertPreviewDependency(PreviewApplication PreviewConfiguration)
AssertPreviewDependency(PreviewApplication PreviewOperations)
AssertPreviewDependency(PreviewApplication PreviewComposition)
AssertPreviewDependency(PreviewApplication PreviewIngress)
target_link_libraries(PreviewApplication
        PUBLIC
        PreviewFoundation
        PreviewLifecycle
        PreviewRuntime
        PreviewAccount
        PreviewResource
        PreviewScheduler
        PreviewConfiguration
        PreviewOperations
        PreviewComposition
        PreviewIngress
        OpenSSL::SSL
        OpenSSL::Crypto
)

add_executable(PrismPreview
        Main/PreviewMain.cpp
)

set_target_properties(PrismPreview PROPERTIES
        OUTPUT_NAME "PrismPreview"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/src"
)
get_target_property(PreviewOutputDirectory PrismPreview RUNTIME_OUTPUT_DIRECTORY)
file(TO_CMAKE_PATH "${PreviewOutputDirectory}" PreviewNormalizedOutputDirectory)
file(TO_CMAKE_PATH "${CMAKE_BINARY_DIR}/src" PreviewExpectedOutputDirectory)
if(NOT "${PreviewNormalizedOutputDirectory}" STREQUAL "${PreviewExpectedOutputDirectory}")
    message(FATAL_ERROR
        "PrismPreview must output to build/src: ${PreviewOutputDirectory}")
endif()
foreach(PreviewConfiguration IN ITEMS Debug Release RelWithDebInfo MinSizeRel)
    set_target_properties(PrismPreview PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY_${PreviewConfiguration} "${CMAKE_BINARY_DIR}/src")
endforeach()

target_include_directories(PrismPreview PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(PrismPreview PRIVATE PreviewApplication)

set(PreviewConfigurationFile
        "${CMAKE_CURRENT_SOURCE_DIR}/Configuration/PreviewConfiguration.json")
if(NOT EXISTS "${PreviewConfigurationFile}")
    message(FATAL_ERROR
        "Preview application configuration is missing: ${PreviewConfigurationFile}")
endif()
add_custom_command(TARGET PrismPreview POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${PreviewConfigurationFile}"
        "$<TARGET_FILE_DIR:PrismPreview>/PreviewConfiguration.json"
)

if(MINGW)
    target_link_options(PrismPreview PRIVATE -static-libgcc)
    target_compile_options(PrismPreview PRIVATE -fno-keep-inline-dllexport)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(PrismPreview PRIVATE -g1 -Os)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(PrismPreview PRIVATE -Wl,--no-gc-sections)
    if(WIN32)
        target_link_options(PrismPreview PRIVATE -Wl,--image-base,0x141000000)
    endif()
endif()
