add_library(PreviewApplication STATIC
        Startup/Start.hpp
)
set_source_files_properties(Startup/Start.hpp PROPERTIES LANGUAGE CXX)
target_sources(PreviewApplication PRIVATE
        Application.hpp
        Definition.hpp
        RuntimeState.hpp
        ClosingFailure.hpp
        ConfigurationStartup.hpp
        ProtocolProfile.hpp
        ProtocolAcceptors.hpp
        BoundaryStartup.hpp
        OperationsStartup.hpp
        OperationsBootstrap.hpp
        OperationsTask.hpp
        OperationsDrain.hpp
        CommandOperationOwner.hpp
        OperationsEventProducer.hpp
        Shutdown.hpp
        Shutdown/BoundedOperation.hpp
        Shutdown/Coordinator.hpp
        Shutdown/DrainStages.hpp
        Shutdown/GenerationRetirement.hpp
        Shutdown/Failure.hpp
        Shutdown/ProcessDns.hpp
        Shutdown/RuntimeResources.hpp
        Shutdown/Types.hpp
        DiagnoseRuntime.hpp
        Assembly/ProtocolAssembly.hpp
        Assembly/ConfigurationAssembly.hpp
        Account/IdentityRegistry.hpp
        Account/Catalog.hpp
        Assembly/AccountAssembly.hpp
        Assembly/CapabilityAssembly.hpp
        Assembly/DnsAssembly.hpp
        Assembly/NetworkAssembly.hpp
        Assembly/ProviderAssembly.hpp
        Startup/GenerationPhase.hpp
        Startup/StartupTransaction.hpp
        Startup/ProcessServices.hpp
        Startup/ProtocolServices.hpp
        Startup/DatagramServices.hpp
        Startup/QuicServices.hpp
        Startup/BoundaryPhase.hpp
        Startup/OperationsPhase.hpp
        Startup/PublishPhase.hpp
        Startup/StartupErrors.hpp)
target_include_directories(PreviewApplication
        PUBLIC
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
)
target_compile_definitions(PreviewApplication PUBLIC SPDLOG_COMPILED_LIB)
AssertPreviewDependency(PreviewApplication PreviewFoundation)
AssertPreviewDependency(PreviewApplication PreviewLifecycle)
AssertPreviewDependency(PreviewApplication PreviewRuntime)
AssertPreviewDependency(PreviewApplication PreviewAccount)
AssertPreviewDependency(PreviewApplication PreviewResource)
AssertPreviewDependency(PreviewApplication PreviewConfiguration)
AssertPreviewDependency(PreviewApplication PreviewOperations)
AssertPreviewDependency(PreviewApplication PreviewComposition)
AssertPreviewDependency(PreviewApplication PreviewBoundary)
AssertPreviewDependency(PreviewApplication PreviewDiagnoseBackend)
AssertPreviewDependency(PreviewApplication PreviewProtocolEch)
target_link_libraries(PreviewApplication
        PUBLIC
        PreviewFoundation
        PreviewLifecycle
        PreviewRuntime
        PreviewAccount
        PreviewResource
        PreviewConfiguration
        PreviewOperations
        PreviewComposition
        PreviewBoundary
        OpenSSL::SSL
        OpenSSL::Crypto
)
target_link_libraries(PreviewApplication PRIVATE PreviewDiagnoseBackend PreviewProtocolEch spdlog::spdlog)

add_executable(PrismPreview
        Main/PreviewMain.hpp
)
set_source_files_properties(Main/PreviewMain.hpp PROPERTIES LANGUAGE CXX)

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
target_compile_definitions(PrismPreview PRIVATE SPDLOG_COMPILED_LIB)

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

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PreviewApplication PRIVATE
    ConfigurationCommandOutcome.hpp
    OperationsConfiguration.hpp
    OperationsMetrics.hpp
    OperationsReload.hpp
    OperationsStreamQuery.hpp
    Reload/CandidateOwner.hpp
    Reload/ConfigurationDifference.hpp
    Reload/GenerationPreparation.hpp
    Reload/PublicationTransaction.hpp
    ReloadGenerationPreparation.hpp
    RuntimeGenerationSnapshot.hpp
    WorkerSessionServices.hpp
)

# 同一实际owner的源文件，复用现有target。
target_sources(PreviewApplication PRIVATE
    Main/ExecutablePath.hpp
)
