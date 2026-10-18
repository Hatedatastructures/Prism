add_library(PrismApplication STATIC
        Startup/Start.hpp
)
set_source_files_properties(Startup/Start.hpp PROPERTIES LANGUAGE CXX)
target_sources(PrismApplication PRIVATE
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
target_include_directories(PrismApplication
        PUBLIC
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
)
target_compile_definitions(PrismApplication PUBLIC SPDLOG_COMPILED_LIB)
AssertPrismDependency(PrismApplication PrismFoundation)
AssertPrismDependency(PrismApplication PrismLifecycle)
AssertPrismDependency(PrismApplication PrismRuntime)
AssertPrismDependency(PrismApplication PrismAccount)
AssertPrismDependency(PrismApplication PrismResource)
AssertPrismDependency(PrismApplication PrismConfiguration)
AssertPrismDependency(PrismApplication PrismOperations)
AssertPrismDependency(PrismApplication PrismComposition)
AssertPrismDependency(PrismApplication PrismBoundary)
AssertPrismDependency(PrismApplication PrismDiagnoseBackend)
AssertPrismDependency(PrismApplication PrismProtocolEch)
target_link_libraries(PrismApplication
        PUBLIC
        PrismFoundation
        PrismLifecycle
        PrismRuntime
        PrismAccount
        PrismResource
        PrismConfiguration
        PrismOperations
        PrismComposition
        PrismBoundary
        OpenSSL::SSL
        OpenSSL::Crypto
)
target_link_libraries(PrismApplication PRIVATE PrismDiagnoseBackend PrismProtocolEch spdlog::spdlog)

add_executable(Prism
        Main/PrismMain.hpp
)
set_source_files_properties(Main/PrismMain.hpp PROPERTIES LANGUAGE CXX)

set_target_properties(Prism PROPERTIES
        OUTPUT_NAME "Prism"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/src"
)
get_target_property(PrismOutputDirectory Prism RUNTIME_OUTPUT_DIRECTORY)
file(TO_CMAKE_PATH "${PrismOutputDirectory}" PrismNormalizedOutputDirectory)
file(TO_CMAKE_PATH "${CMAKE_BINARY_DIR}/src" PrismExpectedOutputDirectory)
if(NOT "${PrismNormalizedOutputDirectory}" STREQUAL "${PrismExpectedOutputDirectory}")
    message(FATAL_ERROR
        "Prism must output to build/src: ${PrismOutputDirectory}")
endif()
foreach(PrismConfiguration IN ITEMS Debug Release RelWithDebInfo MinSizeRel)
    set_target_properties(Prism PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY_${PrismConfiguration} "${CMAKE_BINARY_DIR}/src")
endforeach()

target_include_directories(Prism PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(Prism PRIVATE PrismApplication)
target_compile_definitions(Prism PRIVATE SPDLOG_COMPILED_LIB)

set(PrismConfigurationFile
        "${CMAKE_CURRENT_SOURCE_DIR}/Configuration/PrismConfiguration.json")
if(NOT EXISTS "${PrismConfigurationFile}")
    message(FATAL_ERROR
        "Prism application configuration is missing: ${PrismConfigurationFile}")
endif()
add_custom_command(TARGET Prism POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${PrismConfigurationFile}"
        "$<TARGET_FILE_DIR:Prism>/PrismConfiguration.json"
)

if(MINGW)
    target_link_options(Prism PRIVATE -static-libgcc)
    target_compile_options(Prism PRIVATE -fno-keep-inline-dllexport)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(Prism PRIVATE -g1 -Os)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(Prism PRIVATE -Wl,--no-gc-sections)
    if(WIN32)
        target_link_options(Prism PRIVATE -Wl,--image-base,0x141000000)
    endif()
endif()

# 同一 owner 的正式职责头与行为场景，复用既有 target。
target_sources(PrismApplication PRIVATE
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
target_sources(PrismApplication PRIVATE
    Main/ExecutablePath.hpp
)
