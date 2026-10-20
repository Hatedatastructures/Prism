include_guard(GLOBAL)

include(CMakeParseArguments)

function(CollectPrismDirectoryTargets Directory OutVariable)
    get_property(_targets DIRECTORY "${Directory}" PROPERTY BUILDSYSTEM_TARGETS)
    get_property(_subdirectories DIRECTORY "${Directory}" PROPERTY SUBDIRECTORIES)
    foreach(_subdirectory IN LISTS _subdirectories)
        CollectPrismDirectoryTargets("${_subdirectory}" _nested_targets)
        list(APPEND _targets ${_nested_targets})
    endforeach()
    list(REMOVE_DUPLICATES _targets)
    set(${OutVariable} "${_targets}" PARENT_SCOPE)
endfunction()

function(_PrismValidateTargetName Target)
    if(NOT "${Target}" MATCHES "^Prism[A-Za-z0-9]+$")
        message(FATAL_ERROR "Prism production target must use PascalCase: ${Target}")
    endif()
    if(TARGET "${Target}")
        message(FATAL_ERROR "Prism production target is already defined: ${Target}")
    endif()
endfunction()

function(PrismAddInterfaceTarget Target)
    cmake_parse_arguments(ARG "" "" "HEADERS;PRIVATE_HEADERS" ${ARGN})
    if(ARG_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "Unexpected PrismAddInterfaceTarget arguments: ${ARG_UNPARSED_ARGUMENTS}")
    endif()
    if(ARG_PRIVATE_HEADERS)
        message(FATAL_ERROR
            "Prism interface target ${Target} cannot own implementation-private headers")
    endif()

    _PrismValidateTargetName("${Target}")
    add_library(${Target} INTERFACE)
    target_include_directories(${Target} INTERFACE
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/Include>")

    if(ARG_HEADERS)
        target_sources(${Target} INTERFACE
            FILE_SET public_headers TYPE HEADERS
            BASE_DIRS "${PROJECT_SOURCE_DIR}/Include"
            FILES ${ARG_HEADERS})
    endif()
endfunction()

function(PrismAddStaticTarget Target)
    cmake_parse_arguments(ARG "" "" "SOURCES;HEADERS;PRIVATE_HEADERS" ${ARGN})
    if(ARG_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "Unexpected PrismAddStaticTarget arguments: ${ARG_UNPARSED_ARGUMENTS}")
    endif()
    if(NOT ARG_SOURCES)
        message(FATAL_ERROR "Prism static target ${Target} must own at least one .cpp source")
    endif()

    _PrismValidateTargetName("${Target}")
    add_library(${Target} STATIC ${ARG_SOURCES})
    target_include_directories(${Target}
        PUBLIC "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/Include>"
        PRIVATE "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/Src>")

    if(ARG_HEADERS)
        target_sources(${Target} PUBLIC
            FILE_SET public_headers TYPE HEADERS
            BASE_DIRS "${PROJECT_SOURCE_DIR}/Include"
            FILES ${ARG_HEADERS})
    endif()
    if(ARG_PRIVATE_HEADERS)
        target_sources(${Target} PRIVATE ${ARG_PRIVATE_HEADERS})
        set_property(TARGET ${Target} PROPERTY PRISM_PRIVATE_HEADERS "${ARG_PRIVATE_HEADERS}")
    endif()
endfunction()
