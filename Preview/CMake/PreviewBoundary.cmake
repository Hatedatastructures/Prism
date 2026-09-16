include_guard(GLOBAL)

function(AssertPreviewExactCasePath Path)
    get_filename_component(_absolute_path "${Path}" ABSOLUTE)
    if(NOT EXISTS "${_absolute_path}")
        message(FATAL_ERROR "Required Preview path is missing: ${_absolute_path}")
    endif()

    file(TO_CMAKE_PATH "${CMAKE_SOURCE_DIR}" _normalized_root)
    file(TO_CMAKE_PATH "${_absolute_path}" _normalized_absolute)
    set(_root_prefix "${_normalized_root}/")
    string(FIND "${_normalized_absolute}" "${_root_prefix}" _root_prefix_index)
    if("${_normalized_absolute}" STREQUAL "${_normalized_root}")
        set(_relative_path "")
    elseif(_root_prefix_index EQUAL 0)
        string(LENGTH "${_root_prefix}" _root_prefix_length)
        string(SUBSTRING "${_normalized_absolute}" ${_root_prefix_length} -1 _relative_path)
    else()
        message(FATAL_ERROR "Preview path is outside the repository: ${_absolute_path}")
    endif()

    string(REPLACE "/" ";" _components "${_relative_path}")
    set(_current_path "${CMAKE_SOURCE_DIR}")
    foreach(_component IN LISTS _components)
        if("${_component}" STREQUAL "" OR "${_component}" STREQUAL ".")
            continue()
        endif()

        file(GLOB _children LIST_DIRECTORIES true "${_current_path}/*")
        string(TOLOWER "${_component}" _expected_lower)
        set(_exact_match FALSE)
        set(_case_match "")
        foreach(_child IN LISTS _children)
            get_filename_component(_child_name "${_child}" NAME)
            if("${_child_name}" STREQUAL "${_component}")
                set(_exact_match TRUE)
                break()
            endif()
            string(TOLOWER "${_child_name}" _child_lower)
            if("${_child_lower}" STREQUAL "${_expected_lower}")
                set(_case_match "${_child_name}")
            endif()
        endforeach()

        if(NOT _exact_match)
            if("${_case_match}" STREQUAL "")
                message(FATAL_ERROR
                    "Preview path component does not exist with exact case: ${_current_path}/${_component}")
            endif()
            message(FATAL_ERROR
                "Preview path case mismatch: requested ${_absolute_path}; "
                "disk entry is ${_current_path}/${_case_match}")
        endif()
        set(_current_path "${_current_path}/${_component}")
    endforeach()
endfunction()

function(AssertPreviewDependency Consumer Dependency)
    if("${Consumer}" MATCHES "^Preview" AND
       "${Dependency}" MATCHES "^(TestSupport|PreviewTestSupport|ProductionTestSupport|ContractTestSupport)$")
        message(FATAL_ERROR
            "Preview production target ${Consumer} must not depend on ${Dependency}")
    endif()

    if("${Consumer}" STREQUAL "PreviewFoundation" AND
       "${Dependency}" MATCHES "^Preview")
        message(FATAL_ERROR
            "PreviewFoundation must not depend on ${Dependency}")
    endif()

    if("${Consumer}" STREQUAL "PreviewAccount" AND
       NOT "${Dependency}" STREQUAL "PreviewFoundation")
        message(FATAL_ERROR
            "PreviewAccount -> ${Dependency} is outside the Preview account boundary")
    endif()

    if("${Consumer}" STREQUAL "PreviewLifecycle" AND
       NOT "${Dependency}" STREQUAL "PreviewFoundation")
        message(FATAL_ERROR
            "PreviewLifecycle -> ${Dependency} is outside the Preview lifecycle boundary")
    endif()

    if("${Consumer}" STREQUAL "PreviewResource" AND
       NOT "${Dependency}" MATCHES "^Preview(Foundation|Lifecycle)$")
        message(FATAL_ERROR
            "PreviewResource -> ${Dependency} is outside the Preview resource boundary")
    endif()

    if("${Consumer}" STREQUAL "PreviewScheduler" AND
       NOT "${Dependency}" STREQUAL "PreviewFoundation")
        message(FATAL_ERROR
            "PreviewScheduler -> ${Dependency} is outside the Preview scheduler boundary")
    endif()

    if("${Consumer}" STREQUAL "PreviewConfiguration" AND
       NOT "${Dependency}" STREQUAL "PreviewFoundation")
        message(FATAL_ERROR
            "PreviewConfiguration -> ${Dependency} is outside the Preview configuration boundary")
    endif()

    if("${Consumer}" STREQUAL "PreviewTransport" AND
       NOT "${Dependency}" STREQUAL "PreviewFoundation")
        message(FATAL_ERROR
            "PreviewTransport -> ${Dependency} is outside the Foundation boundary")
    endif()

    if("${Consumer}" STREQUAL "PreviewNet" AND
       NOT "${Dependency}" MATCHES "^Preview(Foundation|Transport)$")
        message(FATAL_ERROR
            "PreviewNet -> ${Dependency} is outside the Net boundary")
    endif()

    if("${Consumer}" STREQUAL "PreviewRuntime" AND
       NOT "${Dependency}" MATCHES "^Preview(Foundation|Transport|Net|Lifecycle|Account|Resource|Scheduler|Configuration)$")
        message(FATAL_ERROR
            "PreviewRuntime -> ${Dependency} is outside the Runtime boundary")
    endif()

    if("${Consumer}" STREQUAL "PreviewApplication" AND
       NOT "${Dependency}" MATCHES "^Preview(Foundation|Lifecycle|Runtime|Account|Resource|Scheduler|Configuration|Operations|Composition|Ingress)$")
        message(FATAL_ERROR
            "PreviewApplication -> ${Dependency} is outside the Application boundary")
    endif()

    if("${Consumer}" STREQUAL "PreviewProtocolsCommon" AND
       NOT "${Dependency}" MATCHES "^Preview(Net|Transport|Foundation)$")
        message(FATAL_ERROR
            "PreviewProtocolsCommon -> ${Dependency} is outside the common protocol boundary")
    endif()

    if("${Consumer}" STREQUAL "PreviewComposition" AND
       NOT "${Dependency}" MATCHES "^Preview(Runtime|ProtocolsCommon|Protocol[A-Za-z0-9]+)$")
        message(FATAL_ERROR
            "PreviewComposition -> ${Dependency} is outside the Composition boundary")
    endif()

    if("${Consumer}" MATCHES "^PreviewProtocol" AND
       NOT "${Dependency}" MATCHES "^Preview(Net|Transport|Foundation|ProtocolsCommon|ProtocolHttp3Core|ProtocolHttp2|ProtocolQuic)$")
        message(FATAL_ERROR
            "${Consumer} -> ${Dependency} is outside the protocol boundary")
    endif()
endfunction()

function(LinkPreviewTargets Consumer)
    foreach(Dependency IN LISTS ARGN)
        AssertPreviewDependency(${Consumer} ${Dependency})
    endforeach()
    target_link_libraries(${Consumer} INTERFACE ${ARGN})
endfunction()

function(CollectPreviewTargetClosure Target OutputVariable)
    set(_pending "${Target}")
    set(_visited)
    set(_closure)
    while(_pending)
        list(GET _pending 0 _current)
        list(REMOVE_AT _pending 0)
        list(FIND _visited "${_current}" _seen)
        if(NOT _seen EQUAL -1 OR NOT TARGET "${_current}")
            continue()
        endif()
        list(APPEND _visited "${_current}")

        foreach(_property IN ITEMS LINK_LIBRARIES INTERFACE_LINK_LIBRARIES)
            get_target_property(_dependencies "${_current}" ${_property})
            if(NOT _dependencies OR _dependencies MATCHES "-NOTFOUND$")
                continue()
            endif()
            foreach(_dependency IN LISTS _dependencies)
                if("${_dependency}" MATCHES "PrismStaticLibrary|TestSupport|psm::|src[/\\]prism")
                    message(FATAL_ERROR
                        "Forbidden dependency in Preview target ${Target}: ${_current} -> ${_dependency}")
                endif()
                if(_dependency MATCHES "^\$<")
                    continue()
                endif()
                if(TARGET "${_dependency}")
                    list(APPEND _closure "${_dependency}")
                    list(APPEND _pending "${_dependency}")
                endif()
            endforeach()
        endforeach()
    endwhile()
    list(REMOVE_DUPLICATES _closure)
    set(${OutputVariable} "${_closure}" PARENT_SCOPE)
endfunction()

function(AssertPreviewTargetSources Target)
    if(NOT TARGET "${Target}")
        message(FATAL_ERROR "Required Preview target is missing: ${Target}")
    endif()

    get_target_property(_source_dir "${Target}" SOURCE_DIR)
    foreach(_property IN ITEMS SOURCES INTERFACE_SOURCES)
        get_target_property(_sources "${Target}" ${_property})
        if(NOT _sources OR _sources MATCHES "-NOTFOUND$")
            continue()
        endif()
        foreach(_source IN LISTS _sources)
            if("${_source}" MATCHES "\$<")
                continue()
            endif()
            get_filename_component(_source_path "${_source}" ABSOLUTE BASE_DIR "${_source_dir}")
            file(TO_CMAKE_PATH "${_source_path}" _normalized_source)
            if(NOT EXISTS "${_source_path}")
                message(FATAL_ERROR
                    "Preview target ${Target} registers a missing source: ${_source_path}")
            endif()
            AssertPreviewExactCasePath("${_source_path}")
            if("${_normalized_source}" MATCHES "(^|/)src/prism(/|$)|(^|/)include/prism(/|$)|(^|/)tests/(TestSupport|common)(/|$)")
                message(FATAL_ERROR
                    "Preview target ${Target} registers a forbidden source: ${_source_path}")
            endif()
        endforeach()
    endforeach()
endfunction()

function(AssertPreviewTargetIncludes Target)
    if(NOT TARGET "${Target}")
        message(FATAL_ERROR "Required Preview target is missing: ${Target}")
    endif()

    foreach(_property IN ITEMS INCLUDE_DIRECTORIES INTERFACE_INCLUDE_DIRECTORIES)
        get_target_property(_include_dirs "${Target}" ${_property})
        if(NOT _include_dirs OR _include_dirs MATCHES "-NOTFOUND$")
            continue()
        endif()
        foreach(_include_dir IN LISTS _include_dirs)
            if("${_include_dir}" MATCHES "\$<")
                continue()
            endif()
            file(TO_CMAKE_PATH "${_include_dir}" _normalized_include)
            if("${_normalized_include}" MATCHES "(^|/)src/prism(/|$)|(^|/)include/prism(/|$)|(^|/)tests/(TestSupport|common)(/|$)|(^|/)psm(::|/|$)")
                message(FATAL_ERROR
                    "Preview target ${Target} exposes a forbidden include directory: ${_include_dir}")
            endif()
        endforeach()
    endforeach()
endfunction()

function(AssertPreviewApplicationSources Target)
    get_target_property(_source_dir "${Target}" SOURCE_DIR)
    file(TO_CMAKE_PATH "${CMAKE_SOURCE_DIR}/Preview/Application" _application_root)
    get_target_property(_sources "${Target}" SOURCES)
    if(NOT _sources OR _sources MATCHES "-NOTFOUND$")
        message(FATAL_ERROR "Preview application target has no concrete sources: ${Target}")
    endif()
    foreach(_source IN LISTS _sources)
        get_filename_component(_source_path "${_source}" ABSOLUTE BASE_DIR "${_source_dir}")
        file(TO_CMAKE_PATH "${_source_path}" _normalized_source)
        AssertPreviewExactCasePath("${_source_path}")
        string(FIND "${_normalized_source}" "${_application_root}" _application_prefix)
        if(NOT _application_prefix EQUAL 0)
            message(FATAL_ERROR
                "Preview application target ${Target} owns a source outside Preview/Application: ${_source_path}")
        endif()
    endforeach()
endfunction()

function(AssertPreviewStandaloneClosure Target)
    if(NOT TARGET "${Target}")
        message(FATAL_ERROR "Required standalone Preview target is missing: ${Target}")
    endif()

    AssertPreviewExactCasePath("${CMAKE_SOURCE_DIR}/Preview")
    AssertPreviewExactCasePath("${CMAKE_SOURCE_DIR}/tests/Preview")
    message(STATUS "AssertPreviewExactCasePaths passed: Preview and tests/Preview")

    CollectPreviewTargetClosure(${Target} _closure)
    foreach(_dependency IN LISTS _closure)
        if("${_dependency}" MATCHES "^(PrismStaticLibrary|TestSupport|PreviewTestSupport|ProductionTestSupport|ContractTestSupport)$")
            message(FATAL_ERROR
                "Standalone Preview target ${Target} transitively links forbidden target ${_dependency}: ${_closure}")
        endif()
    endforeach()

    set(_targets "${Target};${_closure}")
    list(REMOVE_DUPLICATES _targets)
    foreach(_target IN LISTS _targets)
        if(NOT "${_target}" MATCHES "^(Preview|PrismPreview)")
            continue()
        endif()
        AssertPreviewTargetSources(${_target})
        AssertPreviewTargetIncludes(${_target})
    endforeach()
    AssertPreviewApplicationSources(PreviewApplication)
    message(STATUS "AssertPreviewStandaloneClosure passed: ${Target} -> ${_closure}")
endfunction()
