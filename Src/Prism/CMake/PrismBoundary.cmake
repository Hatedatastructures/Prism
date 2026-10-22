include_guard(GLOBAL)

function(AssertPrismExactCasePath Path)
    get_filename_component(_absolute_path "${Path}" ABSOLUTE)
    if(NOT EXISTS "${_absolute_path}")
        message(FATAL_ERROR "Required Prism path is missing: ${_absolute_path}")
    endif()

    file(TO_CMAKE_PATH "${CMAKE_SOURCE_DIR}" _normalized_root)
    file(TO_CMAKE_PATH "${_absolute_path}" _normalized_absolute)
    file(TO_CMAKE_PATH "${CMAKE_BINARY_DIR}/_deps" _normalized_dependency_root)
    set(_dependency_prefix "${_normalized_dependency_root}/")
    string(FIND "${_normalized_absolute}" "${_dependency_prefix}" _dependency_prefix_index)
    if(_dependency_prefix_index EQUAL 0)
        return()
    endif()

    set(_root_prefix "${_normalized_root}/")
    string(FIND "${_normalized_absolute}" "${_root_prefix}" _root_prefix_index)
    if("${_normalized_absolute}" STREQUAL "${_normalized_root}")
        set(_relative_path "")
    elseif(_root_prefix_index EQUAL 0)
        string(LENGTH "${_root_prefix}" _root_prefix_length)
        string(SUBSTRING "${_normalized_absolute}" ${_root_prefix_length} -1 _relative_path)
    else()
        message(FATAL_ERROR "Prism path is outside the repository: ${_absolute_path}")
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
                    "Prism path component does not exist with exact case: ${_current_path}/${_component}")
            endif()
            message(FATAL_ERROR
                "Prism path case mismatch: requested ${_absolute_path}; "
                "disk entry is ${_current_path}/${_case_match}")
        endif()
        set(_current_path "${_current_path}/${_component}")
    endforeach()
endfunction()

function(AssertPrismDependency Consumer Dependency)
    if("${Consumer}" MATCHES "^Prism" AND
       "${Dependency}" MATCHES "^(TestSupport|PrismTestSupport|ProductionTestSupport|ContractTestSupport)$")
        message(FATAL_ERROR
            "Prism production target ${Consumer} must not depend on ${Dependency}")
    endif()

    # 唯一事实源是 _GetPrismAllowedInternalLinks；下面的逐消费者正则只是补充说明，
    # 判定权在此收口。依据：2025 条假想 Prism* 边实测有 551 条两表结论相反，
    # 且全部是“表 1 宽 / 表 2 严”，0 条反向 —— 因此本收口只收紧、不放宽任何现有边。
    _IsPrismExternalLink("${Dependency}" "${Dependency}" _is_external)
    if(NOT _is_external AND "${Dependency}" MATCHES "^Prism")
        _GetPrismAllowedInternalLinks("${Consumer}" _allowed_internal)
        list(FIND _allowed_internal "${Dependency}" _allowed_index)
        if(_allowed_index EQUAL -1)
            message(FATAL_ERROR
                "Prism boundary violation: ${Consumer} -> ${Dependency} is not in "
                "${Consumer}'s allowed internal link set (_GetPrismAllowedInternalLinks)")
        endif()
    endif()

    # 逐消费者正则已删除（原 78–175 行，共 98 行）。
    # 依据：46×46=2025 条假想 Prism* 边实测两表 0 分歧、0 条“表1严/表2宽”，
    # 保留它们不增加任何限制，只构成第二套正式事实 —— 计划 §W0-E/§M36 明令禁止。
    # 判定权唯一归 _GetPrismAllowedInternalLinks；TestSupport 硬规则保留在上方。

endfunction()

set(_PrismExternalLinkTargets
    PrismSqlite
    OpenSSL::SSL
    OpenSSL::Crypto
    ssl
    crypto
    Blake3C
    BoostSystemHeaderOnly
    glaze::glaze
    ngtcp2_static
    ngtcp2_crypto_boringssl_static
    nghttp3_static
    Threads::Threads
    dl
    ws2_32
    mswsock
    crypt32
)

function(_NormalizePrismLinkEntry RawEntry OutputVariable)
    set(_entry "${RawEntry}")
    set(_iterations 0)
    while(_iterations LESS 4)
        math(EXPR _iterations "${_iterations} + 1")
        if("${_entry}" MATCHES "^::@.*$" OR "${_entry}" STREQUAL "::@")
            set(_entry "")
            break()
        elseif("${_entry}" MATCHES "^\\$<LINK_ONLY:(.*)>$")
            set(_entry "${CMAKE_MATCH_1}")
        elseif("${_entry}" MATCHES "^\\$<BUILD_INTERFACE:(.*)>$")
            set(_entry "${CMAKE_MATCH_1}")
        else()
            break()
        endif()
    endwhile()

    if("${_entry}" MATCHES "^\\$<")
        message(FATAL_ERROR
            "Prism boundary cannot resolve link generator expression '${RawEntry}'; "
            "only LINK_ONLY and BUILD_INTERFACE are supported")
    endif()
    if(_iterations GREATER_EQUAL 4 AND "${_entry}" MATCHES "^\\$<")
        message(FATAL_ERROR
            "Prism boundary link generator expression is nested too deeply: ${RawEntry}")
    endif()
    set(${OutputVariable} "${_entry}" PARENT_SCOPE)
endfunction()

function(_ResolvePrismAlias TargetName OutputVariable)
    set(_current "${TargetName}")
    set(_visited)
    while(TARGET "${_current}")
        list(FIND _visited "${_current}" _seen)
        if(NOT _seen EQUAL -1)
            message(FATAL_ERROR "Prism boundary alias cycle while resolving ${TargetName}")
        endif()
        list(APPEND _visited "${_current}")
        get_target_property(_alias_target "${_current}" ALIASED_TARGET)
        if(NOT _alias_target OR _alias_target MATCHES "-NOTFOUND$")
            break()
        endif()
        set(_current "${_alias_target}")
    endwhile()
    set(${OutputVariable} "${_current}" PARENT_SCOPE)
endfunction()

function(_IsPrismExternalLink RawEntry CanonicalEntry OutputVariable)
    set(_is_external FALSE)
    foreach(_candidate IN ITEMS "${RawEntry}" "${CanonicalEntry}")
        list(FIND _PrismExternalLinkTargets "${_candidate}" _external_index)
        if(NOT _external_index EQUAL -1)
            set(_is_external TRUE)
        endif()
    endforeach()
    set(${OutputVariable} "${_is_external}" PARENT_SCOPE)
endfunction()

function(_GetPrismAllowedInternalLinks Consumer OutputVariable)
    set(_allowed)
    if("${Consumer}" STREQUAL "PrismFoundation")
        # Foundation 位于生产 target 图底层；外部依赖不计入内部边。
    elseif("${Consumer}" STREQUAL "PrismAccount" OR
           "${Consumer}" STREQUAL "PrismLifecycle" OR
           "${Consumer}" STREQUAL "PrismStatistics" OR
           "${Consumer}" STREQUAL "PrismNetworkModel")
        set(_allowed PrismFoundation)
    elseif("${Consumer}" STREQUAL "PrismResource")
        set(_allowed PrismFoundation PrismLifecycle)
    elseif("${Consumer}" STREQUAL "PrismOperations")
        set(_allowed PrismFoundation PrismStatistics)
    elseif("${Consumer}" STREQUAL "PrismDiagnoseBackend")
        set(_allowed PrismFoundation)
    elseif("${Consumer}" STREQUAL "PrismIoContracts")
        set(_allowed PrismFoundation)
    elseif("${Consumer}" STREQUAL "PrismIngressModel")
        set(_allowed PrismFoundation PrismLifecycle)
    elseif("${Consumer}" STREQUAL "PrismDatagramContract")
        set(_allowed PrismFoundation PrismNetworkModel)
    elseif("${Consumer}" STREQUAL "PrismStreamContract")
        set(_allowed PrismNetworkModel PrismFoundation PrismAccount PrismTransport PrismIngressModel)
    elseif("${Consumer}" STREQUAL "PrismIngressContract")
        set(_allowed PrismFoundation PrismAccount PrismTransport PrismIngressModel
            PrismDatagramContract PrismStreamContract PrismIoContracts PrismNetworkModel)
    elseif("${Consumer}" STREQUAL "PrismTransport")
        set(_allowed PrismFoundation PrismLifecycle PrismIoContracts)
    elseif("${Consumer}" STREQUAL "PrismNet")
        set(_allowed PrismTransport PrismFoundation PrismDatagramContract PrismNetworkModel PrismStreamContract)
    elseif("${Consumer}" STREQUAL "PrismBoundary")
        set(_allowed PrismDatagramContract PrismIngressContract PrismFoundation)
    elseif("${Consumer}" STREQUAL "PrismRuntime")
        set(_allowed PrismIngressModel PrismIngressContract PrismStatistics PrismNet PrismTransport PrismFoundation
            PrismLifecycle PrismAccount PrismResource PrismNetworkModel PrismIoContracts PrismStreamContract)
    elseif("${Consumer}" STREQUAL "PrismProtocolsCommon")
        set(_allowed PrismTransport PrismFoundation PrismIngressModel PrismIngressContract PrismLifecycle PrismNetworkModel
            PrismIoContracts PrismAccount PrismDatagramContract)
    elseif("${Consumer}" STREQUAL "PrismProtocolProviderLifecycle")
        set(_allowed PrismProtocolsCommon PrismProtocolMux PrismFoundation PrismLifecycle PrismAccount)
    elseif("${Consumer}" STREQUAL "PrismProtocolHttp2")
        set(_allowed PrismFoundation PrismProtocolHttpCompression)
    elseif("${Consumer}" STREQUAL "PrismProtocolHttp3Core")
        set(_allowed PrismFoundation PrismProtocolHttpCompression)
    elseif("${Consumer}" STREQUAL "PrismProtocolQuic")
        set(_allowed PrismProtocolsCommon PrismTransport PrismIoContracts PrismFoundation PrismIngressContract PrismLifecycle)
    elseif("${Consumer}" STREQUAL "PrismProtocolQuicNative")
        set(_allowed PrismProtocolQuic PrismIngressContract PrismProtocolsCommon PrismLifecycle PrismFoundation)
    elseif("${Consumer}" STREQUAL "PrismProtocolHttp")
        set(_allowed PrismProtocolsCommon PrismIngressModel PrismIngressContract PrismAccount PrismFoundation
            PrismLifecycle PrismTransport)
    elseif("${Consumer}" STREQUAL "PrismProtocolHttp3")
        set(_allowed PrismProtocolHttp3Core PrismProtocolQuic PrismProtocolQuicNative
            PrismFoundation PrismTransport PrismIngressContract PrismLifecycle)
    elseif("${Consumer}" STREQUAL "PrismProtocolHysteria2")
        set(_allowed PrismProtocolsCommon PrismProtocolHttp3Core PrismProtocolHttp3 PrismProtocolQuic
            PrismProtocolQuicNative PrismTransport PrismFoundation PrismAccount PrismIngressContract
            PrismIngressModel PrismLifecycle PrismNetworkModel)
    elseif("${Consumer}" STREQUAL "PrismProtocolTuic")
        set(_allowed PrismProtocolsCommon PrismProtocolQuic PrismProtocolQuicNative PrismAccount
            PrismFoundation PrismTransport PrismIngressModel PrismIngressContract PrismLifecycle PrismIoContracts
            PrismNetworkModel)
    elseif("${Consumer}" STREQUAL "PrismProtocolMux")
        set(_allowed PrismIngressContract PrismLifecycle PrismAccount PrismNet PrismProtocolHttp2 PrismFoundation
            PrismNetworkModel PrismStreamContract PrismTransport)
    elseif("${Consumer}" STREQUAL "PrismProtocolAnytls")
        set(_allowed PrismIngressModel PrismIngressContract PrismStreamContract PrismLifecycle PrismAccount
            PrismProtocolMux PrismFoundation PrismTransport)
    elseif("${Consumer}" STREQUAL "PrismProtocolShadowsocks2022")
        set(_allowed PrismProtocolsCommon PrismIngressModel PrismIngressContract PrismDatagramContract PrismLifecycle
            PrismAccount PrismProtocolMux PrismFoundation PrismTransport PrismNetworkModel)
    elseif("${Consumer}" STREQUAL "PrismProtocolSocks5")
        set(_allowed PrismProtocolsCommon PrismIngressModel PrismIngressContract PrismDatagramContract PrismLifecycle
            PrismAccount PrismProtocolMux PrismIoContracts PrismFoundation PrismTransport PrismNetworkModel)
    elseif("${Consumer}" STREQUAL "PrismProtocolTrojan" OR
           "${Consumer}" STREQUAL "PrismProtocolVless" OR
           "${Consumer}" STREQUAL "PrismProtocolVmess")
        set(_allowed PrismProtocolsCommon PrismIngressModel PrismIngressContract PrismDatagramContract PrismLifecycle
            PrismAccount PrismNetworkModel PrismProtocolMux PrismProtocolProviderLifecycle PrismIoContracts
            PrismFoundation PrismTransport)
    elseif("${Consumer}" STREQUAL "PrismProtocolEch")
        set(_allowed PrismFoundation)
    elseif("${Consumer}" STREQUAL "PrismProtocolNative")
        set(_allowed PrismFoundation PrismTransport PrismIngressContract)
    elseif("${Consumer}" STREQUAL "PrismProtocolWs")
        set(_allowed PrismFoundation PrismTransport PrismIoContracts PrismIngressContract)
    elseif("${Consumer}" STREQUAL "PrismProtocolGun")
        set(_allowed PrismFoundation PrismTransport PrismProtocolHttp2 PrismIoContracts PrismIngressContract PrismLifecycle)
    elseif("${Consumer}" STREQUAL "PrismProtocolReality" OR
           "${Consumer}" STREQUAL "PrismProtocolRestls" OR
           "${Consumer}" STREQUAL "PrismProtocolShadowtls")
        set(_allowed PrismProtocolsCommon PrismIngressContract PrismFoundation PrismTransport)
    elseif("${Consumer}" STREQUAL "PrismProtocolTrusttunnel")
        set(_allowed PrismProtocolHttp2 PrismIngressModel PrismIngressContract PrismAccount PrismFoundation
            PrismTransport PrismIoContracts)
    elseif("${Consumer}" STREQUAL "PrismProtocolXhttp")
        set(_allowed PrismProtocolHttp2 PrismTransport PrismIoContracts PrismFoundation PrismIngressContract)
    elseif("${Consumer}" STREQUAL "PrismProtocolHttpCompression")
        # HTTP compression is a neutral wire codec.
    elseif("${Consumer}" STREQUAL "PrismConfiguration")
        set(_allowed PrismFoundation PrismAccount PrismIngressModel PrismComposition)
    elseif("${Consumer}" STREQUAL "PrismComposition")
        set(_allowed PrismAccount PrismFoundation PrismNetworkModel PrismIngressModel PrismIngressContract
            PrismDatagramContract PrismStreamContract PrismTransport PrismRuntime
            PrismProtocolsCommon PrismProtocolHttp PrismProtocolSocks5 PrismProtocolVmess PrismProtocolVless
            PrismProtocolTrojan PrismProtocolShadowsocks2022 PrismProtocolAnytls PrismProtocolRestls
            PrismProtocolTrusttunnel PrismProtocolShadowtls PrismProtocolWs PrismProtocolNative
            PrismProtocolHysteria2 PrismProtocolTuic
            PrismProtocolMux PrismProtocolXhttp PrismProtocolGun PrismProtocolReality PrismProtocolHttp3)
    elseif("${Consumer}" STREQUAL "PrismApplication")
        set(_allowed PrismFoundation PrismLifecycle PrismRuntime PrismNet PrismNetworkModel
            PrismIngressContract PrismDatagramContract PrismIngressModel PrismAccount PrismResource
            PrismStatistics PrismConfiguration
            PrismOperations PrismComposition PrismBoundary PrismDiagnoseBackend PrismProtocolEch
            PrismProtocolHttp3)
    elseif("${Consumer}" STREQUAL "Prism")
        set(_allowed PrismApplication)
    else()
        message(FATAL_ERROR
            "Prism boundary has no explicit internal edge policy for target ${Consumer}")
    endif()
    set(${OutputVariable} "${_allowed}" PARENT_SCOPE)
endfunction()

function(_CollectPrismBuildsystemTargets Directory OutputVariable)
    get_property(_targets DIRECTORY "${Directory}" PROPERTY BUILDSYSTEM_TARGETS)
    get_property(_subdirectories DIRECTORY "${Directory}" PROPERTY SUBDIRECTORIES)
    set(_prism_targets)
    foreach(_target IN LISTS _targets)
        if("${_target}" MATCHES "^(Prism|Prism)")
            list(APPEND _prism_targets "${_target}")
        endif()
    endforeach()
    foreach(_subdirectory IN LISTS _subdirectories)
        _CollectPrismBuildsystemTargets("${_subdirectory}" _child_targets)
        list(APPEND _prism_targets ${_child_targets})
    endforeach()
    list(REMOVE_DUPLICATES _prism_targets)
    set(${OutputVariable} "${_prism_targets}" PARENT_SCOPE)
endfunction()

function(_AssertPrismInternalLink Consumer RawEntry CanonicalEntry Property)
    _IsPrismExternalLink("${RawEntry}" "${CanonicalEntry}" _is_external)
    if(_is_external)
        return()
    endif()

    if("${CanonicalEntry}" MATCHES "^(Prism|Prism)")
        _GetPrismAllowedInternalLinks("${Consumer}" _allowed)
        list(FIND _allowed "${CanonicalEntry}" _allowed_index)
        if(_allowed_index EQUAL -1)
            message(FATAL_ERROR
                "Forbidden Prism target edge: ${Consumer} -> ${RawEntry} "
                "(${CanonicalEntry}) from ${Property}")
        endif()
        return()
    endif()

    _IsPrismExternalLink("${RawEntry}" "${CanonicalEntry}" _known_external)
    if(_known_external)
        return()
    endif()

    if(TARGET "${CanonicalEntry}")
        message(FATAL_ERROR
            "Unknown external Prism link target: ${Consumer} -> ${RawEntry} "
            "(${CanonicalEntry}) from ${Property}")
    endif()
    message(FATAL_ERROR
        "Unknown external Prism link item: ${Consumer} -> ${RawEntry} from ${Property}")
endfunction()

function(AssertPrismTargetGraph)
    _CollectPrismBuildsystemTargets("${CMAKE_CURRENT_SOURCE_DIR}" _prism_targets)
    if(NOT _prism_targets)
        message(FATAL_ERROR "Prism boundary found no Prism buildsystem targets")
    endif()

    foreach(_consumer IN LISTS _prism_targets)
        foreach(_property IN ITEMS LINK_LIBRARIES INTERFACE_LINK_LIBRARIES)
            get_target_property(_raw_dependencies "${_consumer}" ${_property})
            if(NOT _raw_dependencies OR _raw_dependencies MATCHES "-NOTFOUND$")
                continue()
            endif()
            foreach(_raw_entry IN LISTS _raw_dependencies)
                if("${_raw_entry}" STREQUAL "debug" OR
                   "${_raw_entry}" STREQUAL "optimized" OR
                   "${_raw_entry}" STREQUAL "general")
                    continue()
                endif()
                if("${_raw_entry}" MATCHES "PrismStaticLibrary|TestSupport|psm::|src[/\\]prism")
                    message(FATAL_ERROR
                        "Forbidden dependency in Prism target ${_consumer}: ${_raw_entry}")
                endif()
                _NormalizePrismLinkEntry("${_raw_entry}" _normalized_entries)
                foreach(_entry IN LISTS _normalized_entries)
                    if("${_entry}" STREQUAL "")
                        continue()
                    endif()
                    _ResolvePrismAlias("${_entry}" _canonical_entry)
                    _AssertPrismInternalLink(
                        "${_consumer}" "${_entry}" "${_canonical_entry}" "${_property}")
                endforeach()
            endforeach()
        endforeach()
    endforeach()
    message(STATUS "AssertPrismTargetGraph passed: ${_prism_targets}")
endfunction()

function(LinkPrismTargets Consumer)
    set(_dependencies ${ARGN})
    list(LENGTH _dependencies _dependency_count)
    if(_dependency_count GREATER 0)
        list(GET _dependencies 0 _first_argument)
    else()
        set(_first_argument "")
    endif()

    if("${_first_argument}" MATCHES "^(PUBLIC|PRIVATE|INTERFACE)$")
        set(_scope "${_first_argument}")
        list(REMOVE_AT _dependencies 0)
    else()
        get_target_property(_target_type "${Consumer}" TYPE)
        if("${_target_type}" STREQUAL "INTERFACE_LIBRARY")
            set(_scope INTERFACE)
        elseif("${_target_type}" STREQUAL "EXECUTABLE")
            set(_scope PRIVATE)
        else()
            set(_scope PUBLIC)
        endif()
    endif()

    foreach(Dependency IN LISTS _dependencies)
        AssertPrismDependency(${Consumer} ${Dependency})
    endforeach()
    if(_dependencies)
        target_link_libraries(${Consumer} ${_scope} ${_dependencies})
    endif()
endfunction()

function(CollectPrismTargetClosure Target OutputVariable)
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
                        "Forbidden dependency in Prism target ${Target}: ${_current} -> ${_dependency}")
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

function(_AssertPrismPathWithinRoot Path Root Ownership Target)
    get_filename_component(_absolute_path "${Path}" ABSOLUTE)
    file(REAL_PATH "${_absolute_path}" _real_path)
    file(REAL_PATH "${Root}" _real_root)
    file(TO_CMAKE_PATH "${_real_path}" _normalized_path)
    file(TO_CMAKE_PATH "${_real_root}" _normalized_root)
    cmake_path(IS_PREFIX _normalized_root "${_normalized_path}" NORMALIZE _is_within_root)
    if(NOT _is_within_root OR "${_normalized_path}" STREQUAL "${_normalized_root}")
        message(FATAL_ERROR
            "Prism ${Target} ${Ownership} must resolve under ${_normalized_root}: ${_real_path}")
    endif()
endfunction()

function(_AssertPrismRegisteredHeaderSet Target HeaderSet Root Ownership)
    get_target_property(_headers "${Target}" "HEADER_SET_${HeaderSet}")
    if(NOT _headers OR _headers MATCHES "-NOTFOUND$")
        message(FATAL_ERROR
            "Prism target ${Target} has an empty registered header set: ${HeaderSet}")
    endif()
    get_target_property(_source_dir "${Target}" SOURCE_DIR)
    foreach(_header IN LISTS _headers)
        if("${_header}" MATCHES "\\$<")
            message(FATAL_ERROR
                "Prism target ${Target} must register concrete file-set headers, not generator expressions: ${_header}")
        endif()
        get_filename_component(_header_path "${_header}" ABSOLUTE BASE_DIR "${_source_dir}")
        file(TO_CMAKE_PATH "${_header_path}" _normalized_header)
        if(NOT EXISTS "${_header_path}")
            message(FATAL_ERROR
                "Prism target ${Target} registers a missing ${Ownership}: ${_header_path}")
        endif()
        AssertPrismExactCasePath("${_header_path}")
        if("${_normalized_header}" MATCHES "(^|/)src/prism(/|$)|(^|/)include/prism(/|$)|(^|/)tests/(TestSupport|common)(/|$)")
            message(FATAL_ERROR
                "Prism target ${Target} registers a forbidden ${Ownership}: ${_header_path}")
        endif()
        _AssertPrismPathWithinRoot("${_header_path}" "${Root}" "${Ownership}" "${Target}")
    endforeach()
endfunction()

function(AssertPrismTargetSources Target)
    if(NOT TARGET "${Target}")
        message(FATAL_ERROR "Required Prism target is missing: ${Target}")
    endif()

    get_target_property(_source_dir "${Target}" SOURCE_DIR)
    foreach(_property IN ITEMS SOURCES INTERFACE_SOURCES)
        get_target_property(_sources "${Target}" ${_property})
        if(NOT _sources OR _sources MATCHES "-NOTFOUND$")
            continue()
        endif()
        foreach(_source IN LISTS _sources)
            if("${_source}" MATCHES "\\$<")
                message(FATAL_ERROR
                    "Prism target ${Target} must register concrete source paths, not generator expressions: ${_source}")
            endif()
            get_filename_component(_source_path "${_source}" ABSOLUTE BASE_DIR "${_source_dir}")
            file(TO_CMAKE_PATH "${_source_path}" _normalized_source)
            if(NOT EXISTS "${_source_path}")
                message(FATAL_ERROR
                    "Prism target ${Target} registers a missing source: ${_source_path}")
            endif()
            AssertPrismExactCasePath("${_source_path}")
            if("${_normalized_source}" MATCHES "(^|/)src/prism(/|$)|(^|/)include/prism(/|$)|(^|/)tests/(TestSupport|common)(/|$)")
                message(FATAL_ERROR
                    "Prism target ${Target} registers a forbidden source: ${_source_path}")
            endif()
            _AssertPrismPathWithinRoot(
                "${_source_path}" "${PROJECT_SOURCE_DIR}/Src/Prism"
                "implementation source or private header" "${Target}")
        endforeach()
    endforeach()

    get_target_property(_interface_header_sets "${Target}" INTERFACE_HEADER_SETS)
    get_target_property(_all_header_sets "${Target}" HEADER_SETS)
    if(_interface_header_sets AND NOT _interface_header_sets MATCHES "-NOTFOUND$")
        foreach(_header_set IN LISTS _interface_header_sets)
            _AssertPrismRegisteredHeaderSet(
                "${Target}" "${_header_set}" "${PROJECT_SOURCE_DIR}/Include/Prism" "public header")
        endforeach()
    endif()
    if(_all_header_sets AND NOT _all_header_sets MATCHES "-NOTFOUND$")
        foreach(_header_set IN LISTS _all_header_sets)
            list(FIND _interface_header_sets "${_header_set}" _interface_header_index)
            if(_interface_header_index EQUAL -1)
                _AssertPrismRegisteredHeaderSet(
                    "${Target}" "${_header_set}" "${PROJECT_SOURCE_DIR}/Src/Prism" "private header")
            endif()
        endforeach()
    endif()

    get_target_property(_private_headers "${Target}" PRISM_PRIVATE_HEADERS)
    if(_private_headers AND NOT _private_headers MATCHES "-NOTFOUND$")
        foreach(_header IN LISTS _private_headers)
            get_filename_component(_header_path "${_header}" ABSOLUTE BASE_DIR "${_source_dir}")
            if(NOT EXISTS "${_header_path}")
                message(FATAL_ERROR
                    "Prism target ${Target} registers a missing private header: ${_header_path}")
            endif()
            AssertPrismExactCasePath("${_header_path}")
            _AssertPrismPathWithinRoot(
                "${_header_path}" "${PROJECT_SOURCE_DIR}/Src/Prism" "private header" "${Target}")
        endforeach()
    endif()
endfunction()

function(AssertPrismTargetIncludes Target)
    if(NOT TARGET "${Target}")
        message(FATAL_ERROR "Required Prism target is missing: ${Target}")
    endif()

    foreach(_property IN ITEMS INCLUDE_DIRECTORIES INTERFACE_INCLUDE_DIRECTORIES)
        get_target_property(_include_dirs "${Target}" ${_property})
        if(NOT _include_dirs OR _include_dirs MATCHES "-NOTFOUND$")
            continue()
        endif()
        foreach(_include_dir IN LISTS _include_dirs)
            if("${_property}" STREQUAL "INTERFACE_INCLUDE_DIRECTORIES")
                set(_public_include_dir "${_include_dir}")
                string(REPLACE "$<BUILD_INTERFACE:" "" _public_include_dir "${_public_include_dir}")
                string(REPLACE ">" "" _public_include_dir "${_public_include_dir}")
                file(TO_CMAKE_PATH "${_public_include_dir}" _normalized_public_include)
                if("${_normalized_public_include}" MATCHES "(^|/)Src(/|$)")
                    message(FATAL_ERROR
                        "Prism target ${Target} exposes Src as a public include root: ${_include_dir}")
                endif()
            endif()
            if("${_include_dir}" MATCHES "\$<")
                continue()
            endif()
            file(TO_CMAKE_PATH "${_include_dir}" _normalized_include)
            if("${_normalized_include}" MATCHES "(^|/)src/prism(/|$)|(^|/)include/prism(/|$)|(^|/)tests/(TestSupport|common)(/|$)|(^|/)psm(::|/|$)")
                message(FATAL_ERROR
                    "Prism target ${Target} exposes a forbidden include directory: ${_include_dir}")
            endif()
        endforeach()
    endforeach()
endfunction()

function(AssertPrismApplicationSources Target)
    get_target_property(_source_dir "${Target}" SOURCE_DIR)
    file(TO_CMAKE_PATH "${CMAKE_SOURCE_DIR}/Src/Prism/Application" _application_root)
    get_target_property(_sources "${Target}" SOURCES)
    if(NOT _sources OR _sources MATCHES "-NOTFOUND$")
        message(FATAL_ERROR "Prism application target has no concrete sources: ${Target}")
    endif()
    foreach(_source IN LISTS _sources)
        get_filename_component(_source_path "${_source}" ABSOLUTE BASE_DIR "${_source_dir}")
        file(TO_CMAKE_PATH "${_source_path}" _normalized_source)
        AssertPrismExactCasePath("${_source_path}")
        string(FIND "${_normalized_source}" "${_application_root}" _application_prefix)
        if(NOT _application_prefix EQUAL 0)
            message(FATAL_ERROR
                "Prism application target ${Target} owns a source outside Prism/Application: ${_source_path}")
        endif()
    endforeach()
endfunction()

function(AssertPrismStandaloneClosure Target)
    if(NOT TARGET "${Target}")
        message(FATAL_ERROR "Required standalone Prism target is missing: ${Target}")
    endif()

    AssertPrismExactCasePath("${CMAKE_SOURCE_DIR}/Include/Prism")
    AssertPrismExactCasePath("${CMAKE_SOURCE_DIR}/Src/Prism")
    AssertPrismExactCasePath("${CMAKE_SOURCE_DIR}/Test/Prism")
    message(STATUS "AssertPrismExactCasePaths passed: Include/Prism, Src/Prism, and Test/Prism")

    CollectPrismTargetClosure(${Target} _closure)
    foreach(_dependency IN LISTS _closure)
        if("${_dependency}" MATCHES "^(PrismStaticLibrary|TestSupport|PrismTestSupport|ProductionTestSupport|ContractTestSupport)$")
            message(FATAL_ERROR
                "Standalone Prism target ${Target} transitively links forbidden target ${_dependency}: ${_closure}")
        endif()
    endforeach()

    set(_targets "${Target};${_closure}")
    list(REMOVE_DUPLICATES _targets)
    foreach(_target IN LISTS _targets)
        if(NOT "${_target}" MATCHES "^Prism" OR "${_target}" STREQUAL "PrismSqlite")
            continue()
        endif()
        AssertPrismTargetSources(${_target})
        AssertPrismTargetIncludes(${_target})
    endforeach()
    AssertPrismApplicationSources(PrismApplication)
    message(STATUS "AssertPrismStandaloneClosure passed: ${Target} -> ${_closure}")
endfunction()

function(AssertPrismDiagnoseBackendBoundary)
    if(NOT TARGET PrismApplication OR NOT TARGET PrismDiagnoseBackend OR NOT TARGET PrismFoundation)
        message(FATAL_ERROR "Diagnose backend boundary targets are incomplete")
    endif()

    CollectPrismTargetClosure(PrismApplication _application_closure)
    list(FIND _application_closure "PrismDiagnoseBackend" _diagnose_backend_index)
    if(_diagnose_backend_index EQUAL -1)
        message(FATAL_ERROR "PrismApplication must depend on PrismDiagnoseBackend")
    endif()

    set(_business_targets)
    set(_prism_targets "Prism;PrismApplication;${_application_closure}")
    list(REMOVE_DUPLICATES _prism_targets)
    foreach(_target IN LISTS _prism_targets)
        if(NOT "${_target}" MATCHES "^Prism")
            continue()
        endif()
        foreach(_property IN ITEMS LINK_LIBRARIES INTERFACE_LINK_LIBRARIES
                                   INCLUDE_DIRECTORIES INTERFACE_INCLUDE_DIRECTORIES
                                   COMPILE_DEFINITIONS INTERFACE_COMPILE_DEFINITIONS
                                   COMPILE_OPTIONS INTERFACE_COMPILE_OPTIONS)
            get_target_property(_values "${_target}" ${_property})
            if(NOT _values OR _values MATCHES "-NOTFOUND$")
                continue()
            endif()
            foreach(_value IN LISTS _values)
                if("${_value}" MATCHES "spdlog|SPDLOG_COMPILED_LIB")
                    message(FATAL_ERROR
                        "Prism production target ${_target} uses spdlog through ${_property}: ${_value}")
                endif()
            endforeach()
        endforeach()
        if(NOT "${_target}" STREQUAL "PrismApplication")
            list(APPEND _business_targets "${_target}")
        endif()
    endforeach()

    get_target_property(_application_public_includes PrismApplication INTERFACE_INCLUDE_DIRECTORIES)
    CollectPrismTargetClosure(Prism _standalone_closure)

    set(_report "${CMAKE_BINARY_DIR}/prism-diagnose-target-closure.txt")
    file(WRITE "${_report}"
        "diagnose_backend_target=PrismDiagnoseBackend\n"
        "spdlog_prism_dependencies=none\n"
        "application_public_include_directories=${_application_public_includes}\n"
        "business_prism_targets=${_business_targets}\n"
        "standalone_link_closure=${_standalone_closure}\n")
    message(STATUS
        "AssertPrismDiagnoseBackendBoundary passed: production closure has no spdlog dependency; report ${_report}")
endfunction()
