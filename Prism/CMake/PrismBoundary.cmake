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
    spdlog::spdlog
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
        # Foundation 位于 Prism target 图底层。
    elseif("${Consumer}" STREQUAL "PrismAccount")
        set(_allowed PrismFoundation)
    elseif("${Consumer}" STREQUAL "PrismLifecycle")
        set(_allowed PrismFoundation)
    elseif("${Consumer}" STREQUAL "PrismResource")
        set(_allowed PrismFoundation PrismLifecycle)
    elseif("${Consumer}" STREQUAL "PrismStatistics")
        set(_allowed PrismFoundation)
    elseif("${Consumer}" STREQUAL "PrismOperations")
        # C05 拆分 Operations/Statistics 编译归属。
        set(_allowed PrismFoundation PrismStatistics)
    elseif("${Consumer}" STREQUAL "PrismTransport")
        set(_allowed PrismFoundation PrismLifecycle PrismIoContracts)
    elseif("${Consumer}" STREQUAL "PrismIoContracts")
        set(_allowed PrismFoundation)
    elseif("${Consumer}" STREQUAL "PrismNet")
        set(_allowed PrismTransport PrismFoundation PrismDatagramContract PrismNetworkModel PrismStreamContract)
    elseif("${Consumer}" STREQUAL "PrismIngressModel")
        # 值身份/trace 元数据属于模型，不属于反向调用 Net 的工厂契约。
        set(_allowed PrismFoundation PrismLifecycle)
    elseif("${Consumer}" STREQUAL "PrismDatagramContract" OR "${Consumer}" STREQUAL "PrismNetworkModel")
        set(_allowed PrismFoundation)
    elseif("${Consumer}" STREQUAL "PrismStreamContract")
        set(_allowed PrismNetworkModel PrismFoundation PrismAccount PrismTransport PrismIngressModel)
    elseif("${Consumer}" STREQUAL "PrismIngressContract")
        set(_allowed PrismFoundation PrismAccount PrismLifecycle PrismTransport PrismNet PrismIngressModel PrismDatagramContract PrismStreamContract)
    elseif("${Consumer}" STREQUAL "PrismBoundary")
        set(_allowed
            PrismDatagramContract
            PrismIngressContract
            PrismFoundation
            PrismNet
            PrismProtocolQuic
            PrismProtocolQuicNative
        )
    elseif("${Consumer}" STREQUAL "PrismRuntime")
        # Runtime 只拥有调度和会话契约，不再直接消费 Configuration。
        set(_allowed
            PrismIngressContract
            PrismStatistics
            PrismNet
            PrismTransport
            PrismFoundation
            PrismLifecycle
            PrismAccount
            PrismResource
        )
    elseif("${Consumer}" STREQUAL "PrismComposition")
        set(_allowed
            PrismAccount
            PrismFoundation
            PrismNet
            PrismRuntime
            PrismProtocolMux
            PrismProtocolXhttp
            PrismProtocolGun
            PrismProtocolTuic
            PrismProtocolQuic
            PrismProtocolQuicNative
            PrismProtocolHysteria2
            PrismProtocolReality
            PrismProtocolHttp3
            PrismProtocolsCommon
            PrismProtocolHttp
            PrismProtocolSocks5
            PrismProtocolVmess
            PrismProtocolVless
            PrismProtocolTrojan
            PrismProtocolShadowsocks2022
            PrismProtocolAnytls
            PrismProtocolRestls
            PrismProtocolTrusttunnel
            # Recognition 的真实 carrier factory 直接消费这两个协议 owner。
            PrismProtocolShadowtls
            PrismProtocolWs
            PrismProtocolNative
        )
        # C05 过渡：Composition 暂时消费 Operations/Statistics。
        list(APPEND _allowed PrismOperations PrismStatistics)
    elseif("${Consumer}" STREQUAL "PrismConfiguration")
        # C03 过渡：Configuration 暂时消费 Account 合同。
        set(_allowed PrismFoundation PrismAccount PrismIngressModel)
    elseif("${Consumer}" STREQUAL "PrismProtocolsCommon")
        set(_allowed PrismTransport PrismFoundation PrismIngressContract PrismLifecycle)
    elseif("${Consumer}" STREQUAL "PrismProtocolHttp2")
        set(_allowed PrismProtocolsCommon PrismProtocolHttp3Core)
    elseif("${Consumer}" STREQUAL "PrismProtocolHttp3Core")
        set(_allowed PrismProtocolsCommon PrismProtocolQuic)
    elseif("${Consumer}" STREQUAL "PrismProtocolQuic")
        set(_allowed PrismProtocolsCommon)
    elseif("${Consumer}" STREQUAL "PrismProtocolQuicNative")
        # QUIC 关闭 owner 直接消费中立 TrafficSink 与 typed 统计退休契约。
        set(_allowed PrismProtocolQuic PrismIngressContract PrismProtocolsCommon PrismLifecycle PrismFoundation)
    elseif("${Consumer}" STREQUAL "PrismProtocolHttp")
        # HTTP 协议工厂直接消费唯一入站结果与所有权守卫，不反向依赖装配层。
        set(_allowed PrismProtocolsCommon PrismIngressContract)
    elseif("${Consumer}" STREQUAL "PrismProtocolHttp3")
        set(_allowed PrismProtocolsCommon PrismProtocolHttp3Core PrismProtocolQuic PrismProtocolQuicNative)
    elseif("${Consumer}" STREQUAL "PrismProtocolHysteria2")
        set(_allowed
            PrismProtocolsCommon
            PrismProtocolHttp3Core
            PrismProtocolQuic
            PrismTransport
            PrismFoundation
            PrismAccount)
        list(APPEND _allowed PrismProtocolHttp3 PrismProtocolQuicNative PrismIngressContract PrismLifecycle)
    elseif("${Consumer}" STREQUAL "PrismProtocolShadowsocks2022")
        set(_allowed PrismProtocolsCommon PrismIngressContract PrismAccount PrismLifecycle PrismProtocolMux)
    elseif("${Consumer}" STREQUAL "PrismProtocolSocks5")
        set(_allowed PrismProtocolsCommon PrismIngressContract PrismAccount PrismLifecycle PrismProtocolMux)
    elseif("${Consumer}" STREQUAL "PrismProtocolTrojan")
        set(_allowed PrismProtocolsCommon PrismIngressContract PrismLifecycle PrismAccount PrismNet PrismProtocolMux)
    elseif("${Consumer}" STREQUAL "PrismProtocolTuic")
        set(_allowed
            PrismProtocolsCommon
            PrismProtocolQuic
            PrismAccount
            PrismFoundation
            PrismTransport
        )
        list(APPEND _allowed PrismProtocolQuicNative PrismIngressContract PrismLifecycle)
    elseif("${Consumer}" STREQUAL "PrismProtocolVless")
        set(_allowed PrismProtocolsCommon PrismIngressContract PrismLifecycle PrismAccount PrismNet PrismProtocolMux)
    elseif("${Consumer}" STREQUAL "PrismProtocolVmess")
        set(_allowed PrismProtocolsCommon PrismIngressContract PrismLifecycle PrismAccount PrismNet PrismProtocolMux)
    elseif("${Consumer}" STREQUAL "PrismProtocolMux")
        set(_allowed PrismProtocolsCommon PrismIngressContract PrismLifecycle PrismAccount PrismNet PrismProtocolHttp2)
    elseif("${Consumer}" STREQUAL "PrismProtocolAnytls")
        set(_allowed PrismProtocolsCommon PrismIngressContract PrismLifecycle PrismAccount PrismNet PrismProtocolMux)
    elseif("${Consumer}" STREQUAL "PrismProtocolEch")
        set(_allowed PrismProtocolsCommon)
    elseif("${Consumer}" STREQUAL "PrismProtocolGun")
        set(_allowed PrismProtocolsCommon PrismProtocolHttp2)
    elseif("${Consumer}" STREQUAL "PrismProtocolNative")
        set(_allowed PrismProtocolsCommon)
    elseif("${Consumer}" STREQUAL "PrismProtocolReality")
        set(_allowed PrismProtocolsCommon PrismIngressContract)
    elseif("${Consumer}" STREQUAL "PrismProtocolRestls")
        set(_allowed PrismProtocolsCommon PrismIngressContract)
    elseif("${Consumer}" STREQUAL "PrismProtocolShadowtls")
        set(_allowed PrismProtocolsCommon PrismIngressContract)
    elseif("${Consumer}" STREQUAL "PrismProtocolTrusttunnel")
        set(_allowed PrismProtocolsCommon PrismProtocolHttp2 PrismIngressContract PrismAccount)
    elseif("${Consumer}" STREQUAL "PrismProtocolWs")
        set(_allowed PrismProtocolsCommon)
    elseif("${Consumer}" STREQUAL "PrismProtocolXhttp")
        set(_allowed PrismProtocolsCommon PrismProtocolHttp2)
    elseif("${Consumer}" STREQUAL "PrismDiagnoseBackend")
        set(_allowed PrismFoundation)
    elseif("${Consumer}" STREQUAL "PrismApplication")
        set(_allowed
            PrismFoundation
            PrismLifecycle
            PrismRuntime
            PrismAccount
            PrismResource
            PrismConfiguration
            PrismOperations
            PrismComposition
            PrismBoundary
            PrismDiagnoseBackend
            PrismProtocolEch
        )
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
    foreach(Dependency IN LISTS ARGN)
        AssertPrismDependency(${Consumer} ${Dependency})
    endforeach()
    target_link_libraries(${Consumer} INTERFACE ${ARGN})
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
            if("${_source}" MATCHES "\$<")
                continue()
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
        endforeach()
    endforeach()
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
    file(TO_CMAKE_PATH "${CMAKE_SOURCE_DIR}/Prism/Application" _application_root)
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

    AssertPrismExactCasePath("${CMAKE_SOURCE_DIR}/Prism")
    AssertPrismExactCasePath("${CMAKE_SOURCE_DIR}/tests/Prism")
    message(STATUS "AssertPrismExactCasePaths passed: Prism and tests/Prism")

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
        if(NOT "${_target}" MATCHES "^(Prism|Prism)")
            continue()
        endif()
        AssertPrismTargetSources(${_target})
        AssertPrismTargetIncludes(${_target})
    endforeach()
    AssertPrismApplicationSources(PrismApplication)
    message(STATUS "AssertPrismStandaloneClosure passed: ${Target} -> ${_closure}")
endfunction()

function(AssertPrismDiagnoseBackendBoundary)
    if(NOT TARGET PrismApplication OR NOT TARGET PrismFoundation OR NOT TARGET spdlog::spdlog)
        message(FATAL_ERROR "Diagnose backend boundary targets are incomplete")
    endif()

    get_target_property(_application_links PrismApplication LINK_LIBRARIES)
    list(FIND _application_links "spdlog::spdlog" _private_spdlog_index)
    if(_private_spdlog_index EQUAL -1)
        message(FATAL_ERROR "PrismApplication must privately link spdlog::spdlog")
    endif()

    get_target_property(_application_interface_links PrismApplication INTERFACE_LINK_LIBRARIES)
    foreach(_link IN LISTS _application_interface_links)
        if("${_link}" MATCHES "spdlog")
            if(NOT "${_link}" MATCHES "^\\$<LINK_ONLY:spdlog::spdlog>$")
                message(FATAL_ERROR
                    "spdlog must not be exposed as a PrismApplication interface dependency: ${_link}")
            endif()
        endif()
    endforeach()

    CollectPrismTargetClosure(PrismApplication _application_closure)
    set(_business_targets)
    foreach(_target IN LISTS _application_closure)
        if(NOT "${_target}" MATCHES "^Prism" OR "${_target}" STREQUAL "PrismApplication")
            continue()
        endif()
        list(APPEND _business_targets "${_target}")
        foreach(_property IN ITEMS LINK_LIBRARIES INTERFACE_LINK_LIBRARIES
                                   INCLUDE_DIRECTORIES INTERFACE_INCLUDE_DIRECTORIES)
            get_target_property(_values "${_target}" ${_property})
            if(NOT _values OR _values MATCHES "-NOTFOUND$")
                continue()
            endif()
            foreach(_value IN LISTS _values)
                if("${_value}" MATCHES "spdlog")
                    message(FATAL_ERROR
                        "Prism business target ${_target} exposes spdlog through ${_property}: ${_value}")
                endif()
            endforeach()
        endforeach()
    endforeach()

    get_target_property(_application_public_includes PrismApplication INTERFACE_INCLUDE_DIRECTORIES)
    if(_application_public_includes MATCHES "spdlog")
        message(FATAL_ERROR "PrismApplication exposes spdlog include directories publicly")
    endif()
    get_target_property(_spdlog_include_directories spdlog::spdlog INTERFACE_INCLUDE_DIRECTORIES)
    CollectPrismTargetClosure(Prism _standalone_closure)

    set(_report "${CMAKE_BINARY_DIR}/prism-diagnose-target-closure.txt")
    file(WRITE "${_report}"
        "backend_owner=PrismApplication\n"
        "private_backend_link=spdlog::spdlog\n"
        "spdlog_compile_include_directories=${_spdlog_include_directories}\n"
        "application_public_include_directories=${_application_public_includes}\n"
        "business_prism_targets=${_business_targets}\n"
        "standalone_link_closure=${_standalone_closure}\n")
    message(STATUS
        "AssertPrismDiagnoseBackendBoundary passed: private spdlog owner; report ${_report}")
endfunction()
