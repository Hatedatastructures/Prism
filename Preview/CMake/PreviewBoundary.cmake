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

    # 唯一事实源是 _GetPreviewAllowedInternalLinks；下面的逐消费者正则只是补充说明，
    # 判定权在此收口。依据：2025 条假想 Preview* 边实测有 551 条两表结论相反，
    # 且全部是“表 1 宽 / 表 2 严”，0 条反向 —— 因此本收口只收紧、不放宽任何现有边。
    if("${Dependency}" MATCHES "^Preview")
        _GetPreviewAllowedInternalLinks("${Consumer}" _allowed_internal)
        list(FIND _allowed_internal "${Dependency}" _allowed_index)
        if(_allowed_index EQUAL -1)
            message(FATAL_ERROR
                "Preview boundary violation: ${Consumer} -> ${Dependency} is not in "
                "${Consumer}'s allowed internal link set (_GetPreviewAllowedInternalLinks)")
        endif()
    endif()

    # 逐消费者正则已删除（原 78–175 行，共 98 行）。
    # 依据：46×46=2025 条假想 Preview* 边实测两表 0 分歧、0 条“表1严/表2宽”，
    # 保留它们不增加任何限制，只构成第二套正式事实 —— 计划 §W0-E/§M36 明令禁止。
    # 判定权唯一归 _GetPreviewAllowedInternalLinks；TestSupport 硬规则保留在上方。

endfunction()

set(_PreviewExternalLinkTargets
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
    ws2_32
    mswsock
    crypt32
)

function(_NormalizePreviewLinkEntry RawEntry OutputVariable)
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
            "Preview boundary cannot resolve link generator expression '${RawEntry}'; "
            "only LINK_ONLY and BUILD_INTERFACE are supported")
    endif()
    if(_iterations GREATER_EQUAL 4 AND "${_entry}" MATCHES "^\\$<")
        message(FATAL_ERROR
            "Preview boundary link generator expression is nested too deeply: ${RawEntry}")
    endif()
    set(${OutputVariable} "${_entry}" PARENT_SCOPE)
endfunction()

function(_ResolvePreviewAlias TargetName OutputVariable)
    set(_current "${TargetName}")
    set(_visited)
    while(TARGET "${_current}")
        list(FIND _visited "${_current}" _seen)
        if(NOT _seen EQUAL -1)
            message(FATAL_ERROR "Preview boundary alias cycle while resolving ${TargetName}")
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

function(_IsPreviewExternalLink RawEntry CanonicalEntry OutputVariable)
    set(_is_external FALSE)
    foreach(_candidate IN ITEMS "${RawEntry}" "${CanonicalEntry}")
        list(FIND _PreviewExternalLinkTargets "${_candidate}" _external_index)
        if(NOT _external_index EQUAL -1)
            set(_is_external TRUE)
        endif()
    endforeach()
    set(${OutputVariable} "${_is_external}" PARENT_SCOPE)
endfunction()

function(_GetPreviewAllowedInternalLinks Consumer OutputVariable)
    set(_allowed)
    if("${Consumer}" STREQUAL "PreviewFoundation")
        # Foundation 位于 Preview target 图底层。
    elseif("${Consumer}" STREQUAL "PreviewAccount")
        set(_allowed PreviewFoundation)
    elseif("${Consumer}" STREQUAL "PreviewLifecycle")
        set(_allowed PreviewFoundation)
    elseif("${Consumer}" STREQUAL "PreviewResource")
        set(_allowed PreviewFoundation PreviewLifecycle)
    elseif("${Consumer}" STREQUAL "PreviewStatistics")
        set(_allowed PreviewFoundation)
    elseif("${Consumer}" STREQUAL "PreviewOperations")
        # C05 拆分 Operations/Statistics 编译归属。
        set(_allowed PreviewFoundation PreviewStatistics)
    elseif("${Consumer}" STREQUAL "PreviewTransport")
        set(_allowed PreviewFoundation PreviewLifecycle PreviewIoContracts)
    elseif("${Consumer}" STREQUAL "PreviewIoContracts")
        set(_allowed PreviewFoundation)
    elseif("${Consumer}" STREQUAL "PreviewNet")
        set(_allowed PreviewTransport PreviewFoundation PreviewDatagramContract PreviewNetworkModel PreviewStreamContract)
    elseif("${Consumer}" STREQUAL "PreviewIngressModel")
        # 值身份/trace 元数据属于模型，不属于反向调用 Net 的工厂契约。
        set(_allowed PreviewFoundation PreviewLifecycle)
    elseif("${Consumer}" STREQUAL "PreviewDatagramContract" OR "${Consumer}" STREQUAL "PreviewNetworkModel")
        set(_allowed PreviewFoundation)
    elseif("${Consumer}" STREQUAL "PreviewStreamContract")
        set(_allowed PreviewNetworkModel PreviewFoundation PreviewAccount PreviewTransport PreviewIngressModel)
    elseif("${Consumer}" STREQUAL "PreviewIngressContract")
        set(_allowed PreviewFoundation PreviewAccount PreviewLifecycle PreviewTransport PreviewNet PreviewIngressModel PreviewDatagramContract PreviewStreamContract)
    elseif("${Consumer}" STREQUAL "PreviewBoundary")
        set(_allowed
            PreviewDatagramContract
            PreviewIngressContract
            PreviewFoundation
            PreviewNet
            PreviewProtocolQuic
            PreviewProtocolQuicNative
        )
    elseif("${Consumer}" STREQUAL "PreviewRuntime")
        # Runtime 只拥有调度和会话契约，不再直接消费 Configuration。
        set(_allowed
            PreviewIngressContract
            PreviewStatistics
            PreviewNet
            PreviewTransport
            PreviewFoundation
            PreviewLifecycle
            PreviewAccount
            PreviewResource
        )
    elseif("${Consumer}" STREQUAL "PreviewComposition")
        set(_allowed
            PreviewAccount
            PreviewFoundation
            PreviewNet
            PreviewRuntime
            PreviewProtocolMux
            PreviewProtocolXhttp
            PreviewProtocolGun
            PreviewProtocolTuic
            PreviewProtocolQuic
            PreviewProtocolQuicNative
            PreviewProtocolHysteria2
            PreviewProtocolReality
            PreviewProtocolHttp3
            PreviewProtocolsCommon
            PreviewProtocolHttp
            PreviewProtocolSocks5
            PreviewProtocolVmess
            PreviewProtocolVless
            PreviewProtocolTrojan
            PreviewProtocolShadowsocks2022
            PreviewProtocolAnytls
            PreviewProtocolRestls
            PreviewProtocolTrusttunnel
            # Recognition 的真实 carrier factory 直接消费这两个协议 owner。
            PreviewProtocolShadowtls
            PreviewProtocolWs
            PreviewProtocolNative
        )
        # C05 过渡：Composition 暂时消费 Operations/Statistics。
        list(APPEND _allowed PreviewOperations PreviewStatistics)
    elseif("${Consumer}" STREQUAL "PreviewConfiguration")
        # C03 过渡：Configuration 暂时消费 Account 合同。
        set(_allowed PreviewFoundation PreviewAccount PreviewIngressModel)
    elseif("${Consumer}" STREQUAL "PreviewProtocolsCommon")
        set(_allowed PreviewTransport PreviewFoundation PreviewIngressContract PreviewLifecycle)
    elseif("${Consumer}" STREQUAL "PreviewProtocolHttp2")
        set(_allowed PreviewProtocolsCommon PreviewProtocolHttp3Core)
    elseif("${Consumer}" STREQUAL "PreviewProtocolHttp3Core")
        set(_allowed PreviewProtocolsCommon PreviewProtocolQuic)
    elseif("${Consumer}" STREQUAL "PreviewProtocolQuic")
        set(_allowed PreviewProtocolsCommon)
    elseif("${Consumer}" STREQUAL "PreviewProtocolQuicNative")
        # QUIC 关闭 owner 直接消费中立 TrafficSink 与 typed 统计退休契约。
        set(_allowed PreviewProtocolQuic PreviewIngressContract PreviewProtocolsCommon PreviewLifecycle PreviewFoundation)
    elseif("${Consumer}" STREQUAL "PreviewProtocolHttp")
        # HTTP 协议工厂直接消费唯一入站结果与所有权守卫，不反向依赖装配层。
        set(_allowed PreviewProtocolsCommon PreviewIngressContract)
    elseif("${Consumer}" STREQUAL "PreviewProtocolHttp3")
        set(_allowed PreviewProtocolsCommon PreviewProtocolHttp3Core PreviewProtocolQuic PreviewProtocolQuicNative)
    elseif("${Consumer}" STREQUAL "PreviewProtocolHysteria2")
        set(_allowed
            PreviewProtocolsCommon
            PreviewProtocolHttp3Core
            PreviewProtocolQuic
            PreviewTransport
            PreviewFoundation
            PreviewAccount)
        list(APPEND _allowed PreviewProtocolHttp3 PreviewProtocolQuicNative PreviewIngressContract PreviewLifecycle)
    elseif("${Consumer}" STREQUAL "PreviewProtocolShadowsocks2022")
        set(_allowed PreviewProtocolsCommon PreviewIngressContract PreviewAccount PreviewLifecycle PreviewProtocolMux)
    elseif("${Consumer}" STREQUAL "PreviewProtocolSocks5")
        set(_allowed PreviewProtocolsCommon PreviewIngressContract PreviewAccount PreviewLifecycle PreviewProtocolMux)
    elseif("${Consumer}" STREQUAL "PreviewProtocolTrojan")
        set(_allowed PreviewProtocolsCommon PreviewIngressContract PreviewLifecycle PreviewAccount PreviewNet PreviewProtocolMux)
    elseif("${Consumer}" STREQUAL "PreviewProtocolTuic")
        set(_allowed
            PreviewProtocolsCommon
            PreviewProtocolQuic
            PreviewAccount
            PreviewFoundation
            PreviewTransport
        )
        list(APPEND _allowed PreviewProtocolQuicNative PreviewIngressContract PreviewLifecycle)
    elseif("${Consumer}" STREQUAL "PreviewProtocolVless")
        set(_allowed PreviewProtocolsCommon PreviewIngressContract PreviewLifecycle PreviewAccount PreviewNet PreviewProtocolMux)
    elseif("${Consumer}" STREQUAL "PreviewProtocolVmess")
        set(_allowed PreviewProtocolsCommon PreviewIngressContract PreviewLifecycle PreviewAccount PreviewNet PreviewProtocolMux)
    elseif("${Consumer}" STREQUAL "PreviewProtocolMux")
        set(_allowed PreviewProtocolsCommon PreviewIngressContract PreviewLifecycle PreviewAccount PreviewNet PreviewProtocolHttp2)
    elseif("${Consumer}" STREQUAL "PreviewProtocolAnytls")
        set(_allowed PreviewProtocolsCommon PreviewIngressContract PreviewLifecycle PreviewAccount PreviewNet PreviewProtocolMux)
    elseif("${Consumer}" STREQUAL "PreviewProtocolEch")
        set(_allowed PreviewProtocolsCommon)
    elseif("${Consumer}" STREQUAL "PreviewProtocolGun")
        set(_allowed PreviewProtocolsCommon PreviewProtocolHttp2)
    elseif("${Consumer}" STREQUAL "PreviewProtocolNative")
        set(_allowed PreviewProtocolsCommon)
    elseif("${Consumer}" STREQUAL "PreviewProtocolReality")
        set(_allowed PreviewProtocolsCommon PreviewIngressContract)
    elseif("${Consumer}" STREQUAL "PreviewProtocolRestls")
        set(_allowed PreviewProtocolsCommon PreviewIngressContract)
    elseif("${Consumer}" STREQUAL "PreviewProtocolShadowtls")
        set(_allowed PreviewProtocolsCommon PreviewIngressContract)
    elseif("${Consumer}" STREQUAL "PreviewProtocolTrusttunnel")
        set(_allowed PreviewProtocolsCommon PreviewProtocolHttp2 PreviewIngressContract PreviewAccount)
    elseif("${Consumer}" STREQUAL "PreviewProtocolWs")
        set(_allowed PreviewProtocolsCommon)
    elseif("${Consumer}" STREQUAL "PreviewProtocolXhttp")
        set(_allowed PreviewProtocolsCommon PreviewProtocolHttp2)
    elseif("${Consumer}" STREQUAL "PreviewDiagnoseBackend")
        set(_allowed PreviewFoundation)
    elseif("${Consumer}" STREQUAL "PreviewApplication")
        set(_allowed
            PreviewFoundation
            PreviewLifecycle
            PreviewRuntime
            PreviewAccount
            PreviewResource
            PreviewConfiguration
            PreviewOperations
            PreviewComposition
            PreviewBoundary
            PreviewDiagnoseBackend
            PreviewProtocolEch
        )
    elseif("${Consumer}" STREQUAL "PrismPreview")
        set(_allowed PreviewApplication)
    else()
        message(FATAL_ERROR
            "Preview boundary has no explicit internal edge policy for target ${Consumer}")
    endif()
    set(${OutputVariable} "${_allowed}" PARENT_SCOPE)
endfunction()

function(_CollectPreviewBuildsystemTargets Directory OutputVariable)
    get_property(_targets DIRECTORY "${Directory}" PROPERTY BUILDSYSTEM_TARGETS)
    get_property(_subdirectories DIRECTORY "${Directory}" PROPERTY SUBDIRECTORIES)
    set(_preview_targets)
    foreach(_target IN LISTS _targets)
        if("${_target}" MATCHES "^(Preview|PrismPreview)")
            list(APPEND _preview_targets "${_target}")
        endif()
    endforeach()
    foreach(_subdirectory IN LISTS _subdirectories)
        _CollectPreviewBuildsystemTargets("${_subdirectory}" _child_targets)
        list(APPEND _preview_targets ${_child_targets})
    endforeach()
    list(REMOVE_DUPLICATES _preview_targets)
    set(${OutputVariable} "${_preview_targets}" PARENT_SCOPE)
endfunction()

function(_AssertPreviewInternalLink Consumer RawEntry CanonicalEntry Property)
    if("${CanonicalEntry}" MATCHES "^(Preview|PrismPreview)")
        _GetPreviewAllowedInternalLinks("${Consumer}" _allowed)
        list(FIND _allowed "${CanonicalEntry}" _allowed_index)
        if(_allowed_index EQUAL -1)
            message(FATAL_ERROR
                "Forbidden Preview target edge: ${Consumer} -> ${RawEntry} "
                "(${CanonicalEntry}) from ${Property}")
        endif()
        return()
    endif()

    _IsPreviewExternalLink("${RawEntry}" "${CanonicalEntry}" _known_external)
    if(_known_external)
        return()
    endif()

    if(TARGET "${CanonicalEntry}")
        message(FATAL_ERROR
            "Unknown external Preview link target: ${Consumer} -> ${RawEntry} "
            "(${CanonicalEntry}) from ${Property}")
    endif()
    message(FATAL_ERROR
        "Unknown external Preview link item: ${Consumer} -> ${RawEntry} from ${Property}")
endfunction()

function(AssertPreviewTargetGraph)
    _CollectPreviewBuildsystemTargets("${CMAKE_CURRENT_SOURCE_DIR}" _preview_targets)
    if(NOT _preview_targets)
        message(FATAL_ERROR "Preview boundary found no Preview buildsystem targets")
    endif()

    foreach(_consumer IN LISTS _preview_targets)
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
                        "Forbidden dependency in Preview target ${_consumer}: ${_raw_entry}")
                endif()
                _NormalizePreviewLinkEntry("${_raw_entry}" _normalized_entries)
                foreach(_entry IN LISTS _normalized_entries)
                    if("${_entry}" STREQUAL "")
                        continue()
                    endif()
                    _ResolvePreviewAlias("${_entry}" _canonical_entry)
                    _AssertPreviewInternalLink(
                        "${_consumer}" "${_entry}" "${_canonical_entry}" "${_property}")
                endforeach()
            endforeach()
        endforeach()
    endforeach()
    message(STATUS "AssertPreviewTargetGraph passed: ${_preview_targets}")
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

function(AssertPreviewDiagnoseBackendBoundary)
    if(NOT TARGET PreviewApplication OR NOT TARGET PreviewFoundation OR NOT TARGET spdlog::spdlog)
        message(FATAL_ERROR "Diagnose backend boundary targets are incomplete")
    endif()

    get_target_property(_application_links PreviewApplication LINK_LIBRARIES)
    list(FIND _application_links "spdlog::spdlog" _private_spdlog_index)
    if(_private_spdlog_index EQUAL -1)
        message(FATAL_ERROR "PreviewApplication must privately link spdlog::spdlog")
    endif()

    get_target_property(_application_interface_links PreviewApplication INTERFACE_LINK_LIBRARIES)
    foreach(_link IN LISTS _application_interface_links)
        if("${_link}" MATCHES "spdlog")
            if(NOT "${_link}" MATCHES "^\\$<LINK_ONLY:spdlog::spdlog>$")
                message(FATAL_ERROR
                    "spdlog must not be exposed as a PreviewApplication interface dependency: ${_link}")
            endif()
        endif()
    endforeach()

    CollectPreviewTargetClosure(PreviewApplication _application_closure)
    set(_business_targets)
    foreach(_target IN LISTS _application_closure)
        if(NOT "${_target}" MATCHES "^Preview" OR "${_target}" STREQUAL "PreviewApplication")
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
                        "Preview business target ${_target} exposes spdlog through ${_property}: ${_value}")
                endif()
            endforeach()
        endforeach()
    endforeach()

    get_target_property(_application_public_includes PreviewApplication INTERFACE_INCLUDE_DIRECTORIES)
    if(_application_public_includes MATCHES "spdlog")
        message(FATAL_ERROR "PreviewApplication exposes spdlog include directories publicly")
    endif()
    get_target_property(_spdlog_include_directories spdlog::spdlog INTERFACE_INCLUDE_DIRECTORIES)
    CollectPreviewTargetClosure(PrismPreview _standalone_closure)

    set(_report "${CMAKE_BINARY_DIR}/preview-diagnose-target-closure.txt")
    file(WRITE "${_report}"
        "backend_owner=PreviewApplication\n"
        "private_backend_link=spdlog::spdlog\n"
        "spdlog_compile_include_directories=${_spdlog_include_directories}\n"
        "application_public_include_directories=${_application_public_includes}\n"
        "business_preview_targets=${_business_targets}\n"
        "standalone_link_closure=${_standalone_closure}\n")
    message(STATUS
        "AssertPreviewDiagnoseBackendBoundary passed: private spdlog owner; report ${_report}")
endfunction()
