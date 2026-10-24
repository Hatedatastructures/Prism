# Go 工具只在显式互操作构建中参与 all；默认构建不触发 Go 模块下载。
find_program(PRISM_GO_EXECUTABLE NAMES go)
if(NOT PRISM_GO_EXECUTABLE)
    return()
endif()

set(_PRISM_GO_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(_PRISM_GO_BINARY_DIR ${CMAKE_BINARY_DIR}/Test/Prism/Integration/Go)
file(MAKE_DIRECTORY ${_PRISM_GO_BINARY_DIR})

function(AddPrismGoTool TargetName OutputName SourceDirectory BuildByDefault)
    set(_Output "${_PRISM_GO_BINARY_DIR}/${OutputName}${CMAKE_EXECUTABLE_SUFFIX}")
    set(_Source "${_PRISM_GO_SOURCE_DIR}/${SourceDirectory}/main.go")
    add_custom_command(
        OUTPUT "${_Output}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${_PRISM_GO_BINARY_DIR}"
        COMMAND "${PRISM_GO_EXECUTABLE}" build -o "${_Output}" "./${SourceDirectory}"
        DEPENDS "${_Source}" "${_PRISM_GO_SOURCE_DIR}/go.mod" "${_PRISM_GO_SOURCE_DIR}/go.sum"
        WORKING_DIRECTORY "${_PRISM_GO_SOURCE_DIR}"
        VERBATIM)
    if(BuildByDefault)
        add_custom_target(${TargetName} ALL DEPENDS "${_Output}")
    else()
        add_custom_target(${TargetName} DEPENDS "${_Output}")
    endif()
endfunction()

set(_GoCmpSources
    realitycmp shadowtlscmp restlscmp anytlscmp trusttunnelcmp wscmp guncmp
    httpcmp socks5cmp trojancmp vlesscmp hysteria2cmp tuiccmp xhttpcmp vmesscmp)
set(_GoCmpTargets
    GoCmpReality GoCmpShadowtls GoCmpRestls GoCmpAnytls GoCmpTrusttunnel GoCmpWs
    GoCmpGun GoCmpHttp GoCmpSocks5 GoCmpTrojan GoCmpVless GoCmpHysteria2
    GoCmpTuic GoCmpXhttp GoCmpVmess)
list(LENGTH _GoCmpSources _GoCmpCount)
math(EXPR _GoCmpLast "${_GoCmpCount} - 1")
foreach(_Index RANGE 0 ${_GoCmpLast})
    list(GET _GoCmpSources ${_Index} _CmpSource)
    list(GET _GoCmpTargets ${_Index} _CmpTarget)
    AddPrismGoTool(${_CmpTarget} ${_CmpSource} ${_CmpSource} ${PRISM_ENABLE_INTEROP})
    if(PRISM_ENABLE_INTEROP)
        add_test(NAME ${_CmpTarget} COMMAND
            "${_PRISM_GO_BINARY_DIR}/${_CmpSource}${CMAKE_EXECUTABLE_SUFFIX}")
        set_tests_properties(${_CmpTarget} PROPERTIES TIMEOUT 30 LABELS interop)
    endif()
endforeach()

# 外部客户端与服务端由 scripts/interop/Run-Matrix.ps1 驱动。
AddPrismGoTool(GoTestHysteria2 hysteria2 hysteria2 ${PRISM_ENABLE_INTEROP})
AddPrismGoTool(GoTestTuic tuic tuic ${PRISM_ENABLE_INTEROP})
AddPrismGoTool(GoTestShadowtls shadowtls shadowtls ${PRISM_ENABLE_INTEROP})
AddPrismGoTool(GoTestHysteria2Server hysteria2_server hysteria2_server ${PRISM_ENABLE_INTEROP})
AddPrismGoTool(GoTestVmess vmess_client VmessClient ${PRISM_ENABLE_INTEROP})
AddPrismGoTool(GoTestSingVmess singvmess singvmess ${PRISM_ENABLE_INTEROP})
AddPrismGoTool(GoTestVmessServer vmess_server VmessServer ${PRISM_ENABLE_INTEROP})
AddPrismGoTool(GoTestTuicServer tuic_server tuic_server ${PRISM_ENABLE_INTEROP})
AddPrismGoTool(GoTestVless vless Vless ${PRISM_ENABLE_INTEROP})
AddPrismGoTool(GoTestSocks5 socks5 socks5 ${PRISM_ENABLE_INTEROP})
AddPrismGoTool(GoTestHttp http http ${PRISM_ENABLE_INTEROP})
AddPrismGoTool(GoTestNativeTls native_tls native_tls ${PRISM_ENABLE_INTEROP})
AddPrismGoTool(GoTestWebsocket websocket websocket ${PRISM_ENABLE_INTEROP})
AddPrismGoTool(GoTestAnytls anytls anytls ${PRISM_ENABLE_INTEROP})
AddPrismGoTool(GoTestGun gun gun ${PRISM_ENABLE_INTEROP})
AddPrismGoTool(GoTestGunGrpc gun_grpc gun_grpc ${PRISM_ENABLE_INTEROP})
AddPrismGoTool(GoTestXhttp xhttp xhttp ${PRISM_ENABLE_INTEROP})
AddPrismGoTool(GoTestTrusttunnel trusttunnel trusttunnel ${PRISM_ENABLE_INTEROP})
AddPrismGoTool(GoTestSs2022Client ss2022_client Interop/Ss2022Client ${PRISM_ENABLE_INTEROP})
AddPrismGoTool(GoTestSs2022Server ss2022_server Interop/Ss2022Server ${PRISM_ENABLE_INTEROP})

set(_TrojanGoBinary ${_PRISM_GO_BINARY_DIR}/trojan${CMAKE_EXECUTABLE_SUFFIX})
add_custom_command(
    OUTPUT "${_TrojanGoBinary}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_PRISM_GO_BINARY_DIR}"
    COMMAND "${PRISM_GO_EXECUTABLE}" build -o "${_TrojanGoBinary}" .
    DEPENDS "${_PRISM_GO_SOURCE_DIR}/Trojan/main.go" "${_PRISM_GO_SOURCE_DIR}/Trojan/go.mod"
    WORKING_DIRECTORY "${_PRISM_GO_SOURCE_DIR}/Trojan"
    VERBATIM)
if(PRISM_ENABLE_INTEROP)
    add_custom_target(GoTestTrojan ALL DEPENDS "${_TrojanGoBinary}")
else()
    add_custom_target(GoTestTrojan DEPENDS "${_TrojanGoBinary}")
endif()
