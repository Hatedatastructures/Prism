# Go 参考实现与互操作向量：所有有 Go 编译器的平台都注册这些工具。
find_program(PRISM_GO_EXECUTABLE NAMES go)
if(NOT PRISM_GO_EXECUTABLE)
    return()
endif()

set(_PRISM_GO_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(_PRISM_GO_BINARY_DIR ${CMAKE_BINARY_DIR}/tests/Prism/Integration/Go)
file(MAKE_DIRECTORY ${_PRISM_GO_BINARY_DIR})

function(AddPrismGoTool TargetName OutputName SourceDirectory)
    set(_Output "${_PRISM_GO_BINARY_DIR}/${OutputName}.exe")
    set(_Source "${_PRISM_GO_SOURCE_DIR}/${SourceDirectory}/main.go")
    add_custom_command(
        OUTPUT "${_Output}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${_PRISM_GO_BINARY_DIR}"
        COMMAND "${PRISM_GO_EXECUTABLE}" build -o "${_Output}" "./${SourceDirectory}"
        DEPENDS "${_Source}" "${_PRISM_GO_SOURCE_DIR}/go.mod" "${_PRISM_GO_SOURCE_DIR}/go.sum"
        WORKING_DIRECTORY "${_PRISM_GO_SOURCE_DIR}"
        VERBATIM)
    add_custom_target(${TargetName} ALL DEPENDS "${_Output}")
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
    AddPrismGoTool(${_CmpTarget} ${_CmpSource} ${_CmpSource})
    add_test(NAME ${_CmpTarget} COMMAND "${_PRISM_GO_BINARY_DIR}/${_CmpSource}.exe")
    set_tests_properties(${_CmpTarget} PROPERTIES TIMEOUT 30)
endforeach()

# 外部客户端与服务端由 scripts/interop/Run-Matrix.ps1 驱动。
AddPrismGoTool(GoTestHysteria2 hysteria2 hysteria2)
AddPrismGoTool(GoTestTuic tuic tuic)
AddPrismGoTool(GoTestShadowtls shadowtls shadowtls)
AddPrismGoTool(GoTestHysteria2Server hysteria2_server hysteria2_server)
AddPrismGoTool(GoTestVmess vmess_client VmessClient)
AddPrismGoTool(GoTestSingVmess singvmess singvmess)
AddPrismGoTool(GoTestVmessServer vmess_server VmessServer)
AddPrismGoTool(GoTestTuicServer tuic_server tuic_server)
AddPrismGoTool(GoTestVless vless Vless)
AddPrismGoTool(GoTestSocks5 socks5 socks5)
AddPrismGoTool(GoTestHttp http http)
AddPrismGoTool(GoTestNativeTls native_tls native_tls)
AddPrismGoTool(GoTestWebsocket websocket websocket)
AddPrismGoTool(GoTestAnytls anytls anytls)
AddPrismGoTool(GoTestGun gun gun)
AddPrismGoTool(GoTestGunGrpc gun_grpc gun_grpc)
AddPrismGoTool(GoTestXhttp xhttp xhttp)
AddPrismGoTool(GoTestTrusttunnel trusttunnel trusttunnel)
AddPrismGoTool(GoTestSs2022Client ss2022_client Interop/Ss2022Client)
AddPrismGoTool(GoTestSs2022Server ss2022_server Interop/Ss2022Server)

set(_TrojanGoBinary ${_PRISM_GO_BINARY_DIR}/trojan.exe)
add_custom_command(
    OUTPUT "${_TrojanGoBinary}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_PRISM_GO_BINARY_DIR}"
    COMMAND "${PRISM_GO_EXECUTABLE}" build -o "${_TrojanGoBinary}" .
    DEPENDS "${_PRISM_GO_SOURCE_DIR}/Trojan/main.go" "${_PRISM_GO_SOURCE_DIR}/Trojan/go.mod"
    WORKING_DIRECTORY "${_PRISM_GO_SOURCE_DIR}/Trojan"
    VERBATIM)
add_custom_target(GoTestTrojan ALL DEPENDS "${_TrojanGoBinary}")
