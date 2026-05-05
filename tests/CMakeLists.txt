set(TEST_COMPILE_OPTS -g1 -Os -fno-keep-inline-dllexport)

function(forward_add_test test_name source_file)
    add_executable(${test_name} ${source_file})
    target_compile_options(${test_name} PRIVATE ${TEST_COMPILE_OPTS})
    target_link_libraries(${test_name} PRIVATE ${PROJECT_NAME}_static_library)
    add_test(NAME ${test_name} COMMAND ${test_name})
endfunction()

# ─── 基础设施 ────────────────────────────────────
forward_add_test(Session        Session.cpp)
forward_add_test(Connection     Connection.cpp)
forward_add_test(Transmission   Transmission.cpp)
forward_add_test(Trace          Trace.cpp)

# ─── 协议 ────────────────────────────────────────
forward_add_test(Http           Http.cpp)
forward_add_test(Socks5         Socks5.cpp)
forward_add_test(Trojan         Trojan.cpp)
forward_add_test(Vless          Vless.cpp)
forward_add_test(Shadowsocks    Shadowsocks.cpp)

# ─── 回归 ────────────────────────────────────────
forward_add_test(Regression     Regression.cpp)

# ─── 单元测试 ────────────────────────────────────
forward_add_test(HttpParser     HttpParser.cpp)
forward_add_test(Smux           Smux.cpp)
forward_add_test(SmuxCraft      SmuxCraft.cpp)
forward_add_test(Yamux          Yamux.cpp)
forward_add_test(YamuxCraft     YamuxCraft.cpp)
forward_add_test(MultiplexDuct  MultiplexDuct.cpp)
forward_add_test(Crypto         Crypto.cpp)
forward_add_test(Hkdf           Hkdf.cpp)
forward_add_test(Block          Block.cpp)
forward_add_test(Aead           Aead.cpp)
forward_add_test(Reality        Reality.cpp)
forward_add_test(Blake3         Blake3.cpp)
forward_add_test(X25519         X25519.cpp)
forward_add_test(DnsPacket      DnsPacket.cpp)
forward_add_test(DnsRules       DnsRules.cpp)
forward_add_test(Fault          Fault.cpp)
forward_add_test(Exception      Exception.cpp)
	forward_add_test(ProtocolAnalysis ProtocolAnalysis.cpp)
	forward_add_test(ProtocolToString ProtocolToString.cpp)
	forward_add_test(Balancer       Balancer.cpp)
	forward_add_test(DnsCache       DnsCache.cpp)
	forward_add_test(AccountDirectory AccountDirectory.cpp)
	forward_add_test(Shadowtls      Shadowtls.cpp)
forward_add_test(Restls         Restls.cpp)
forward_add_test(Config         Config.cpp)
forward_add_test(Base64Encode   Base64Encode.cpp)
forward_add_test(MemoryArena    MemoryArena.cpp)
forward_add_test(PipelinePrimitives PipelinePrimitives.cpp)
forward_add_test(Recognition    Recognition.cpp)
forward_add_test(Executor       Executor.cpp)
forward_add_test(FaultHandling  FaultHandling.cpp)


add_subdirectory(concurrency)

if(MINGW)
    foreach(t IN ITEMS
        Session Connection Transmission Trace
        Http Socks5 Trojan Vless Shadowsocks Regression
        HttpParser Smux SmuxCraft Yamux YamuxCraft MultiplexDuct Crypto Hkdf Block Aead Reality Blake3 X25519 DnsPacket DnsRules Fault Exception ProtocolAnalysis ProtocolToString
        Balancer DnsCache AccountDirectory Shadowtls Restls Base64Encode MemoryArena Config PipelinePrimitives Recognition Executor FaultHandling
        ConcurrencyServer ConcurrencyClient)
        if(TARGET ${t})
            target_compile_options(${t} PRIVATE -Wa,-mbig-obj)
        endif()
    endforeach()
endif()
