/**
 * @file Hysteria2InteropBlocker.cpp
 * @brief Hysteria2 HTTP/3 初始化失败路径回归
 * @details 保留名称以避免扩大本轮 CMake 变更；真实互操作已经由
 *          InteropHysteria2 覆盖。本测试只确认没有可用单向流时，
 *          Http3::Server::Init() 不会接受无效 stream ID。
 */

#include <Preview/Protocols/Http3/Server.hpp>
#include <Preview/Protocols/Quic/Native.hpp>

#include <cstdint>
#include <cstdio>

namespace
{
    template <typename Type>
    concept HasOpenUnidirectionalStream = requires(Type &Value)
    {
        Value.OpenUnidirectionalStream();
    };
}

static_assert(HasOpenUnidirectionalStream<Preview::Quic::Server>);
static_assert(HasOpenUnidirectionalStream<Preview::Quic::Gateway>);

int main()
{
    bool OpenUniCallbackCalled = false;
    auto Http3Server = Preview::Http3::MakeServer(Preview::Http3::ServerOptions{});
    if (!Http3Server)
    {
        std::fprintf(stderr, "FAIL: cannot construct Preview HTTP3 server\n");
        return 1;
    }

    const auto Initialized = Http3Server->Init([&OpenUniCallbackCalled]() -> std::int64_t
    {
        OpenUniCallbackCalled = true;
        return -1;
    });
    Http3Server->Close();
    if (Initialized || !OpenUniCallbackCalled)
    {
        std::fprintf(stderr, "FAIL: HTTP3 server accepted unavailable unidirectional streams\n");
        return 1;
    }

    std::printf("PASS: HTTP3 rejects unavailable unidirectional stream IDs\n");
    return 0;
}
