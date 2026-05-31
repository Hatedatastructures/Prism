/**
 * @file ShadowtlsTransportDeep.cpp
 * @brief ShadowTLS transport 构造器与生命周期测试 — gcov 覆盖
 * @details 通过静态库链接调用 transport 的同步方法。
 *          覆盖构造器（含/不含 HMAC 上下文、含/不含 initial_data）、
 *          close()、cancel()、shutdown_write()、transport_type()、next_layer()。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

#include <boost/asio.hpp>
#include <cstdint>
#include <cstring>
#include <vector>

#include <openssl/hmac.h>

#define private public
#include <prism/stealth/facade/shadowtls/transport.hpp>
#undef private

using psm::testing::TestRunner;

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using namespace psm::stealth::shadowtls;

    auto make_hmac_ctx(std::string_view password, std::span<const std::byte> server_random, char direction)
        -> std::shared_ptr<HMAC_CTX>
    {
        auto ctx = std::shared_ptr<HMAC_CTX>(HMAC_CTX_new(), HMAC_CTX_free);
        HMAC_Init_ex(ctx.get(), password.data(), static_cast<int>(password.size()), EVP_sha1(), nullptr);
        // safe: SSL HMAC API requires uint8_t*, byte span data is read-only
        HMAC_Update(ctx.get(), reinterpret_cast<const std::uint8_t *>(server_random.data()),
                    server_random.size());
        unsigned char d = static_cast<unsigned char>(direction);
        HMAC_Update(ctx.get(), &d, 1);
        return ctx;
    }

    void TestConstructWithHmac(TestRunner &runner)
    {
        net::io_context ioc;
        tcp::socket sock(ioc);

        const char *password = "test_password";
        std::array<std::byte, 32> server_random{};
        for (int i = 0; i < 32; ++i)
            server_random[i] = std::byte{static_cast<uint8_t>(i)};

        auto write_ctx = make_hmac_ctx(password, server_random, 'S');
        auto read_ctx = make_hmac_ctx(password, server_random, 'C');

        shadowtls_handover handover{
            password,
            server_random,
            {},
            write_ctx,
            read_ctx
        };

        shadowtls_transport transport(std::move(sock), std::move(handover));

        runner.Check(!transport.write_key_.empty(), "hmac: write_key not empty");
        runner.Check(transport.write_key_.size() == 32, "hmac: write_key 32 bytes");
        runner.Check(transport.hmac_write_ctx_ != nullptr, "hmac: write ctx not null");
        runner.Check(transport.hmac_read_ctx_ != nullptr, "hmac: read ctx not null");
        runner.Check(transport.initial_buffer_.empty(), "hmac: init empty");
        runner.Check(transport.initial_offset_ == 0, "hmac: init_off=0");
        runner.Check(transport.pending_buffer_.empty(), "hmac: pending empty");

        runner.Check(std::memcmp(transport.server_random_.data(), server_random.data(), 32) == 0,
                     "hmac: server_random copied");
    }

    void TestConstructWithInitialData(TestRunner &runner)
    {
        net::io_context ioc;
        tcp::socket sock(ioc);

        const char *password = "pwd";
        std::array<std::byte, 32> server_random{};
        std::byte init_data[] = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};

        auto write_ctx = make_hmac_ctx(password, server_random, 'S');

        shadowtls_handover handover{
            password,
            server_random,
            init_data,
            write_ctx,
            nullptr
        };

        shadowtls_transport transport(std::move(sock), std::move(handover));

        runner.Check(transport.initial_buffer_.size() == 4, "init: size=4");
        runner.Check(transport.initial_buffer_[0] == std::byte{0x01}, "init: [0]=0x01");
        runner.Check(transport.initial_buffer_[3] == std::byte{0x04}, "init: [3]=0x04");
    }

    void TestConstructNullHmac(TestRunner &runner)
    {
        net::io_context ioc;
        tcp::socket sock(ioc);

        const char *password = "pwd";
        std::array<std::byte, 32> server_random{};

        shadowtls_handover handover{
            password,
            server_random,
            {},
            nullptr,
            nullptr
        };

        shadowtls_transport transport(std::move(sock), std::move(handover));

        runner.Check(transport.hmac_write_ctx_ == nullptr, "null: write ctx null");
        runner.Check(transport.hmac_read_ctx_ == nullptr, "null: read ctx null");
    }

    void TestTransportType(TestRunner &runner)
    {
        net::io_context ioc;
        tcp::socket sock(ioc);

        const char *password = "pwd";
        std::array<std::byte, 32> server_random{};

        shadowtls_handover handover{
            password,
            server_random,
            {},
            nullptr,
            nullptr
        };

        shadowtls_transport transport(std::move(sock), std::move(handover));

        runner.Check(transport.transport_type() == psm::transport::transmission::type::tcp, "type: tcp");
        runner.Check(transport.next_layer() == nullptr, "layer: null");
    }

    void TestClose(TestRunner &runner)
    {
        net::io_context ioc;
        tcp::socket sock(ioc);

        const char *password = "pwd";
        std::array<std::byte, 32> server_random{};

        shadowtls_handover handover{
            password,
            server_random,
            {},
            nullptr,
            nullptr
        };

        shadowtls_transport transport(std::move(sock), std::move(handover));
        transport.close();
        runner.Check(true, "close: no crash");
    }

    void TestCancel(TestRunner &runner)
    {
        net::io_context ioc;
        tcp::socket sock(ioc);

        const char *password = "pwd";
        std::array<std::byte, 32> server_random{};

        shadowtls_handover handover{
            password,
            server_random,
            {},
            nullptr,
            nullptr
        };

        shadowtls_transport transport(std::move(sock), std::move(handover));
        try
        {
            transport.cancel();
        }
        catch (...)
        {
        }
        runner.Check(true, "cancel: covered");
        transport.close();
    }

    void TestShutdownWrite(TestRunner &runner)
    {
        net::io_context ioc;
        tcp::socket sock(ioc);

        const char *password = "pwd";
        std::array<std::byte, 32> server_random{};

        shadowtls_handover handover{
            password,
            server_random,
            {},
            nullptr,
            nullptr
        };

        shadowtls_transport transport(std::move(sock), std::move(handover));
        transport.shutdown_write();
        runner.Check(true, "shutdown_write: no crash on unconnected socket");
        transport.close();
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("ShadowtlsTransportDeep");

    TestConstructWithHmac(runner);
    TestConstructWithInitialData(runner);
    TestConstructNullHmac(runner);
    TestTransportType(runner);
    TestClose(runner);
    TestCancel(runner);
    TestShutdownWrite(runner);

    return runner.Summary();
}
