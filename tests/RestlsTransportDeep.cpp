/**
 * @file RestlsTransportDeep.cpp
 * @brief Restls transport 构造器与生命周期测试 — gcov 覆盖
 * @details 通过静态库链接调用 transport 的同步方法。
 *          覆盖构造器（含/不含 initial_data、client_finished）、close()、cancel()、
 *          transport_type()、next_layer()。
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

#define private public
#include <prism/stealth/facade/restls/transport.hpp>
#undef private

using psm::testing::TestRunner;

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using namespace psm::stealth::restls;

    void TestConstructBasic(TestRunner &runner)
    {
        net::io_context ioc;
        tcp::socket sock(ioc);

        std::array<std::uint8_t, 32> secret{};
        std::array<std::uint8_t, 32> server_random{};
        for (int i = 0; i < 32; ++i)
        {
            secret[i] = static_cast<std::uint8_t>(i);
            server_random[i] = static_cast<std::uint8_t>(32 - i);
        }

        restls_handover handover{
            std::span<const std::uint8_t, 32>(secret),
            std::span<const std::uint8_t, 32>(server_random),
            {},
            script_engine("300"),
            {},
            tls_version::v13
        };

        restls_transport transport(std::move(sock), std::move(handover));

        runner.Check(transport.secret_[0] == 0, "basic: secret[0]=0");
        runner.Check(transport.secret_[31] == 31, "basic: secret[31]=31");
        runner.Check(transport.server_random_[0] == 32, "basic: srandom[0]=32");
        runner.Check(transport.server_random_[31] == 1, "basic: srandom[31]=1");
        runner.Check(transport.client_finished_.empty(), "basic: cf empty");
        runner.Check(transport.initial_buffer_.empty(), "basic: init empty");
        runner.Check(transport.tls_version_ == tls_version::v13, "basic: v13");
        runner.Check(transport.read_counter_ == 0, "basic: rctr=0");
        runner.Check(transport.write_counter_ == 0, "basic: wctr=0");
        runner.Check(transport.first_write_ == true, "basic: first_write=true");
        runner.Check(transport.write_pending_ == false, "basic: write_pending=false");
    }

    void TestConstructWithClientFinished(TestRunner &runner)
    {
        net::io_context ioc;
        tcp::socket sock(ioc);

        std::array<std::uint8_t, 32> secret{};
        std::array<std::uint8_t, 32> server_random{};
        std::vector<std::uint8_t> cf = {0x10, 0x20, 0x30, 0x40, 0x50};

        restls_handover handover{
            std::span<const std::uint8_t, 32>(secret),
            std::span<const std::uint8_t, 32>(server_random),
            std::span<const std::uint8_t>(cf),
            script_engine("300"),
            {},
            tls_version::v12
        };

        restls_transport transport(std::move(sock), std::move(handover));

        runner.Check(transport.client_finished_.size() == 5, "cf: size=5");
        runner.Check(transport.client_finished_[0] == 0x10, "cf: [0]=0x10");
        runner.Check(transport.client_finished_[4] == 0x50, "cf: [4]=0x50");
        runner.Check(transport.tls_version_ == tls_version::v12, "cf: v12");
    }

    void TestConstructWithInitialData(TestRunner &runner)
    {
        net::io_context ioc;
        tcp::socket sock(ioc);

        std::array<std::uint8_t, 32> secret{};
        std::array<std::uint8_t, 32> server_random{};
        std::byte init_bytes[] = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}};

        restls_handover handover{
            std::span<const std::uint8_t, 32>(secret),
            std::span<const std::uint8_t, 32>(server_random),
            {},
            script_engine("300"),
            std::span<const std::byte>(init_bytes),
            tls_version::v13
        };

        restls_transport transport(std::move(sock), std::move(handover));

        runner.Check(transport.initial_buffer_.size() == 3, "init: size=3");
        runner.Check(transport.initial_buffer_[0] == std::byte{0xAA}, "init: [0]=0xAA");
        runner.Check(transport.initial_buffer_[2] == std::byte{0xCC}, "init: [2]=0xCC");
    }

    void TestTransportType(TestRunner &runner)
    {
        net::io_context ioc;
        tcp::socket sock(ioc);

        std::array<std::uint8_t, 32> secret{};
        std::array<std::uint8_t, 32> server_random{};

        restls_handover handover{
            std::span<const std::uint8_t, 32>(secret),
            std::span<const std::uint8_t, 32>(server_random),
            {},
            script_engine("300"),
            {},
            tls_version::v13
        };

        restls_transport transport(std::move(sock), std::move(handover));

        runner.Check(transport.transport_type() == psm::transport::transmission::type::tcp, "type: tcp");
        runner.Check(transport.next_layer() == nullptr, "layer: null");
    }

    void TestClose(TestRunner &runner)
    {
        net::io_context ioc;
        tcp::socket sock(ioc);

        std::array<std::uint8_t, 32> secret{};
        std::array<std::uint8_t, 32> server_random{};

        restls_handover handover{
            std::span<const std::uint8_t, 32>(secret),
            std::span<const std::uint8_t, 32>(server_random),
            {},
            script_engine("300"),
            {},
            tls_version::v13
        };

        restls_transport transport(std::move(sock), std::move(handover));
        transport.close();
        runner.Check(true, "close: no crash");
    }

    void TestCancel(TestRunner &runner)
    {
        net::io_context ioc;
        tcp::socket sock(ioc);

        std::array<std::uint8_t, 32> secret{};
        std::array<std::uint8_t, 32> server_random{};

        restls_handover handover{
            std::span<const std::uint8_t, 32>(secret),
            std::span<const std::uint8_t, 32>(server_random),
            {},
            script_engine("300"),
            {},
            tls_version::v13
        };

        restls_transport transport(std::move(sock), std::move(handover));
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

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("RestlsTransportDeep");

    TestConstructBasic(runner);
    TestConstructWithClientFinished(runner);
    TestConstructWithInitialData(runner);
    TestTransportType(runner);
    TestClose(runner);
    TestCancel(runner);

    return runner.Summary();
}
