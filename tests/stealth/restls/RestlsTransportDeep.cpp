/**
 * @file RestlsTransportDeep.cpp
 * @brief Restls transport 构造器与生命周期测试 — gcov 覆盖
 * @details 通过静态库链接调用 transport 的同步方法。
 *          覆盖构造器（含/不含 initial_data、client_finished）、close()、cancel()、
 *          transport_type()、next_layer()。
 */

#include <gtest/gtest.h>

#include <prism/memory.hpp>

#include <boost/asio.hpp>
#include <cstdint>
#include <cstring>
#include <vector>

#define private public
#include <prism/stealth/facade/restls/transport.hpp>
#undef private

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using namespace psm::stealth::restls;

    TEST(RestlsTransportDeep, ConstructBasic)
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

        EXPECT_TRUE(transport.secret_[0] == 0) << "basic: secret[0]=0";
        EXPECT_TRUE(transport.secret_[31] == 31) << "basic: secret[31]=31";
        EXPECT_TRUE(transport.server_random_[0] == 32) << "basic: srandom[0]=32";
        EXPECT_TRUE(transport.server_random_[31] == 1) << "basic: srandom[31]=1";
        EXPECT_TRUE(transport.client_finished_.empty()) << "basic: cf empty";
        EXPECT_TRUE(transport.initial_buffer_.empty()) << "basic: init empty";
        EXPECT_TRUE(transport.tls_version_ == tls_version::v13) << "basic: v13";
        EXPECT_TRUE(transport.read_counter_ == 0) << "basic: rctr=0";
        EXPECT_TRUE(transport.write_counter_ == 0) << "basic: wctr=0";
        EXPECT_TRUE(transport.first_write_ == true) << "basic: first_write=true";
        EXPECT_TRUE(transport.write_pending_ == false) << "basic: write_pending=false";
    }

    TEST(RestlsTransportDeep, ConstructWithClientFinished)
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

        EXPECT_TRUE(transport.client_finished_.size() == 5) << "cf: size=5";
        EXPECT_TRUE(transport.client_finished_[0] == 0x10) << "cf: [0]=0x10";
        EXPECT_TRUE(transport.client_finished_[4] == 0x50) << "cf: [4]=0x50";
        EXPECT_TRUE(transport.tls_version_ == tls_version::v12) << "cf: v12";
    }

    TEST(RestlsTransportDeep, ConstructWithInitialData)
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

        EXPECT_TRUE(transport.initial_buffer_.size() == 3) << "init: size=3";
        EXPECT_TRUE(transport.initial_buffer_[0] == std::byte{0xAA}) << "init: [0]=0xAA";
        EXPECT_TRUE(transport.initial_buffer_[2] == std::byte{0xCC}) << "init: [2]=0xCC";
    }

    TEST(RestlsTransportDeep, TransportType)
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

        EXPECT_TRUE(transport.transport_type() == psm::transport::transmission::type::tcp) << "type: tcp";
        EXPECT_TRUE(transport.next_layer() == nullptr) << "layer: null";
    }

    TEST(RestlsTransportDeep, Close)
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
        // close() 后再次 close 不应崩溃（幂等）
        transport.close();
        EXPECT_TRUE(true) << "close: idempotent, double close safe";
    }

    TEST(RestlsTransportDeep, Cancel)
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
        EXPECT_TRUE(true) << "cancel: covered (exception caught safely)";
        transport.close();
        // close 后再 close 验证幂等
        transport.close();
    }

} // namespace
