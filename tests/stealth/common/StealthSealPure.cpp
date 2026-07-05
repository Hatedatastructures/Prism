/**
 * @file StealthSealPure.cpp
 * @brief Reality seal 加密封装纯构造/属性测试
 * @details 测试 seal 的构造、executor、close、cancel 等非协程路径。
 *          加解密路径需要真实 AEAD 密钥+TLS 记录，此处测试基础行为。
 */

#include <gtest/gtest.h>

#include <prism/foundation/foundation.hpp>
#include <prism/stealth/facade/reality/seal.hpp>
#include <prism/crypto/aead.hpp>

#include "common/MockTransport.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <array>
#include <cstring>

using psm::testing::MockTransport;

namespace
{
    namespace reality = psm::stealth::reality;
    namespace crypto = psm::crypto;

    auto make_test_key_material() -> reality::key_material
    {
        reality::key_material km;
        // 填充 16 字节密钥和 IV（AES-128-GCM）
        std::fill(km.server_appkey.begin(), km.server_appkey.end(), std::uint8_t{0x01});
        std::fill(km.client_appkey.begin(), km.client_appkey.end(), std::uint8_t{0x02});
        std::fill(km.server_appiv.begin(), km.server_appiv.end(), std::uint8_t{0x03});
        std::fill(km.client_appiv.begin(), km.client_appiv.end(), std::uint8_t{0x04});
        return km;
    }

    TEST(StealthSealPure, SealConstructor)
    {
        auto mock = std::make_shared<MockTransport>();
        auto km = make_test_key_material();
        auto s = std::make_shared<reality::seal>(mock, km);
        EXPECT_TRUE(s != nullptr) << "seal: constructed";
    }

    TEST(StealthSealPure, SealExecutor)
    {
        auto mock = std::make_shared<MockTransport>();
        auto km = make_test_key_material();
        auto s = std::make_shared<reality::seal>(mock, km);

        auto ex = s->executor();
        EXPECT_TRUE(ex != boost::asio::any_io_executor{}) << "seal: executor valid";
    }

    TEST(StealthSealPure, SealClose)
    {
        auto mock = std::make_shared<MockTransport>();
        auto km = make_test_key_material();
        auto s = std::make_shared<reality::seal>(mock, km);

        EXPECT_TRUE(!mock->is_closed()) << "seal: mock not closed before close";
        s->close();
        EXPECT_TRUE(mock->is_closed()) << "seal: mock closed after close";
    }

    TEST(StealthSealPure, SealCancel)
    {
        auto mock = std::make_shared<MockTransport>();
        auto km = make_test_key_material();
        auto s = std::make_shared<reality::seal>(mock, km);

        EXPECT_TRUE(!mock->is_cancelled()) << "seal: mock not cancelled before cancel";
        s->cancel();
        EXPECT_TRUE(mock->is_cancelled()) << "seal: mock cancelled after cancel";
    }

    TEST(StealthSealPure, SealNextLayerNotNull)
    {
        auto mock = std::make_shared<MockTransport>();
        auto km = make_test_key_material();
        auto s = std::make_shared<reality::seal>(mock, km);
        EXPECT_TRUE(s->next_layer() == mock.get()) << "seal: next_layer==mock";
    }

    TEST(StealthSealPure, SealTransportType)
    {
        auto mock = std::make_shared<MockTransport>();
        auto km = make_test_key_material();
        auto s = std::make_shared<reality::seal>(mock, km);
        // seal 的 transport_type 沿 next_layer() 走 -> nullptr -> tcp
        EXPECT_TRUE(s->transport_type() == psm::transport::transmission::type::tcp)
            << "seal: transport_type=tcp";
    }

} // namespace
