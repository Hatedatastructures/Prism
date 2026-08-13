/**
 * @file ConnectPure.cpp
 * @brief Connect 模块纯函数测试 — is_ipv6/is_mux
 */

#include <prism/net/connection/dialer/dialer.hpp>
#include <prism/net/connection/util.hpp>

#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    TEST(ConnectPure, IsMux)
    {
        using psm::connect::mux_switch;

        EXPECT_TRUE(psm::connect::is_mux("test.mux.sing-box.arpa", mux_switch::on))
            << "is_mux: valid suffix + on=true";
        EXPECT_TRUE(!psm::connect::is_mux("test.mux.sing-box.arpa", mux_switch::off))
            << "is_mux: valid suffix + off=false";
        EXPECT_TRUE(!psm::connect::is_mux("example.com", mux_switch::on)) << "is_mux: no suffix + on=false";
        EXPECT_TRUE(!psm::connect::is_mux("", mux_switch::on)) << "is_mux: empty + on=false";
        EXPECT_TRUE(psm::connect::is_mux(".mux.sing-box.arpa", mux_switch::on)) << "is_mux: bare suffix=true";
    }
} // namespace
