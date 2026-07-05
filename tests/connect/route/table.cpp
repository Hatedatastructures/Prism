/**
 * @file route_table.cpp
 * @brief route_table 单元测试
 * @details 验证 add_route/remove_route/lookup/set_forward_endpoint/stats 行为。
 * route_table 单线程使用，无并发测试需求。
 */

#include <prism/net/connect/route/table.hpp>

#include <gtest/gtest.h>

namespace
{
    using psm::connect::route_table;
    using psm::connect::route_stats;

    auto make_endpoint(const std::string &ip, std::uint16_t port) -> boost::asio::ip::tcp::endpoint
    {
        return boost::asio::ip::tcp::endpoint{boost::asio::ip::make_address(ip), port};
    }
} // namespace

TEST(RouteTable, EmptyLookupReturnsNullopt)
{
    route_table table;
    EXPECT_FALSE(table.lookup("nonexistent.com").has_value());

    const auto s = table.stats();
    EXPECT_EQ(s.reverse_hits, std::uint64_t{0});
    EXPECT_EQ(s.reverse_misses, std::uint64_t{1});
}

TEST(RouteTable, AddAndLookup)
{
    route_table table;
    const auto ep = make_endpoint("127.0.0.1", 8080);
    table.add_route("example.com", ep);

    auto result = table.lookup("example.com");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->address().to_string(), "127.0.0.1");
    EXPECT_EQ(result->port(), 8080);

    const auto s = table.stats();
    EXPECT_EQ(s.reverse_hits, std::uint64_t{1});
    EXPECT_EQ(s.reverse_misses, std::uint64_t{0});
}

TEST(RouteTable, RemoveReturnsCount)
{
    route_table table;
    table.add_route("example.com", make_endpoint("127.0.0.1", 80));
    EXPECT_EQ(table.remove_route("example.com"), std::size_t{1});
    EXPECT_EQ(table.remove_route("example.com"), std::size_t{0});
    EXPECT_FALSE(table.lookup("example.com").has_value());
}

TEST(RouteTable, ForwardEndpoint)
{
    route_table table;
    EXPECT_FALSE(table.forward_host().has_value());
    EXPECT_EQ(table.forward_port(), std::uint16_t{0});

    table.set_forward_endpoint("upstream.proxy", 1080);
    ASSERT_TRUE(table.forward_host().has_value());
    EXPECT_EQ(*table.forward_host(), "upstream.proxy");
    EXPECT_EQ(table.forward_port(), std::uint16_t{1080});

    table.clear_forward_endpoint();
    EXPECT_FALSE(table.forward_host().has_value());
    EXPECT_EQ(table.forward_port(), std::uint16_t{0});
}

TEST(RouteTable, SetForwardEndpointWithEmptyHostClears)
{
    route_table table;
    table.set_forward_endpoint("upstream.proxy", 1080);
    ASSERT_TRUE(table.forward_host().has_value());

    table.set_forward_endpoint("", 0);
    EXPECT_FALSE(table.forward_host().has_value());
}

TEST(RouteTable, AddRouteOverwrites)
{
    route_table table;
    table.add_route("example.com", make_endpoint("1.1.1.1", 80));
    table.add_route("example.com", make_endpoint("2.2.2.2", 443));

    auto result = table.lookup("example.com");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->address().to_string(), "2.2.2.2");
    EXPECT_EQ(result->port(), 443);
}

TEST(RouteTable, StatsDefaults)
{
    route_table table;
    const auto s = table.stats();
    EXPECT_EQ(s.reverse_hits, std::uint64_t{0});
    EXPECT_EQ(s.reverse_misses, std::uint64_t{0});
    EXPECT_EQ(s.forward_uses, std::uint64_t{0});
}
