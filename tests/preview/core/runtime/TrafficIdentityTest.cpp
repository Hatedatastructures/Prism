/**
 * @file TrafficIdentityTest.cpp
 * @brief 统计 identity 链路测试
 * @details 验证认证身份 → context.identity → relay 上报的完整链路：
 * 1. relay 按 ctx.identity 上报流量
 * 2. 多个身份可区分聚合
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <memory>
#include <string>
#include <unordered_map>

#include <common/core/middleware/builtin/relay.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/transmission.hpp>

namespace
{
    using namespace preview;
    namespace net = boost::asio;

    /// 内存传输（极简，供 relay 测试）
    class mem_tx final : public preview::transmission
    {
    public:
        explicit mem_tx(net::any_io_executor ex, std::size_t n) : ex_(std::move(ex)), n_(n)
        {
        }

        [[nodiscard]] auto executor() const -> executor_type override
        {
            return ex_;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (n_ == 0)
            {
                ec = make_error_code(error::io_error);
                co_return 0;
            }
            const auto n = std::min(buffer.size(), n_);
            n_ -= n;
            co_return n;
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte>, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec.clear();
            co_return 0;
        }

        void close() override
        {
        }

        void cancel() override
        {
        }

    private:
        net::any_io_executor ex_;
        std::size_t n_;
    };

    /// 按身份聚合的 fake sink
    class aggregating_sink final : public preview::middleware::context::traffic_sink
    {
    public:
        void report(std::string_view identity, std::size_t up, std::size_t down) override
        {
            auto &acc = by_identity_[std::string(identity)];
            acc.first += up;
            acc.second += down;
        }

        std::unordered_map<std::string, std::pair<std::size_t, std::size_t>> by_identity_;
    };

    TEST(TrafficIdentity, RelayReportsWithIdentity)
    {
        net::io_context ioc;
        std::exception_ptr ep;

        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            preview::middleware::context ctx;
            ctx.identity = "alice";
            ctx.buffer_size = 4096;

            auto inbound = std::make_shared<mem_tx>(ioc.get_executor(), 16384);
            auto outbound = std::make_shared<mem_tx>(ioc.get_executor(), 0);
            aggregating_sink sink;
            ctx.traffic = &sink;
            auto shared_inbound = std::shared_ptr<preview::transmission>(inbound);

            preview::middleware::builtin::relay_middleware relay(outbound);
            const auto code = co_await relay.handle(shared_inbound, ctx);
            EXPECT_EQ(code, preview::fault::code::success);

            // 按身份聚合：alice 应收到 16384 字节
            const auto it = sink.by_identity_.find("alice");
            if (it == sink.by_identity_.end()) { ADD_FAILURE(); } else {  }
            
        }, [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    TEST(TrafficIdentity, DistinctIdentities)
    {
        net::io_context ioc;
        std::exception_ptr ep;

        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            preview::middleware::context ctx;
            ctx.identity = "bob";
            ctx.buffer_size = 4096;

            auto inbound = std::make_shared<mem_tx>(ioc.get_executor(), 8192);
            auto outbound = std::make_shared<mem_tx>(ioc.get_executor(), 0);
            aggregating_sink sink;
            ctx.traffic = &sink;
            auto shared_inbound = std::shared_ptr<preview::transmission>(inbound);

            preview::middleware::builtin::relay_middleware relay(outbound);
            const auto code = co_await relay.handle(shared_inbound, ctx);
            EXPECT_EQ(code, preview::fault::code::success);

            // bob 独立聚合，alice 不应出现
            EXPECT_EQ(sink.by_identity_.count("bob"), 1u);
            EXPECT_EQ(sink.by_identity_.count("alice"), 0u);
            EXPECT_EQ(sink.by_identity_["bob"].first, 8192u);
        }, [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

} // namespace
