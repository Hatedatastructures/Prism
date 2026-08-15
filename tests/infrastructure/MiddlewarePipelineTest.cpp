/**
 * @file MiddlewarePipelineTest.cpp
 * @brief 中间件管线联通性测试
 * @details 验证 middleware 管线（dial → relay）在内存流上
 * 的数据转发正确性：
 * 1. dial_middleware 注入内存"上游"
 * 2. relay_middleware 双向转发
 * 3. 客户端写入数据 → 经管线 → 上游收到；回显 → 客户端收到
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <memory>
#include <string>

#include <common/core/middleware/context.hpp>
#include <common/core/middleware/pipeline.hpp>
#include <common/core/middleware/builtin/dial.hpp>
#include <common/core/middleware/builtin/relay.hpp>
#include <common/core/transport/memory_stream.hpp>
#include <common/core/transport/transmission.hpp>
#include <common/core/fault/handling.hpp>
#include <common/core/fault/code.hpp>

namespace
{

    namespace net = boost::asio;
    namespace psmnet = boost::asio;
    using psm::transport::shared_transmission;
    using psm::transport::transmission;

    /// psm::transport 内存 mock（成对传输）
    class memory_transport final : public transmission
    {
    public:
        memory_transport(psmnet::any_io_executor ex) : ex_(std::move(ex))
        {
        }

        [[nodiscard]] auto executor() const -> executor_type override
        {
            return ex_;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            while (true)
            {
                if (!recv_buf_.empty())
                {
                    const auto n = (std::min)(buffer.size(), recv_buf_.size());
                    std::memcpy(buffer.data(), recv_buf_.data(), n);
                    recv_buf_.erase(recv_buf_.begin(),
                                    recv_buf_.begin() + static_cast<std::ptrdiff_t>(n));
                    ec.clear();
                    co_return n;
                }
                if (closed_)
                {
                    ec = std::make_error_code(std::errc::broken_pipe);
                    co_return 0;
                }
                co_await net::post(ex_, net::use_awaitable);
            }
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!peer_ || closed_)
            {
                ec = std::make_error_code(std::errc::broken_pipe);
                co_return 0;
            }
            peer_->recv_buf_.insert(peer_->recv_buf_.end(), buffer.begin(), buffer.end());
            ec.clear();
            co_return buffer.size();
        }

        void close() override
        {
            closed_ = true;
        }

        void cancel() override
        {
        }

        void bind_peer(const std::shared_ptr<memory_transport> &peer)
        {
            peer_ = peer;
        }

    private:
        psmnet::any_io_executor ex_;                    ///< 执行器
        std::shared_ptr<memory_transport> peer_;        ///< 对端
        std::vector<std::byte> recv_buf_;               ///< 接收缓冲（对端写入）
        bool closed_{false};                            ///< 关闭标志
    };

    /// 回显上游：读到的数据原样写回
    auto echo_upstream(shared_transmission client_side)
        -> net::awaitable<void>
    {
        std::array<std::byte, 4096> buf{};
        std::error_code ec;
        while (true)
        {
            const auto n = co_await client_side->async_read_some(std::span<std::byte>(buf), ec);
            if (ec || n == 0)
            {
                break;
            }
            co_await client_side->async_write_some(std::span<const std::byte>(buf.data(), n), ec);
            if (ec)
            {
                break;
            }
        }
        client_side->close();
    }

    TEST(MiddlewarePipeline, DialRelayEcho)
    {
        net::io_context ioc;
        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            // 客户端连接对：client_side（客户端）↔ inbound（代理入站）
            auto client_side = std::make_shared<memory_transport>(ioc.get_executor());
            auto inbound = std::make_shared<memory_transport>(ioc.get_executor());
            client_side->bind_peer(inbound);
            inbound->bind_peer(client_side);

            // 上游连接对：outbound（代理出站）↔ upstream（上游服务器）
            auto outbound = std::make_shared<memory_transport>(ioc.get_executor());
            auto upstream = std::make_shared<memory_transport>(ioc.get_executor());
            outbound->bind_peer(upstream);
            upstream->bind_peer(outbound);

            // 管线：dial（注入已建立的 outbound 作为"上游"）→ relay
            psm::middleware::context ctx;
            ctx.target.positive = true;

            auto dial = std::make_shared<psm::middleware::builtin::dial_middleware>(
                [outbound](const psm::connect::target &) -> net::awaitable<
                    std::pair<psm::fault::code, psm::transport::shared_transmission>>
                {
                    co_return std::pair{psm::fault::code::success, outbound};
                });

            psm::middleware::pipeline pipe;
            pipe.add(dial).add(std::make_shared<psm::middleware::builtin::relay_middleware>(
                nullptr, std::chrono::milliseconds(100)));

            // 启动管线（detached，relay 内部跑隧道）
            net::co_spawn(
                ioc.get_executor(),
                [&pipe, inbound, &ctx]() -> net::awaitable<void>
                {
                    co_await pipe.run(inbound, ctx);
                },
                net::detached);

            // 客户端写入 → 代理入站 → relay 上行 → 上游收到
            const std::string payload = "middleware pipeline echo test";
            std::error_code wec;
            co_await client_side->async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                           payload.size()),
                wec);

            std::array<std::byte, 512> sbuf{};
            std::error_code sec;
            std::size_t stotal = 0;
            while (stotal < payload.size())
            {
                const auto n = co_await upstream->async_read_some(
                    std::span<std::byte>(sbuf.data() + stotal, sbuf.size() - stotal), sec);
                if (sec || n == 0)
                {
                    break;
                }
                stotal += n;
            }
            const std::string sup(reinterpret_cast<const char *>(sbuf.data()), stotal);
            EXPECT_EQ(sup, payload);

            // 上游回写 → relay 下行 → 客户端收到
            std::error_code wec2;
            co_await upstream->async_write_some(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                           payload.size()),
                wec2);

            std::array<std::byte, 512> rbuf{};
            std::error_code rec;
            std::size_t total = 0;
            while (total < payload.size())
            {
                const auto n = co_await client_side->async_read_some(
                    std::span<std::byte>(rbuf.data() + total, rbuf.size() - total), rec);
                if (rec || n == 0)
                {
                    break;
                }
                total += n;
            }

            const std::string got(reinterpret_cast<const char *>(rbuf.data()), total);
            EXPECT_EQ(got, payload);

            client_side->close();
            ioc.stop();
        };

        net::co_spawn(ioc, coro(), [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        (void)ep;
    }

} // namespace
