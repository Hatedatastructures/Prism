/**
 * @file MiddlewarePipelineTest.cpp
 * @brief 中间件管线联通性测试
 * @details 验证 Middleware 管线（Dial → relay）在内存流上
 * 的数据转发正确性：
 * 1. DialMiddleware 注入内存"上游"
 * 2. RelayMiddleware 双向转发
 * 3. 客户端写入数据 → 经管线 → 上游收到；回显 → 客户端收到
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <memory>
#include <string>

#include <common/Core/Middleware/Context.hpp>
#include <common/Core/Middleware/Pipeline.hpp>
#include <common/Core/Middleware/Builtin/Dial.hpp>
#include <common/Core/Middleware/Builtin/Relay.hpp>
#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Core/Fault/Handling.hpp>
#include <common/Core/Fault/Code.hpp>

namespace
{

    namespace net = boost::asio;
    namespace psmnet = boost::asio;
    using Preview::SharedTransmission;
    using Preview::Transmission;

    /// Preview::Transport 内存 mock（成对传输）
    class memory_transport final : public Transmission
    {
    public:
        memory_transport(psmnet::any_io_executor ex) : Ex_(std::move(ex))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            while (true)
            {
                if (!recv_buf_.empty())
                {
                    const auto n = (std::min)(Buffer.size(), recv_buf_.size());
                    std::memcpy(Buffer.data(), recv_buf_.data(), n);
                    recv_buf_.erase(recv_buf_.begin(),
                                    recv_buf_.begin() + static_cast<std::ptrdiff_t>(n));
                    ec.clear();
                    co_return n;
                }
                if (Closed_)
                {
                    ec = std::make_error_code(std::errc::broken_pipe);
                    co_return 0;
                }
                co_await net::post(Ex_, net::use_awaitable);
            }
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!Peer_ || Closed_)
            {
                ec = std::make_error_code(std::errc::broken_pipe);
                co_return 0;
            }
            Peer_->recv_buf_.insert(Peer_->recv_buf_.end(), Buffer.begin(), Buffer.end());
            ec.clear();
            co_return Buffer.size();
        }

        void Close() override
        {
            Closed_ = true;
        }

        void Cancel() override
        {
        }

        void bind_peer(const std::shared_ptr<memory_transport> &peer)
        {
            Peer_ = peer;
        }

    private:
        psmnet::any_io_executor Ex_;                    ///< 执行器
        std::shared_ptr<memory_transport> Peer_;        ///< 对端
        std::vector<std::byte> recv_buf_;               ///< 接收缓冲（对端写入）
        bool Closed_{false};                            ///< 关闭标志
    };

    /// 回显上游：读到的数据原样写回
    auto echo_upstream(SharedTransmission client_side)
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
        client_side->Close();
    }

    TEST(MiddlewarePipeline, DialRelayEcho)
    {
        net::io_context ioc;
        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            // 客户端连接对：client_side（客户端）↔ Inbound（代理入站）
            auto client_side = std::make_shared<memory_transport>(ioc.get_executor());
            auto Inbound = std::make_shared<memory_transport>(ioc.get_executor());
            client_side->bind_peer(Inbound);
            Inbound->bind_peer(client_side);

            // 上游连接对：Outbound（代理出站）↔ upstream（上游服务器）
            auto Outbound = std::make_shared<memory_transport>(ioc.get_executor());
            auto upstream = std::make_shared<memory_transport>(ioc.get_executor());
            Outbound->bind_peer(upstream);
            upstream->bind_peer(Outbound);

            // 管线：Dial（注入已建立的 Outbound 作为"上游"）→ relay
            Preview::Middleware::Context ctx;
            ctx.Target.positive = true;

            auto Dial = std::make_shared<Preview::Middleware::Builtin::DialMiddleware>(
                [Outbound](const Preview::Network::Target &) -> net::awaitable<
                    std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
                {
                    co_return std::pair{Preview::Fault::Code::Success, Outbound};
                });

            Preview::Middleware::Pipeline pipe;
            pipe.Add(Dial).Add(std::make_shared<Preview::Middleware::Builtin::RelayMiddleware>(
                nullptr, std::chrono::milliseconds(100)));

            // 启动管线（detached，relay 内部跑隧道）
            net::co_spawn(
                ioc.get_executor(),
                [&pipe, Inbound, &ctx]() -> net::awaitable<void>
                {
                    co_await pipe.Run(Inbound, ctx);
                },
                net::detached);

            // 客户端写入 → 代理入站 → relay 上行 → 上游收到
            const std::string payload = "Middleware Pipeline echo test";
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
            std::size_t Total = 0;
            while (Total < payload.size())
            {
                const auto n = co_await client_side->async_read_some(
                    std::span<std::byte>(rbuf.data() + Total, rbuf.size() - Total), rec);
                if (rec || n == 0)
                {
                    break;
                }
                Total += n;
            }

            const std::string got(reinterpret_cast<const char *>(rbuf.data()), Total);
            EXPECT_EQ(got, payload);

            client_side->Close();
            ioc.stop();
        };

        net::co_spawn(ioc, coro(), [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

} // namespace
