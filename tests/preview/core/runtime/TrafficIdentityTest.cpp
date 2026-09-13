/**
 * @file TrafficIdentityTest.cpp
 * @brief 统计 identity 链路测试
 * @details 验证认证身份 → Context.identity → relay 上报的完整链路：
 * 1. relay 按 ctx.identity 上报流量
 * 2. 多个身份可区分聚合
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <memory>
#include <string>
#include <unordered_map>

#include <preview/Runtime/Middleware/Builtin/Relay.hpp>
#include <preview/Runtime/Middleware/Context.hpp>
#include <preview/Transport/Transmission.hpp>

namespace
{
    namespace Net = boost::asio;

    /// 内存传输（极简，供 relay 测试）
    class MemTx final : public Preview::Transmission
    {
    public:
        explicit MemTx(
            Net::any_io_executor Executor,
            const std::size_t Remaining)
            : Ex_(std::move(Executor)),
              Remaining_(Remaining)
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        [[nodiscard]] auto async_read_some(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            if (Remaining_ == 0)
            {
                ErrorCode.clear();
                co_return 0;
            }
            const auto Count = std::min(Buffer.size(), Remaining_);
            Remaining_ -= Count;
            ErrorCode.clear();
            co_return Count;
        }

        [[nodiscard]] auto async_write_some(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            // 黑洞对端：吸收全部写入（返回 0 会被组合 AsyncWrite 判定为
            // broken_pipe 而中断 relay，与"可写对端"的桩意图不符）
            ErrorCode.clear();
            co_return Buffer.size();
        }

        void Close() override
        {
        }

        void Cancel() override
        {
        }

    private:
        Net::any_io_executor Ex_;
        std::size_t Remaining_;
    };

    /// 按身份聚合的 fake sink
    class AggregatingSink final : public Preview::Middleware::Context::TrafficSink
    {
    public:
        void Report(
            std::string_view Identity,
            const std::size_t Up,
            const std::size_t Down) override
        {
            auto &Accumulator = ByIdentity_[std::string(Identity)];
            Accumulator.first += Up;
            Accumulator.second += Down;
        }

        std::unordered_map<std::string, std::pair<std::size_t, std::size_t>> ByIdentity_;
    };

    TEST(TrafficIdentity, RelayReportsWithIdentity)
    {
        Net::io_context IoContext;
        std::exception_ptr Exception;
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            Preview::Middleware::Context Context;
            Context.identity = "alice";
            Context.BufferSize = 4096;

            auto Inbound = std::make_shared<MemTx>(IoContext.get_executor(), 16384);
            auto Outbound = std::make_shared<MemTx>(IoContext.get_executor(), 0);
            AggregatingSink Sink;
            Context.traffic = &Sink;
            auto SharedInbound = std::shared_ptr<Preview::Transmission>(Inbound);

            Preview::Middleware::Builtin::RelayMiddleware Relay(Outbound);
            const auto Code = co_await Relay.Handle(SharedInbound, Context);
            EXPECT_EQ(Code, Preview::Fault::Code::Success);

            // 按身份聚合：alice 上行（Inbound→Outbound）应计 16384 字节
            const auto Iterator = Sink.ByIdentity_.find("alice");
            EXPECT_NE(Iterator, Sink.ByIdentity_.end());
            if (Iterator != Sink.ByIdentity_.end())
            {
                EXPECT_EQ(Iterator->second.first, 16384u);
            }
        };
        auto Completion = [&Exception, &IoContext](std::exception_ptr ErrorValue) -> void
        {
            Exception = ErrorValue;
            IoContext.stop();
        };
        Net::co_spawn(IoContext, std::move(Coroutine), std::move(Completion));
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    TEST(TrafficIdentity, DistinctIdentities)
    {
        Net::io_context IoContext;
        std::exception_ptr Exception;
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            Preview::Middleware::Context Context;
            Context.identity = "bob";
            Context.BufferSize = 4096;

            auto Inbound = std::make_shared<MemTx>(IoContext.get_executor(), 8192);
            auto Outbound = std::make_shared<MemTx>(IoContext.get_executor(), 0);
            AggregatingSink Sink;
            Context.traffic = &Sink;
            auto SharedInbound = std::shared_ptr<Preview::Transmission>(Inbound);

            Preview::Middleware::Builtin::RelayMiddleware Relay(Outbound);
            const auto Code = co_await Relay.Handle(SharedInbound, Context);
            EXPECT_EQ(Code, Preview::Fault::Code::Success);

            // bob 独立聚合，alice 不应出现
            EXPECT_EQ(Sink.ByIdentity_.count("bob"), 1u);
            EXPECT_EQ(Sink.ByIdentity_.count("alice"), 0u);
            EXPECT_EQ(Sink.ByIdentity_["bob"].first, 8192u);
        };
        auto Completion = [&Exception, &IoContext](std::exception_ptr ErrorValue) -> void
        {
            Exception = ErrorValue;
            IoContext.stop();
        };
        Net::co_spawn(IoContext, std::move(Coroutine), std::move(Completion));
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

} // namespace
