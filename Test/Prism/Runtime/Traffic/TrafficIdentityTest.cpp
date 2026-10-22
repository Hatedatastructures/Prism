/**
 * @file TrafficIdentityTest.cpp
 * @brief 统计 identity 链路测试
 * @details 验证认证身份 → Context.Identity() → relay 上报的完整链路：
 * 1. relay 按 ctx.Identity() 上报流量
 * 2. 多个身份可区分聚合
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <array>
#include <exception>
#include <memory>
#include <string>
#include <unordered_map>

#include <Prism/Runtime/Middleware/Builtin/Relay.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{
    namespace Net = boost::asio;

    /// 内存传输（极简，供 relay 测试）
    class MemTx final : public Prism::Transmission
    {
    public:
        explicit MemTx(
            Net::any_io_executor Executor,
            const std::size_t Remaining)
            : Prism::Transmission(Executor),
              Ex_(std::move(Executor)),
              Remaining_(Remaining)
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(ReadWork{}, Ex_), Handler,
                ReadInput{std::static_pointer_cast<MemTx>(Prism::Transmission::shared_from_this()), Buffer});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(WriteWork{}, Ex_), Handler,
                WriteInput{std::static_pointer_cast<MemTx>(Prism::Transmission::shared_from_this()), Buffer});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto *Inner = NextLayer())
            {
                Inner->WriteShutdown(std::move(Handler));
                return;
            }
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        struct ReadInput final
        {
            std::shared_ptr<MemTx> Owner;
            std::span<std::byte> Buffer;
        };
        struct WriteInput final
        {
            std::shared_ptr<MemTx> Owner;
            std::span<const std::byte> Buffer;
        };
        /** @brief 原协程体原位保留，新前门一次性映射正式结果。 */
        struct ReadWork final
        {
            template <class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                co_return std::tuple{co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadSome(Input.Buffer), Net::deferred)};
            }
        };
        struct WriteWork final
        {
            template <class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                co_return std::tuple{co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WriteSome(Input.Buffer), Net::deferred)};
            }
        };
        [[nodiscard]] auto ReadSome(std::span<std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            if (Remaining_ == 0U)
            {
                co_return Prism::IoResult{
                    0, Prism::Fault::Failure{Prism::Fault::Code::Eof}};
            }
            const auto Count = (std::min)(Buffer.size(), Remaining_);
            std::fill_n(Buffer.begin(), Count, std::byte{});
            Remaining_ -= Count;
            co_return Prism::IoResult{Count, {}};
        }
        [[nodiscard]] auto WriteSome(std::span<const std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            // 黑洞对端：吸收全部写入（返回 0 会被组合 AsyncWrite 判定为
            // broken_pipe 而中断 relay，与"可写对端"的桩意图不符）
            co_return Prism::IoResult{Buffer.size(), {}};
        }
        Net::any_io_executor Ex_;
        std::size_t Remaining_;
    };

    /// 按 numeric account 聚合的 fake sink
    class AggregatingSink final : public Prism::Foundation::TrafficSink
    {
    public:
        void Report(const Prism::Foundation::TrafficEvent Event) noexcept override
        {
            try
            {
                auto &Accumulator = ByAccount_[Event.Account.Value()];
                Accumulator.first += Event.Up;
                Accumulator.second += Event.Down;
            }
            catch (...)
            {
                ++ObservationFailures;
            }
        }

        auto Retire(Prism::Foundation::TrafficRetirement Owner)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        { (void)Owner; co_return std::expected<void, Prism::Fault::Failure>{}; }

        std::unordered_map<std::uint64_t, std::pair<std::size_t, std::size_t>> ByAccount_;
        std::size_t ObservationFailures{0};
    };

    /**
     * @brief 保存单个 account identity relay 场景的真实输入和聚合合同。
     */
    struct TrafficIdentityRequest final
    {
        Net::io_context &IoContext;
        std::string Identity;
        Prism::AccountId Account;
        std::size_t Remaining;
        std::uint64_t AbsentAccount;
        bool CheckAbsent;
    };

    /**
     * @brief 执行 identity relay 并核对 account traffic 聚合结果。
     */
    auto RunTrafficIdentityScenario(TrafficIdentityRequest Request) -> Net::awaitable<void>
    {
        Prism::Middleware::Context Context;
        Context.Identity() = Request.Identity;
        Context.DataPlane.AccountId = Request.Account;
        Context.BufferSize = 4096;
        Context.Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockSize = Context.BufferSize, .BlockCount = 2});

        auto Inbound = std::make_shared<MemTx>(Request.IoContext.get_executor(), Request.Remaining);
        auto Outbound = std::make_shared<MemTx>(Request.IoContext.get_executor(), 0);
        auto Sink = std::make_shared<AggregatingSink>();
        Context.Traffic = Sink;
        auto SharedInbound = std::shared_ptr<Prism::Transmission>(Inbound);

        Prism::Middleware::Builtin::RelayMiddleware Relay(Outbound);
        const auto Code = co_await Relay.Handle(SharedInbound, Context);
        if (Request.CheckAbsent)
        {
            EXPECT_TRUE(Code.Succeeded());
            EXPECT_EQ(Sink->ByAccount_.count(Request.Account.Value()), 1U);
            EXPECT_EQ(Sink->ByAccount_.count(Request.AbsentAccount), 0U);
            EXPECT_EQ(Sink->ByAccount_[Request.Account.Value()].first, Request.Remaining);
        }
        else
        {
            EXPECT_TRUE(Code.Succeeded());
            const auto Iterator = Sink->ByAccount_.find(Request.Account.Value());
            EXPECT_NE(Iterator, Sink->ByAccount_.end());
            if (Iterator != Sink->ByAccount_.end())
            {
                EXPECT_EQ(Iterator->second.first, Request.Remaining);
            }
        }
    }

    /**
     * @brief 自然驱动 identity coroutine，等待所有已启动任务并透传首异常。
     */
    auto RunTrafficIdentityCoro(Net::io_context &IoContext, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(IoContext, std::move(Operation),
            [&Failure](std::exception_ptr ErrorValue)
            {
                Failure = std::move(ErrorValue);
            });
        IoContext.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    TEST(TrafficIdentity, RelayReportsWithIdentity)
    {
        Net::io_context IoContext;
        RunTrafficIdentityCoro(IoContext,
            RunTrafficIdentityScenario(
                TrafficIdentityRequest{IoContext, "alice", Prism::AccountId{7}, 16384, 0, false}));
    }

    TEST(TrafficIdentity, DistinctIdentities)
    {
        Net::io_context IoContext;
        RunTrafficIdentityCoro(IoContext,
            RunTrafficIdentityScenario(
                TrafficIdentityRequest{IoContext, "bob", Prism::AccountId{8}, 8192, 7, true}));
    }

} // namespace
