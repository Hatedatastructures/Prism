/**
 * @file PadOwnershipAuditTest.cpp
 * @brief Transport Pad 满区间所有权审计。
 */
#include <gtest/gtest.h>
#include "../Core/Resources.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <cstddef>
#include <memory>
#include <span>
#include <vector>
#include <Prism/Transport/Pad.hpp>
#include <Prism/Transport/Transmission.hpp>
namespace
{
    namespace Net = boost::asio;
    class FakeSink final : public Prism::Transmission
    {
    public:
        explicit FakeSink(Net::any_io_executor Executor) : Prism::Transmission(Executor), Ex_(std::move(Executor)) {}
        [[nodiscard]] auto Executor() const -> ExecutorType override { return Ex_; }
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            std::error_code Ec; Ec.clear(); { std::move(Handler)(Prism::IoResult{0, Prism::Fault::FromNative(Ec)}); return; } }
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            std::error_code Ec; Ec.clear(); Written_.insert(Written_.end(), Buffer.begin(), Buffer.end()); { std::move(Handler)(Prism::IoResult{Buffer.size(), Prism::Fault::FromNative(Ec)}); return; } }
        auto OnClose() -> ControlResult override
        {
            return {};
        }
        auto OnCancel() -> ControlResult override
        {
            return {};
        }
        std::vector<std::byte> Written_;
    private:
        Net::any_io_executor Ex_;

        /** @brief 测试替身显式兑现半关闭；装饰器沿实际inner转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer()) { Inner->WriteShutdown(std::move(Handler)); return; }
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {});
        }
    };
}
TEST(OwnershipAudit, PadMaxRangeNoDivZero)
    {
        Net::io_context IoContext;
        auto Sink = std::make_shared<FakeSink>(IoContext.get_executor());

        Prism::Transport::PadConfig Config;
        Config.Targets = *Prism::Transport::ParsePadTargets("0-65535");
        auto TransportOwner14 = std::make_shared<Prism::Transport::PadTransport>(Sink, Prism::Testing::MakePadOptions(Config));
        auto& Pad = *TransportOwner14;

        std::array<std::byte, 1> Buffer{std::byte{0x42}};
        Prism::Fault::Failure Ec;
        std::size_t BytesWritten = 0;
        Net::co_spawn(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                BytesWritten = ([&](Prism::IoResult Result) { Ec = Result.Failure; return Result.Bytes; })(co_await Pad.WriteSome(Buffer));
            },
            Net::detached);
        IoContext.run();

        EXPECT_TRUE(Ec.Succeeded());
        EXPECT_EQ(BytesWritten, 1u);
        EXPECT_GE(Sink->Written_.size(), 1u);
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(IoContext, TransportOwner14));
        EXPECT_TRUE(Prism::Testing::DriveDrain(IoContext, Sink).has_value());
    }
