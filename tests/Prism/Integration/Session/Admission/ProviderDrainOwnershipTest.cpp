/** @file ProviderDrainOwnershipTest.cpp @brief 验证丢弃接入 plane 后仍由 provider drain 关闭传输。 */
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Socks5/Binding.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/TransportResources.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <utility>

namespace
{
    namespace Net = boost::asio;

    /** @brief 构造带有限字节池的 SOCKS5 入站接入值。 */
    [[nodiscard]] auto MakeStreamAcceptInput(Prism::SharedTransmission Inbound)
        -> Prism::Contract::StreamAcceptInput
    {
        return {
            std::move(Inbound), {},
            std::make_shared<Prism::Memory::BytePool>(
                Prism::Memory::BytePoolOptions{.BlockCount = 8})};
    }

    /** @brief 在 stopped 或运行中的 executor 上完成端点关闭和排空。 */
    auto FinalizeTransport(Net::io_context& Io,
        const std::shared_ptr<Prism::MemoryStream>& Transport) -> void
    {
        if (Transport->IsOpen())
        {
            Prism::Testing::ExpectFixtureCloseReceipt(
                Prism::Testing::DriveClose(Io, Transport));
            return;
        }
        EXPECT_TRUE(Prism::Testing::DriveDrain(Io, Transport));
    }

    struct DroppedPlaneProbe final
    {
        std::shared_ptr<Prism::Socks5::Binding> Owner;
        std::shared_ptr<Prism::MemoryStream> Client;
        std::shared_ptr<Prism::MemoryStream> Server;

        auto Run() -> Net::awaitable<void>
        {
            std::exception_ptr Failure;
            bool Accepted = false;
            try
            {
                const std::array<std::uint8_t, 13> Wire{
                    5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 7};
                const auto Write = co_await Client->WriteSome(std::as_bytes(std::span(Wire)));
                EXPECT_TRUE(Write.Failure.Succeeded());
                EXPECT_EQ(Write.Bytes, Wire.size());

                {
                    auto Result = co_await Owner->Accept(MakeStreamAcceptInput(Server));
                    EXPECT_TRUE(Result);
                    if (Result)
                    {
                        Accepted = true;
                        EXPECT_TRUE(Result->Transport());
                    }
                }
                co_await Net::post(
                    co_await Net::this_coro::executor, Net::use_awaitable);
                if (Accepted) EXPECT_FALSE(Server->IsOpen());
            }
            catch (...)
            {
                Failure = std::current_exception();
            }

            Owner->Close();
            try
            {
                const auto Drain = co_await Owner->Drain();
                EXPECT_TRUE(Drain);
            }
            catch (...)
            {
                if (!Failure)
                {
                    Failure = std::current_exception();
                }
            }
            if (Accepted)
            {
                EXPECT_FALSE(Server->IsOpen());
            }
            if (Failure)
            {
                std::rethrow_exception(Failure);
            }
        }
    };
}

TEST(ProviderAcceptPath, DroppingAcceptedPlaneClosesActualInboundBeforeDrain)
{
    Net::io_context Io;
    Prism::Socks5::ServerConfig Config;
    Config.EnableUdp = false;
    auto Owner = Prism::Testing::MakeSocks5Binding(Config);
    auto [ClientValue, ServerValue] = Prism::MakeMemoryPair(Io.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(ClientValue));
    auto Server = std::make_shared<Prism::MemoryStream>(std::move(ServerValue));
    auto Failure = std::exception_ptr{};
    Net::co_spawn(Io, DroppedPlaneProbe{Owner, Client, Server}.Run(),
        [&Failure](std::exception_ptr Error) { Failure = std::move(Error); });
    Io.run();
    EXPECT_FALSE(Failure);
    FinalizeTransport(Io, Client);
    FinalizeTransport(Io, Server);
}
