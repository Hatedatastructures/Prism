/**
 * @file TimeoutTest.cpp
 * @brief Unreliable UDP 读取 deadline 与到期前数据测试。
 * @details 保留 loopback endpoint、payload 发送时序与普通 Fault 值断言。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <exception>
#include <memory>
#include <span>
#include <utility>

#include <Prism/Transport/Transmission.hpp>
#include <Prism/Transport/Unreliable.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    using ReadCompletion = Net::experimental::channel<void(boost::system::error_code)>;

    /** @brief 驱动单个 UDP 协程并传播真实协程异常。 */
    auto RunCoro(Net::io_context &Context, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Failure;
        Context.restart();
        Net::co_spawn(Context, std::move(Operation), [&Failure](std::exception_ptr Error)
                      { Failure = std::move(Error); });
        Context.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    /** @brief 保留 callback 读取的 40 毫秒 timeout 结果与关闭调用。 */
    auto RunUnreliableHandlerReadTimeout(
        const std::shared_ptr<Prism::Transport::Unreliable> &Udp,
        const Prism::SharedTransmission &Base) -> Net::awaitable<void>
    {
        Udp->SetTimeout(std::chrono::milliseconds(40));
        std::array<std::byte, 8> Buffer{};
        const auto Result = std::make_shared<Prism::IoResult>();
        const auto Done = std::make_shared<ReadCompletion>(Udp->Executor(), 1);
        Base->ReadSome(std::span<std::byte>(Buffer), [Result, Done](Prism::IoResult Value)
                       {
                           *Result = Value;
                           (void)Done->try_send(boost::system::error_code{});
                       });
        co_await Done->async_receive(Net::use_awaitable);
        EXPECT_EQ(Result->Bytes, 0U);
        EXPECT_EQ(Result->Failure.Code, Prism::Fault::Code::Timeout);
        Udp->Close();
    }

    /** @brief 保留无到达数据时 40 毫秒 UDP 读取 timeout 值。 */
    auto RunUnreliableReadTimeout(
        const std::shared_ptr<Prism::Transport::Unreliable> &Udp) -> Net::awaitable<void>
    {
        Udp->SetTimeout(std::chrono::milliseconds(40));
        std::array<std::byte, 8> Buffer{};
        const auto Result = co_await Udp->ReadSome(Buffer);
        EXPECT_EQ(Result.Bytes, 0U);
        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::Timeout);
        Udp->Close();
    }

    /** @brief 保留 500 毫秒窗口内收到的原三字节 payload 长度与成功值断言。 */
    auto RunUnreliableReadBeforeTimeout(
        const std::shared_ptr<Prism::Transport::Unreliable> &Udp,
        const std::array<std::byte, 3> &Payload) -> Net::awaitable<void>
    {
        Udp->SetTimeout(std::chrono::milliseconds(500));
        std::array<std::byte, 8> Buffer{};
        const auto Result = co_await Udp->ReadSome(Buffer);
        EXPECT_EQ(Result.Bytes, Payload.size());
        EXPECT_TRUE(Result.Failure.Succeeded());
        Udp->Close();
    }
}

TEST(Transport, UnreliableHandlerReadTimeout)
{
    Net::io_context Io;
    auto Udp = std::make_shared<Prism::Transport::Unreliable>(Io.get_executor());
    ASSERT_TRUE(Udp->Bind(0));
    Net::ip::udp::socket Peer(
        Io, Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0));
    Udp->SetRemote(Peer.local_endpoint());
    const auto Base = std::static_pointer_cast<Prism::Transmission>(Udp);
    RunCoro(Io, RunUnreliableHandlerReadTimeout(Udp, Base));
}

TEST(Transport, UnreliableReadTimeout)
{
    Net::io_context Io;
    auto Udp = std::make_shared<Prism::Transport::Unreliable>(Io.get_executor());
    ASSERT_TRUE(Udp->Bind(0));
    Net::ip::udp::socket Peer(Io, Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0));
    Udp->SetRemote(Peer.local_endpoint());
    RunCoro(Io, RunUnreliableReadTimeout(Udp));
}

TEST(Transport, UnreliableReadBeforeTimeoutStillSucceeds)
{
    Net::io_context Io;
    auto Udp = std::make_shared<Prism::Transport::Unreliable>(Io.get_executor());
    boost::system::error_code BindError;
    Udp->NativeSocket().open(Net::ip::udp::v4(), BindError);
    ASSERT_FALSE(BindError);
    Udp->NativeSocket().bind(
        Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0), BindError);
    ASSERT_FALSE(BindError);
    Net::ip::udp::socket Peer(Io, Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0));
    Udp->SetRemote(Peer.local_endpoint());
    const std::array<std::byte, 3> Payload{
        std::byte{0x0A}, std::byte{0x0B}, std::byte{0x0C}};
    boost::system::error_code SendError;
    Peer.send_to(Net::buffer(Payload), Udp->LocalEndpoint(), 0, SendError);
    ASSERT_FALSE(SendError) << "send_to failed: " << SendError.message()
                            << " target=" << Udp->LocalEndpoint();
    RunCoro(Io, RunUnreliableReadBeforeTimeout(Udp, Payload));
}
