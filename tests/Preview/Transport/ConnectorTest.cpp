/**
 * @file ConnectorTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "TransportDecoratorTestSupport.hpp"
#include "TransportResources.hpp"

namespace
{
    /**
     * @brief 验证 Connector 先交付预读数据再委托底层读取。
     * @param Ioc 驱动内存传输和 Connector 的执行器。
     * @return 完成预读和底层数据断言的异步操作。
     */
    auto RunPrereadInjectionScenario(Net::io_context &Ioc) -> Net::awaitable<void>
    {
        auto MemoryPair10 = Preview::Testing::MakeOwnedTransportPair(Ioc.get_executor());
        auto& Local = *MemoryPair10.FirstOwner;
        auto& Remote = *MemoryPair10.SecondOwner;
        auto Source = std::make_shared<Preview::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Preview::MemoryStream>(std::move(Remote));

        // 底层先有数据（预读注入应优先返回）。
        Preview::Fault::Failure ErrorCode;
        ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Source->WriteSome(SvBytes("Inner-Data")));

        Preview::Transport::Connector Connector(Preview::Transport::PreviewTransport::Create(
            Destination, {SvBytes("PRE"), Preview::Testing::MakeTransportBytes(), {}}).value());
        std::array<std::byte, 8> Buffer{};
        boost::system::error_code ConnectorError;
        auto Bytes = co_await Connector.async_read_some(
            Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, ConnectorError));
        EXPECT_FALSE(ConnectorError);
        EXPECT_EQ(Bytes, 3u);
        EXPECT_EQ(Preview::AsStrView(
                      Preview::AsU8(std::span<std::byte>(Buffer).first(3))),
                   "PRE");

        // 预读耗尽后委托底层。
        ConnectorError.clear();
        Bytes = co_await Connector.async_read_some(
            Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, ConnectorError));
        EXPECT_FALSE(ConnectorError);
        EXPECT_EQ(Bytes, 8u);
        EXPECT_EQ(Preview::AsStrView(Preview::AsU8(std::span<std::byte>(Buffer))), "Inner-Da");
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Source));
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Destination));
    }

    /**
     * @brief 验证 Connector 写入完整委托到内层传输。
     * @param Ioc 驱动内存传输和 Connector 的执行器。
     * @return 完成写入和 peer 读取断言的异步操作。
     */
    auto RunWriteDelegationScenario(Net::io_context &Ioc) -> Net::awaitable<void>
    {
        auto MemoryPair9 = Preview::Testing::MakeOwnedTransportPair(Ioc.get_executor());
        auto& Local = *MemoryPair9.FirstOwner;
        auto& Remote = *MemoryPair9.SecondOwner;
        auto Source = std::make_shared<Preview::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Preview::MemoryStream>(std::move(Remote));

        Preview::Transport::Connector Connector(Destination);
        const std::string_view Message = "Write-me";
        boost::system::error_code WriteError;
        const auto Written = co_await Connector.async_write_some(
            Net::buffer(Message.data(), Message.size()),
            Net::redirect_error(Net::use_awaitable, WriteError));
        EXPECT_FALSE(WriteError);
        EXPECT_EQ(Written, Message.size());

        std::array<std::byte, 16> Buffer{};
        Preview::Fault::Failure ReadError;
        const auto ReadCount = ([&](Preview::IoResult Result) { ReadError = Result.Failure; return Result.Bytes; })(co_await Source->ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(ReadCount, Message.size());
        EXPECT_EQ(Preview::AsStrView(
                      Preview::AsU8(std::span<std::byte>(Buffer).first(ReadCount))),
                   Message);
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Source));
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Destination));
    }

    /**
     * @brief 验证 Connector 的成员 AsyncRead/AsyncWrite 共享同一传输 owner。
     * @param Ioc 驱动内存传输和 Connector 的执行器。
     * @return 完成成员读写和 payload 对拍的异步操作。
     */
    auto RunMemberAsyncReadWriteScenario(Net::io_context &Ioc) -> Net::awaitable<void>
    {
        auto MemoryPair8 = Preview::Testing::MakeOwnedTransportPair(Ioc.get_executor());
        auto& Local = *MemoryPair8.FirstOwner;
        auto& Remote = *MemoryPair8.SecondOwner;
        auto Source = std::make_shared<Preview::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Preview::MemoryStream>(std::move(Remote));

        Preview::Transport::Connector Writer(Destination);
        const std::string_view Message = "member-loop";
        Preview::Fault::Failure ErrorCode;
        const auto Written = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Writer.WriteExact(std::span<const std::byte>(SvBytes(Message))));
        EXPECT_EQ(Written, Message.size());
        EXPECT_TRUE(ErrorCode.Succeeded());

        Preview::Transport::Connector Reader(Source);
        std::vector<std::byte> Buffer(Message.size());
        const auto ReadCount = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Reader.ReadExact(std::span<std::byte>(Buffer)));
        EXPECT_EQ(ReadCount, Message.size());
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_EQ(Preview::AsStrView(Preview::AsU8(std::span<std::byte>(Buffer))), Message);
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Source));
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Destination));
    }
} // namespace

TEST(Connector, PrereadInjectionThenDelegate)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, RunPrereadInjectionScenario(Ioc));
    }

TEST(Connector, WriteDelegation)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, RunWriteDelegationScenario(Ioc));
    }

TEST(Connector, WritesEveryByteAcrossShortBufferSequence)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->MaxWrite = 2;
        Preview::Transport::Connector Conn(Transport);
        const std::array<std::byte, 3> First{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
        const std::array<std::byte, 2> Second{std::byte{0x04}, std::byte{0x05}};
        const std::array<Net::const_buffer, 2> Buffers{Net::buffer(First), Net::buffer(Second)};
        boost::system::error_code Error;
        std::size_t Written = 0;

        RunCoro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Written = co_await Conn.async_write_some(
                         Buffers, Net::redirect_error(Net::use_awaitable, Error));
                 });

        EXPECT_FALSE(Error);
        EXPECT_EQ(Written, 5U);
        const std::vector<std::uint8_t> Expected{1, 2, 3, 4, 5};
        EXPECT_EQ(Transport->Written, Expected);
        Preview::Testing::ExpectFixtureCloseReceipt(Preview::Testing::DriveClose(Ioc, Transport));
    }

TEST(Connector, MemberAsyncReadWrite)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, RunMemberAsyncReadWriteScenario(Ioc));
    }

TEST(Connector, PrereadCompletionIsDeferred)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        const std::array<std::byte, 2> Preread{std::byte{'o'}, std::byte{'k'}};
        Preview::Transport::Connector Connector(Preview::Transport::PreviewTransport::Create(
            Transport, {Preread, Preview::Testing::MakeTransportBytes(), {}}).value());
        std::array<std::byte, 4> Buffer{};
        bool Called = false;
        std::size_t Bytes = 0;
        boost::system::error_code Error;

        Connector.async_read_some(Net::buffer(Buffer),
                                  [&](boost::system::error_code Ec, const std::size_t N)
                                  {
                                      Called = true;
                                      Error = Ec;
                                      Bytes = N;
                                  });
        EXPECT_FALSE(Called);
        Ioc.run();
        EXPECT_TRUE(Called);
        EXPECT_FALSE(Error);
        EXPECT_EQ(Bytes, 2U);
        EXPECT_EQ(Buffer[0], std::byte{'o'});
        EXPECT_EQ(Buffer[1], std::byte{'k'});
        Preview::Testing::ExpectFixtureCloseReceipt(Preview::Testing::DriveClose(Ioc, Transport));
    }

TEST(Connector, DelegatesReadAcrossBufferSequence)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->InjectRead({0x61, 0x62, 0x63, 0x64, 0x65});
        Preview::Transport::Connector Connector(Transport);
        std::array<std::byte, 2> First{};
        std::array<std::byte, 3> Second{};
        const std::array<Net::mutable_buffer, 2> Buffers{Net::buffer(First), Net::buffer(Second)};
        std::size_t Bytes = 0;

        RunCoro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Bytes = co_await Connector.async_read_some(Buffers, Net::use_awaitable);
                 });

        EXPECT_EQ(Bytes, 5U);
        EXPECT_EQ(First[0], std::byte{'a'});
        EXPECT_EQ(First[1], std::byte{'b'});
        EXPECT_EQ(Second[0], std::byte{'c'});
        EXPECT_EQ(Second[1], std::byte{'d'});
        EXPECT_EQ(Second[2], std::byte{'e'});
        Preview::Testing::ExpectFixtureCloseReceipt(Preview::Testing::DriveClose(Ioc, Transport));
    }

TEST(Connector, ShortWritesDoNotRecurseOrCompleteInline)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<InlineWriteTransport>(Ioc.get_executor());
        Preview::Transport::Connector Connector(Transport);
        const std::array<std::byte, 64> Buffer{};
        bool Called = false;
        std::size_t Bytes = 0;
        boost::system::error_code Error;

        Connector.async_write_some(Net::buffer(Buffer),
                                   [&](boost::system::error_code Ec, const std::size_t N)
                                   {
                                       Called = true;
                                       Error = Ec;
                                       Bytes = N;
                                   });
        EXPECT_FALSE(Called);
        Ioc.run();
        EXPECT_TRUE(Called);
        EXPECT_FALSE(Error);
        EXPECT_EQ(Bytes, Buffer.size());
        EXPECT_EQ(Transport->MaxDepth, 1U);
        Preview::Testing::ExpectFixtureCloseReceipt(Preview::Testing::DriveClose(Ioc, Transport));
    }

TEST(Connector, MoveReleaseAccessors)
    {
        Net::io_context Ioc;
        auto MemoryPair7 = Preview::Testing::MakeOwnedTransportPair(Ioc.get_executor());
        auto& Local = *MemoryPair7.FirstOwner;
        auto& Remote = *MemoryPair7.SecondOwner;
        auto Source = std::make_shared<Preview::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Preview::MemoryStream>(std::move(Remote));

        Preview::Transport::Connector Conn(Destination);
        EXPECT_EQ(&Conn.Transmission(), Destination.get());
        EXPECT_EQ(Conn.Executor(), Conn.get_executor());

        // 移动构造
        Preview::Transport::Connector Moved(std::move(Conn));
        // 移动赋值
        Preview::Transport::Connector Assigned(
            std::make_shared<Preview::MemoryStream>(Ioc.get_executor()));
        Assigned = std::move(Moved);

        // Release 返回底层传输
        auto Released = Assigned.Release();
        EXPECT_EQ(Released.get(), Destination.get());
        Preview::Testing::ExpectFixtureCloseReceipt(Preview::Testing::DriveClose(Ioc, Source));
        Preview::Testing::ExpectFixtureCloseReceipt(Preview::Testing::DriveClose(Ioc, Released));
    }
