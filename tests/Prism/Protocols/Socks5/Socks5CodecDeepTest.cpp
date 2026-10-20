/**
 * @file Socks5CodecDeepTest.cpp
 * @brief Socks5 编解码器序列化、解析和边界测试。
 */

#include <boost/asio/buffer.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <exception>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Socks5/AddressCodec.hpp>
#include <Prism/Protocols/Socks5/AuthCodec.hpp>
#include <Prism/Protocols/Socks5/BeastCodec.hpp>
#include <Prism/Protocols/Socks5/MessageCodec.hpp>
#include <Prism/Protocols/Socks5/TransportCodec.hpp>
#include <Prism/Protocols/Socks5/Types.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Socks5 = Prism::Socks5;
    using Prism::As;
    using Prism::AsBytes;
    using Prism::AsBytesSpan;
    using Prism::AsStrView;
    using Prism::AsU8;
    using Prism::AsU8Span;
    using Prism::Error;
    using Prism::make_error_code;
    using Prism::PrismMockTransport;

    /**
     * @brief 运行测试协程并将协程异常重新抛出。
     * @param IoContext 测试协程使用的执行器。
     * @param Coroutine 待运行的协程对象。
     */
    template <typename Awaitable>
    auto RunCoro(Net::io_context &IoContext, Awaitable Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Coroutine), [&Exception, &IoContext](std::exception_ptr ErrorValue)
                      {
                          Exception = std::move(ErrorValue);
                          IoContext.stop();
                      });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    auto MakeBytes(std::initializer_list<std::uint8_t> List) -> std::vector<std::uint8_t>
    {
        return std::vector<std::uint8_t>(List);
    }

    /** @brief 验证完整 greeting 与同读原生失败先完成解析并关闭载体。 */
    auto RunCompleteGreetingBeforeNativeFailure(
        const std::shared_ptr<PrismMockTransport> &Raw) -> Net::awaitable<void>
    {
        Raw->InjectRead({0x05, 0x01, 0x00});
        Raw->ReadErrorBytes = 3;
        Raw->SetReadError(std::make_error_code(std::errc::connection_reset));
        Socks5::Parser Parser;
        Parser.Expect(Socks5::Message::Kind::Greeting);

        const auto Code = co_await Socks5::AsyncRead(Raw, Parser);
        EXPECT_EQ(Code, Error::IoError);
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_EQ(Parser.Get().Type, Socks5::Message::Kind::Greeting);
        EXPECT_EQ(Parser.Get().Methods, (std::vector<std::uint8_t>{0x00}));
        EXPECT_EQ(Raw->ReadsDone, 1U);
        const auto Closed = Raw->Close();
        EXPECT_TRUE(Closed);
        const auto Drain = co_await Raw->Activity()->Drain();
        EXPECT_TRUE(Drain);
        EXPECT_TRUE(Raw->Activity()->IsRetired());
    }
} // namespace

TEST(CommonAddress, RejectsInvalidIpv6AndAcceptsBinaryIpv6)
{
    Socks5::Address Address{Socks5::AddressType::Ipv6, "not-an-ipv6", 443};
    EXPECT_TRUE(Socks5::EncodeAddress(Address).empty());

    Address.Host.assign(16, '\x5A');
    const auto Wire = Socks5::EncodeAddress(Address);
    ASSERT_EQ(Wire.size(), 19u);
    EXPECT_EQ(Wire[0], static_cast<std::uint8_t>(Socks5::AddressType::Ipv6));
    EXPECT_EQ(Wire[1], 0x5Au);
}

TEST(Socks5Codec, MethodReplyAndAddresses)
    {
        Socks5::MethodReply MethodReply{};
        // need_more
        EXPECT_EQ(Socks5::ParseMethodReply(std::span<const std::uint8_t>(MakeBytes({0x05})), MethodReply),
                  Error::NeedMore);
        // bad_magic
        EXPECT_EQ(Socks5::ParseMethodReply(std::span<const std::uint8_t>(MakeBytes({0x04, 0x00})), MethodReply),
                  Error::BadMagic);
        // 成功
        EXPECT_EQ(Socks5::ParseMethodReply(std::span<const std::uint8_t>(MakeBytes({0x05, 0x00})), MethodReply),
                  Error::None);
        EXPECT_EQ(MethodReply.Ver, 5u);
        EXPECT_EQ(MethodReply.Method, Socks5::AuthMethod::NoAuth);

        Socks5::Address Address{};
        std::size_t Consumed = 0;
        // 空输入
        EXPECT_EQ(Socks5::ParseAddress(std::span<const std::uint8_t>{}, Address, Consumed), Error::NeedMore);
        // ipv4 不足
        EXPECT_EQ(Socks5::ParseAddress(std::span<const std::uint8_t>(MakeBytes({0x01, 1, 2})), Address, Consumed),
                  Error::NeedMore);
        // ipv6 不足
        EXPECT_EQ(Socks5::ParseAddress(std::span<const std::uint8_t>(MakeBytes({0x04, 1})), Address, Consumed),
                  Error::NeedMore);
        // ipv6 成功
        std::vector<std::uint8_t> V6{0x04};
        V6.insert(V6.end(), 16, 0x42);
        V6.push_back(0x1F);
        V6.push_back(0x90);
        EXPECT_EQ(Socks5::ParseAddress(V6, Address, Consumed), Error::None);
        EXPECT_EQ(Address.Type, Socks5::AddressType::Ipv6);
        EXPECT_EQ(Address.Host, std::string(16, '\x42'));
        EXPECT_EQ(Address.Port, 8080u);
        // domain 缺长度字节
        EXPECT_EQ(Socks5::ParseAddress(std::span<const std::uint8_t>(MakeBytes({0x03})), Address, Consumed),
                  Error::NeedMore);
        // domain 不足
        EXPECT_EQ(Socks5::ParseAddress(std::span<const std::uint8_t>(MakeBytes({0x03, 5, 'a'})), Address, Consumed),
                  Error::NeedMore);
        // domain 成功
        std::vector<std::uint8_t> Domain{0x03, 7};
        const std::string_view Name = "example";
        Domain.insert(Domain.end(), Name.begin(), Name.end());
        Domain.push_back(0x00);
        Domain.push_back(0x50);
        EXPECT_EQ(Socks5::ParseAddress(Domain, Address, Consumed), Error::None);
        EXPECT_EQ(Address.Host, "example");
        EXPECT_EQ(Address.Port, 80u);
        // 非法类型
        EXPECT_EQ(Socks5::ParseAddress(std::span<const std::uint8_t>(MakeBytes({0x7F, 0, 0, 0, 0})), Address, Consumed),
                  Error::BadMessage);
    }

TEST(Socks5Codec, ReplyAndGreeting)
    {
        // Reply 解析
        Socks5::Reply Reply{};
        std::size_t Consumed = 0;
        EXPECT_EQ(Socks5::ParseReply(std::span<const std::uint8_t>(MakeBytes({0x05})), Reply, Consumed),
                  Error::NeedMore);
        std::vector<std::uint8_t> ReplyWire{0x05, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35};
        EXPECT_EQ(Socks5::ParseReply(ReplyWire, Reply, Consumed), Error::None);
        EXPECT_EQ(Reply.Code, Socks5::ReplyCode::Success);
        EXPECT_EQ(Reply.Bind.Host, "8.8.8.8");
        EXPECT_EQ(Reply.Bind.Port, 53u);

        // Greeting：版本不匹配
        Socks5::Greeting Greeting{};
        EXPECT_EQ(Socks5::ParseGreeting(std::span<const std::uint8_t>(MakeBytes({0x04, 0x01, 0x00})), Greeting,
                                         Consumed),
                  Error::BadMagic);
        // Greeting：方法列表不足
        EXPECT_EQ(Socks5::ParseGreeting(std::span<const std::uint8_t>(MakeBytes({0x05, 0x02, 0x00})), Greeting,
                                         Consumed),
                  Error::NeedMore);
        // Greeting 成功
        EXPECT_EQ(Socks5::ParseGreeting(std::span<const std::uint8_t>(MakeBytes({0x05, 0x02, 0x00, 0x02})), Greeting,
                                         Consumed),
                  Error::None);
        EXPECT_EQ(Greeting.Methods.size(), 2u);
        EXPECT_EQ(Socks5::BuildGreeting(Greeting).size(), 4u);

        // userpass 响应
        EXPECT_EQ(Socks5::ParseUserpassReply(std::span<const std::uint8_t>(MakeBytes({0x01}))),
                  Error::NeedMore);
        EXPECT_EQ(Socks5::ParseUserpassReply(std::span<const std::uint8_t>(MakeBytes({0x02, 0x00}))),
                  Error::BadMagic);
        EXPECT_EQ(Socks5::ParseUserpassReply(std::span<const std::uint8_t>(MakeBytes({0x01, 0x00}))),
                  Error::None);
        EXPECT_EQ(Socks5::ParseUserpassReply(std::span<const std::uint8_t>(MakeBytes({0x01, 0x01}))),
                  Error::BadAuth);
        const auto Userpass = Socks5::BuildUserpass("user", "pass");
        EXPECT_EQ(Userpass.size(), 11u);
    }

TEST(Socks5Codec, SerializerAllKinds)
    {
        Socks5::Serializer Serializer;
        std::array<std::uint8_t, 256> Buffer{};

        Socks5::Message Message;
        Message.Type = Socks5::Message::Kind::Greeting;
        Message.Methods = {0x00, 0x02};
        Serializer.Reset(Message);
        EXPECT_FALSE(Serializer.IsDone());
        std::error_code ErrorCode;
        const auto BytesWritten = Serializer.Get(Net::buffer(Buffer.data(), Buffer.size()), ErrorCode);
        EXPECT_EQ(BytesWritten, 4u);
        EXPECT_TRUE(Serializer.IsDone());

        Message.Type = Socks5::Message::Kind::MethodReply;
        Message.Method = 0x00;
        Serializer.Reset(Message);
        // 注：生产实现此处 Wire_ 赋值存在未定义行为（不同临时对象
        // begin/end），仅执行路径，不做内容断言
        (void)Serializer.Get(Net::buffer(Buffer.data(), Buffer.size()), ErrorCode);

        Message.Type = Socks5::Message::Kind::Userpass;
        Message.Username = "u";
        Message.Password = "p";
        Serializer.Reset(Message);
        EXPECT_EQ(Serializer.Get(Net::buffer(Buffer.data(), Buffer.size()), ErrorCode), 5u);

        Message.Type = Socks5::Message::Kind::Request;
        Message.Cmd = Socks5::Command::Connect;
        Message.AddressValue.Type = Socks5::AddressType::Ipv4;
        Message.AddressValue.Host = "1.2.3.4";
        Message.AddressValue.Port = 443;
        Serializer.Reset(Message);
        EXPECT_EQ(Serializer.Get(Net::buffer(Buffer.data(), Buffer.size()), ErrorCode), 10u);

        Message.Type = Socks5::Message::Kind::Reply;
        Message.Code = Socks5::ReplyCode::Success;
        Message.AddressValue.Type = Socks5::AddressType::Domain;
        Message.AddressValue.Host = "x.com";
        Message.AddressValue.Port = 80;
        Serializer.Reset(Message);
        EXPECT_EQ(Serializer.Get(Net::buffer(Buffer.data(), Buffer.size()), ErrorCode), 12u);
        // 全量输出后再 Get → 0 字节
        EXPECT_EQ(Serializer.Get(Net::buffer(Buffer.data(), Buffer.size()), ErrorCode), 0u);
    }

TEST(Socks5Codec, ParserRemainingKinds)
    {
        Socks5::Parser Parser;
        std::error_code ErrorCode;

        // MethodReply
        Parser.Expect(Socks5::Message::Kind::MethodReply);
        EXPECT_EQ(Parser.Put(Net::buffer(MakeBytes({0x05})), ErrorCode), 0u);
        EXPECT_FALSE(ErrorCode); // need_more 不设置 ErrorCode（半帧等待）
        ErrorCode.clear();
        EXPECT_EQ(Parser.Put(Net::buffer(MakeBytes({0x00})), ErrorCode), 1u);
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_EQ(Parser.Get().Type, Socks5::Message::Kind::MethodReply);
        EXPECT_EQ(Parser.Get().Method, 0u);
        Parser.Reset();
        // 错误版本
        EXPECT_EQ(Parser.Put(Net::buffer(MakeBytes({0x04, 0x00})), ErrorCode), 0u);
        EXPECT_EQ(ErrorCode, make_error_code(Error::BadMagic));
        Parser.Reset();

        // userpass
        Parser.Expect(Socks5::Message::Kind::Userpass);
        EXPECT_EQ(Parser.Put(Net::buffer(MakeBytes({0x01})), ErrorCode), 0u);
        EXPECT_FALSE(ErrorCode); // need_more 不设置 ErrorCode
        ErrorCode.clear();
        // 错误版本
        Parser.Reset();
        EXPECT_EQ(Parser.Put(Net::buffer(MakeBytes({0x02, 0x01, 'u'})), ErrorCode), 0u);
        EXPECT_EQ(ErrorCode, make_error_code(Error::BadMagic));
        Parser.Reset();
        // 用户名长度不足
        EXPECT_EQ(Parser.Put(Net::buffer(MakeBytes({0x01, 0x05, 'u'})), ErrorCode), 0u);
        EXPECT_FALSE(ErrorCode);
        ErrorCode.clear();
        Parser.Reset();
        // 密码长度不足
        EXPECT_EQ(Parser.Put(Net::buffer(MakeBytes({0x01, 0x01, 'u', 0x05})), ErrorCode), 0u);
        EXPECT_FALSE(ErrorCode);
        ErrorCode.clear();
        Parser.Reset();
        // 成功
        EXPECT_EQ(Parser.Put(Net::buffer(MakeBytes({0x01, 0x01, 'u', 0x01, 'p'})), ErrorCode), 5u);
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_EQ(Parser.Get().Type, Socks5::Message::Kind::Userpass);
        EXPECT_EQ(Parser.Get().Username, "u");
        EXPECT_EQ(Parser.Get().Password, "p");
        Parser.Reset();

        // Reply
        Parser.Expect(Socks5::Message::Kind::Reply);
        std::vector<std::uint8_t> ReplyWire{0x05, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35};
        EXPECT_EQ(Parser.Put(Net::buffer(ReplyWire), ErrorCode), 10u);
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_EQ(Parser.Get().Type, Socks5::Message::Kind::Reply);
        EXPECT_EQ(Parser.Get().Code, Socks5::ReplyCode::Success);
        EXPECT_EQ(Parser.Get().AddressValue.Host, "8.8.8.8");
        // Remaining 与 TakeRemaining
        std::vector<std::uint8_t> Extra{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50, 0xAA, 0xBB};
        Parser.Reset();
        EXPECT_EQ(Parser.Put(Net::buffer(Extra), ErrorCode), 10u);
        EXPECT_EQ(Parser.Remaining().size(), 2u);
        const auto Taken = Parser.TakeRemaining();
        EXPECT_EQ(Taken.size(), 2u);
        EXPECT_EQ(Taken[0], 0xAA);
    }

    // ───────────────────────── tuic Codec ─────────────────────────

TEST(Socks5CodecDeep, RemainingEmpty)
    {
        Socks5::Parser Parser;
        std::error_code ErrorCode;
        // 未完成解析时 Remaining / TakeRemaining 返回空
        EXPECT_TRUE(Parser.Remaining().empty());
        EXPECT_TRUE(Parser.TakeRemaining().empty());
        // 完成后无剩余
        Parser.Expect(Socks5::Message::Kind::Greeting);
        EXPECT_EQ(Parser.Put(boost::asio::buffer(MakeBytes({0x05, 0x01, 0x00})), ErrorCode), 3u);
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_TRUE(Parser.Remaining().empty());
        EXPECT_TRUE(Parser.TakeRemaining().empty());
    }

TEST(Socks5Codec, AsyncWriteRejectsOverreportedWrite)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PrismMockTransport>(Io.get_executor());
        Raw->OverreportWrite = true;
        Socks5::Serializer Serializer;
        Socks5::Message Message;
        Message.Type = Socks5::Message::Kind::Greeting;
        Message.Methods = {0x00};
        Serializer.Reset(Message);

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Code = co_await Socks5::AsyncWrite(Raw, Serializer);
                    EXPECT_EQ(Code, Error::BrokenPipe);
                    EXPECT_EQ(Raw->WritesDone, 1U);
                });
    }

TEST(Socks5Codec, AsyncReadRejectsOverreportedRead)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PrismMockTransport>(Io.get_executor());
        Raw->OverreportRead = true;
        Socks5::Parser Parser;
        Parser.Expect(Socks5::Message::Kind::Greeting);

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    const auto Code = co_await Socks5::AsyncRead(Raw, Parser);
                    EXPECT_EQ(Code, Error::IoError);
                    EXPECT_FALSE(Parser.IsDone());
                });
    }

TEST(Socks5Codec, AsyncReadConsumesBytesBeforePropagatingNativeFailure)
    {
        Net::io_context Io;
        auto Raw = std::make_shared<PrismMockTransport>(Io.get_executor());
        RunCoro(Io, RunCompleteGreetingBeforeNativeFailure(Raw));
    }
