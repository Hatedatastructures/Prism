/**
 * @file BeastTest.cpp
 * @brief SOCKS5 Beast 风格组件测试
 * @details 覆盖：Parser 增量解析（半包/粘包）、Serializer 输出、
 *          错误处理（版本/命令/地址非法）。
 */

#include <Prism/Protocols/Socks5/BeastCodec.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Socks5 = Prism::Socks5;
    using Prism::Error;

    /// 构造 Greeting 消息
    auto MakeGreeting() -> Socks5::Message
    {
        Socks5::Message Message;
        Message.Type = Socks5::Message::Kind::Greeting;
        Message.Methods = {static_cast<std::uint8_t>(Socks5::AuthMethod::NoAuth)};
        return Message;
    }

    /// 构造 Request 消息
    auto MakeRequest() -> Socks5::Message
    {
        Socks5::Message Message;
        Message.Type = Socks5::Message::Kind::Request;
        Message.Cmd = Socks5::Command::Connect;
        Message.AddressValue.Type = Socks5::AddressType::Ipv4;
        Message.AddressValue.Host = "127.0.0.1";
        Message.AddressValue.Port = 8080;
        return Message;
    }

    TEST(Socks5Beast, SerializerGreeting)
    {
        Socks5::Serializer Serializer;
        Serializer.Reset(MakeGreeting());
        std::error_code ErrorCode;
        std::array<std::uint8_t, 64> Output{};
        const auto Count = Serializer.Get(Net::mutable_buffer(Output.data(), Output.size()), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(Count, 3);
        EXPECT_EQ(Output[0], 0x05);
        EXPECT_EQ(Output[1], 0x01);
        EXPECT_EQ(Output[2], 0x00);
        EXPECT_TRUE(Serializer.IsDone());
    }

    TEST(Socks5Beast, SerializerRequest)
    {
        Socks5::Serializer Serializer;
        Serializer.Reset(MakeRequest());
        std::error_code ErrorCode;
        std::array<std::uint8_t, 64> Output{};
        const auto Count = Serializer.Get(Net::mutable_buffer(Output.data(), Output.size()), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(Count, 10);
        // [05 01 00 01 7F 00 00 01 1F 90]
        EXPECT_EQ(Output[0], 0x05);
        EXPECT_EQ(Output[1], 0x01);
        EXPECT_EQ(Output[3], 0x01);
        EXPECT_EQ(Output[4], 127);
        EXPECT_EQ(Output[8], 0x1F);
        EXPECT_EQ(Output[9], 0x90);
    }

    TEST(Socks5Beast, SerializerMethodReply)
    {
        Socks5::Serializer Serializer;
        Socks5::Message Message;
        Message.Type = Socks5::Message::Kind::MethodReply;
        Message.Method = static_cast<std::uint8_t>(Socks5::AuthMethod::NoAuth);
        Serializer.Reset(Message);
        std::error_code ErrorCode;
        std::array<std::uint8_t, 2> Output{};
        const auto Count = Serializer.Get(Net::mutable_buffer(Output.data(), Output.size()), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(Count, 2U);
        EXPECT_EQ(Output[0], 0x05);
        EXPECT_EQ(Output[1], 0x00);
        EXPECT_TRUE(Serializer.IsDone());
    }

    TEST(Socks5Beast, ParserFullFrame)
    {
        // Greeting 一次喂入
        Socks5::Serializer Serializer;
        Serializer.Reset(MakeGreeting());
        std::array<std::uint8_t, 64> Wire{};
        std::error_code ErrorCode;
        Serializer.Get(Net::mutable_buffer(Wire.data(), Wire.size()), ErrorCode);

        Socks5::Parser Parser;
        Parser.Expect(Socks5::Message::Kind::Greeting);
        const auto Consumed = Parser.Put(Net::const_buffer(Wire.data(), 3), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(Consumed, 3);
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_EQ(Parser.Get().Type, Socks5::Message::Kind::Greeting);
        EXPECT_EQ(Parser.Get().Methods.size(), 1u);
        EXPECT_EQ(Parser.Get().Methods[0], static_cast<std::uint8_t>(Socks5::AuthMethod::NoAuth));
    }

    TEST(Socks5Beast, ParserIncrementalHalfFrame)
    {
        Socks5::Parser Parser;
        Parser.Expect(Socks5::Message::Kind::Greeting);
        std::error_code ErrorCode;

        // 半包：先喂 2 字节
        std::array<std::uint8_t, 2> PartOne{0x05, 0x01};
        const auto FirstConsumed = Parser.Put(Net::const_buffer(PartOne.data(), PartOne.size()), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(FirstConsumed, 0); // 未消费（不足完整帧）
        EXPECT_FALSE(Parser.IsDone());

        // 补全
        std::array<std::uint8_t, 1> PartTwo{0x00};
        const auto SecondConsumed = Parser.Put(Net::const_buffer(PartTwo.data(), PartTwo.size()), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(SecondConsumed, 1);
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_EQ(Parser.Get().Methods[0], static_cast<std::uint8_t>(Socks5::AuthMethod::NoAuth));
    }

    TEST(Socks5Beast, ParserPipelinedFrames)
    {
        // 粘包：Request + Greeting 同包
        Socks5::Serializer SerializerValue;
        SerializerValue.Reset(MakeRequest());
        std::array<std::uint8_t, 64> Wire{};
        std::error_code ErrorCode;
        const auto RequestLength = SerializerValue.Get(Net::mutable_buffer(Wire.data(), Wire.size()), ErrorCode);

        Socks5::Parser Parser;
        Parser.Expect(Socks5::Message::Kind::Request);
        const auto Consumed = Parser.Put(Net::const_buffer(Wire.data(), RequestLength), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(Consumed, RequestLength);
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_EQ(Parser.Get().Type, Socks5::Message::Kind::Request);
        EXPECT_EQ(Parser.Get().Cmd, Socks5::Command::Connect);
        EXPECT_EQ(Parser.Get().AddressValue.Host, "127.0.0.1");
        EXPECT_EQ(Parser.Get().AddressValue.Port, 8080);
    }

    TEST(Socks5Beast, ParserRejectsBadVersion)
    {
        Socks5::Parser Parser;
        Parser.Expect(Socks5::Message::Kind::Greeting);
        std::error_code ErrorCode;
        std::array<std::uint8_t, 3> BadWire{0x04, 0x01, 0x00};
        Parser.Put(Net::const_buffer(BadWire.data(), BadWire.size()), ErrorCode);
        EXPECT_EQ(ErrorCode, Error::BadMagic);
    }

    TEST(Socks5Beast, ParserRejectsBadCommand)
    {
        Socks5::Parser Parser;
        Parser.Expect(Socks5::Message::Kind::Request);
        std::error_code ErrorCode;
        // 非法命令 0x09
        std::array<std::uint8_t, 7> BadWire{0x05, 0x09, 0x00, 0x01, 127, 0, 0};
        Parser.Put(Net::const_buffer(BadWire.data(), BadWire.size()), ErrorCode);
        EXPECT_EQ(ErrorCode, Error::Unsupported);
    }

    TEST(Socks5Beast, ParserRejectsNonZeroReservedRequest)
    {
        Socks5::Parser Parser;
        Parser.Expect(Socks5::Message::Kind::Request);
        std::error_code ErrorCode;
        const std::array<std::uint8_t, 10> BadWire{
            0x05, 0x01, 0x01, 0x01, 127, 0, 0, 1, 0x01, 0xBB};

        Parser.Put(Net::const_buffer(BadWire.data(), BadWire.size()), ErrorCode);

        EXPECT_EQ(ErrorCode, Error::BadMessage);
    }

    TEST(Socks5Beast, ParserRejectsBadAddressType)
    {
        Socks5::Parser Parser;
        Parser.Expect(Socks5::Message::Kind::Request);
        std::error_code ErrorCode;
        std::array<std::uint8_t, 4> BadWire{0x05, 0x01, 0x00, 0x09};
        Parser.Put(Net::const_buffer(BadWire.data(), BadWire.size()), ErrorCode);
        EXPECT_EQ(ErrorCode, Error::BadMessage);
    }

    TEST(Socks5Beast, ParserRejectsNonZeroReservedReply)
    {
        Socks5::Parser Parser;
        Parser.Expect(Socks5::Message::Kind::Reply);
        std::error_code ErrorCode;
        const std::array<std::uint8_t, 10> BadWire{
            0x05, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0x01, 0xBB};

        Parser.Put(Net::const_buffer(BadWire.data(), BadWire.size()), ErrorCode);

        EXPECT_EQ(ErrorCode, Error::BadMessage);
    }

    TEST(Socks5Beast, ParserRejectsBadReplyVersion)
    {
        Socks5::Parser Parser;
        Parser.Expect(Socks5::Message::Kind::Reply);
        std::error_code ErrorCode;
        const std::array<std::uint8_t, 10> BadWire{
            0x04, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xBB};

        Parser.Put(Net::const_buffer(BadWire.data(), BadWire.size()), ErrorCode);

        EXPECT_EQ(ErrorCode, Error::BadMagic);
    }

    TEST(Socks5Beast, ParserResetReuse)
    {
        Socks5::Parser Parser;
        Parser.Expect(Socks5::Message::Kind::Greeting);
        std::error_code ErrorCode;
        std::array<std::uint8_t, 3> GreetingWire{0x05, 0x01, 0x00};
        Parser.Put(Net::const_buffer(GreetingWire.data(), GreetingWire.size()), ErrorCode);
        EXPECT_TRUE(Parser.IsDone());

        Parser.Reset();
        Parser.Expect(Socks5::Message::Kind::Greeting);
        Parser.Put(Net::const_buffer(GreetingWire.data(), GreetingWire.size()), ErrorCode);
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_EQ(Parser.Get().Methods.size(), 1u);
    }

} // namespace
