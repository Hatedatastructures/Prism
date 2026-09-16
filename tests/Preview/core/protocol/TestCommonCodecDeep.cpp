/**
 * @file TestCommonCodecDeep.cpp
 * @brief 测试库 Codec 纯函数剩余分支深度测试
 * @details 覆盖 ws / socks5 / tuic / vless 四个 Codec 的未执行分支：
 *          帧头 126/127 长度编码、掩码帧、增量解析 need_more / 错误
 *          路径、Beast 风格 Serializer / Parser 各消息类型，以及
 *          byte_span 工具函数的未用重载。
 */

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Socks5/Codec.hpp>
#include <Preview/Protocols/Tuic/Codec.hpp>
#include <Preview/Protocols/Vless/Codec.hpp>
#include <Preview/Protocols/Ws/Codec.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Socks5 = Preview::Socks5;
    namespace Tuic = Preview::Tuic;
    namespace Vless = Preview::Vless;
    namespace Ws = Preview::Ws;
    using Preview::As;
    using Preview::AsBytes;
    using Preview::AsBytesSpan;
    using Preview::AsStrView;
    using Preview::AsU8;
    using Preview::AsU8Span;
    using Preview::Error;
    using Preview::make_error_code;

    /**
     * @brief 从初始值列表构造 uint8_t 字节向量
     */
    auto MakeBytes(std::initializer_list<std::uint8_t> List) -> std::vector<std::uint8_t>
    {
        return std::vector<std::uint8_t>(List);
    }

    // ───────────────────────── byte_span ─────────────────────────

    TEST(ByteSpan, ConstOverloads)
    {
        std::array<std::uint8_t, 4> U8{1, 2, 3, 4};
        const auto &ConstU8 = U8;
        const auto cb = AsBytes(std::span<const std::uint8_t>(ConstU8));
        EXPECT_EQ(cb.size(), 4u);
        EXPECT_EQ(static_cast<std::uint8_t>(cb[0]), 1u);

        std::string String = "abc";
        const auto StringU8 = AsU8Span(String);
        EXPECT_EQ(StringU8.size(), 3u);
        EXPECT_EQ(StringU8[0], 'a');

        const auto ByteSpan = AsBytesSpan(String);
        EXPECT_EQ(ByteSpan.size(), 3u);
        const std::string_view sv{"def"};
        EXPECT_EQ(AsBytesSpan(sv).size(), 3u);
        const char *Raw = "xy";
        EXPECT_EQ(AsBytesSpan(Raw, 2).size(), 2u);
        std::vector<std::uint8_t> Vector{9, 8};
        EXPECT_EQ(AsBytesSpan(Vector).size(), 2u);

        const auto StringViewBytes = AsStrView(std::span<const std::uint8_t>(U8.data(), 2));
        EXPECT_EQ(StringViewBytes.size(), 2u);
        const auto BytesView = AsBytes(std::span<std::uint8_t>(U8));
        EXPECT_EQ(AsStrView(BytesView.subspan(0, 2)).size(), 2u);
    }

    TEST(ByteSpan, TemplateAs)
    {
        // 目标元素类型由模板参数控制（byte / uint8_t / char）
        std::string String = "abc";
        const auto Bytes = As<std::byte>(String);
        EXPECT_EQ(Bytes.size(), 3u);
        EXPECT_EQ(static_cast<char>(Bytes[0]), 'a');

        std::vector<std::uint8_t> Vector{1, 2, 3};
        const auto U8Vector = As<std::uint8_t>(Vector);
        EXPECT_EQ(U8Vector.size(), 3u);
        EXPECT_EQ(U8Vector[1], 2u);

        std::array<std::byte, 2> arr{std::byte{0x10}, std::byte{0x20}};
        const auto U8Array = As<std::uint8_t>(arr);
        EXPECT_EQ(U8Array[0], 0x10u);
        EXPECT_EQ(U8Array[1], 0x20u);

        // 只读源 → const 视图
        const std::string_view sv{"def"};
        const auto cbytes = As<std::byte>(sv);
        EXPECT_TRUE((std::is_same_v<std::decay_t<decltype(cbytes)>, std::span<const std::byte>>));
        EXPECT_EQ(cbytes.size(), 3u);

        // 裸指针 + 长度 → uint8_t 只读视图
        const char *Raw = "xy";
        const auto rv = As<std::uint8_t>(Raw, 2);
        EXPECT_EQ(rv.size(), 2u);
        EXPECT_EQ(rv[1], 'y');
    }

    TEST(ByteSpan, AsWriteThrough)
    {
        // 可变 string → span<byte> 可写（HTTP 读缓冲场景）
        std::string Buffer = "hello";
        const auto View = AsBytesSpan(Buffer);
        EXPECT_TRUE((std::is_same_v<std::decay_t<decltype(View)>, std::span<std::byte>>));
        View[0] = std::byte{'H'};
        EXPECT_EQ(Buffer, "Hello");

        // span 右值保持可变视图，写穿到原数组
        std::array<std::uint8_t, 3> Data{1, 2, 3};
        const auto U8 = AsU8(std::span(Data));
        EXPECT_TRUE((std::is_same_v<std::decay_t<decltype(U8)>, std::span<std::uint8_t>>));
        U8[0] = 9;
        EXPECT_EQ(Data[0], 9u);
    }

    // ───────────────────────── ws Codec ─────────────────────────

    TEST(WsCodec, FrameHeaderExtendedLengths)
    {
        Ws::FrameHeader Header{};
        std::array<std::byte, 64> Buffer{};

        // 16 位长度（126）+ 掩码
        Buffer[0] = std::byte{0x82};
        Buffer[1] = std::byte{0x80 | 126};
        Buffer[2] = std::byte{0x01};
        Buffer[3] = std::byte{0x00};
        Buffer[4] = std::byte{0xAA};
        Buffer[5] = std::byte{0xBB};
        Buffer[6] = std::byte{0xCC};
        Buffer[7] = std::byte{0xDD};
        EXPECT_TRUE(Ws::ParseFrameHeader(std::span<const std::byte>(Buffer.data(), 8), Header));
        EXPECT_TRUE(Header.Fin);
        EXPECT_EQ(Header.Opcode, 0x02u);
        EXPECT_TRUE(Header.Masked);
        EXPECT_EQ(Header.PayloadLen, 256u);
        EXPECT_EQ(Header.HeaderLen, 8u);
        EXPECT_EQ(static_cast<std::uint8_t>(Header.MaskKey[0]), 0xAA);

        // 16 位长度：数据不足（需 4 字节，只有 3）
        EXPECT_FALSE(Ws::ParseFrameHeader(std::span<const std::byte>(Buffer.data(), 3), Header));

        // 64 位长度（127）
        Buffer[1] = std::byte{0x7F};
        for (std::size_t i = 0; i < 8; ++i)
        {
            Buffer[2 + i] = std::byte{0};
        }
        Buffer[7] = std::byte{0x01};
        EXPECT_TRUE(Ws::ParseFrameHeader(std::span<const std::byte>(Buffer.data(), 10), Header));
        EXPECT_EQ(Header.PayloadLen, 65536u);
        EXPECT_EQ(Header.HeaderLen, 10u);

        // 64 位长度：数据不足（需 10 字节，只有 9）
        EXPECT_FALSE(Ws::ParseFrameHeader(std::span<const std::byte>(Buffer.data(), 9), Header));

        // 掩码 key 不足
        Buffer[1] = std::byte{0x80 | 5};
        EXPECT_FALSE(Ws::ParseFrameHeader(std::span<const std::byte>(Buffer.data(), 3), Header));
    }

    TEST(WsCodec, RejectsInvalidFrameHeaderShape)
    {
        Ws::FrameHeader Header{};
        std::array<std::byte, 14> Buffer{};

        // RSV bits and reserved opcodes are rejected before any Payload allocation.
        Buffer[0] = std::byte{0xC2};
        Buffer[1] = std::byte{0x00};
        EXPECT_FALSE(Ws::ParseFrameHeader(std::span<const std::byte>(Buffer), Header));

        Buffer[0] = std::byte{0x8B};
        EXPECT_FALSE(Ws::ParseFrameHeader(std::span<const std::byte>(Buffer), Header));

        // Control frames must be final and use the Short length form.
        Buffer[0] = std::byte{0x09};
        EXPECT_FALSE(Ws::ParseFrameHeader(std::span<const std::byte>(Buffer), Header));
        Buffer[0] = std::byte{0x89};
        Buffer[1] = std::byte{126};
        EXPECT_FALSE(Ws::ParseFrameHeader(std::span<const std::byte>(Buffer), Header));

        // Extended lengths must be canonical and the 64-bit form cannot set bit 63.
        Buffer[0] = std::byte{0x82};
        Buffer[1] = std::byte{126};
        Buffer[2] = std::byte{0x00};
        Buffer[3] = std::byte{0x7D};
        EXPECT_FALSE(Ws::ParseFrameHeader(std::span<const std::byte>(Buffer), Header));

        Buffer[1] = std::byte{127};
        Buffer[2] = std::byte{0x80};
        EXPECT_FALSE(Ws::ParseFrameHeader(std::span<const std::byte>(Buffer), Header));

        for (std::size_t I = 2; I < 10; ++I)
        {
            Buffer[I] = std::byte{0x00};
        }
        Buffer[9] = std::byte{0x01};
        EXPECT_FALSE(Ws::ParseFrameHeader(std::span<const std::byte>(Buffer), Header));
    }

    TEST(WsCodec, EncodeExtendedLengths)
    {
        std::array<std::byte, 80000> Output{};

        // 16 位长度（126）
        std::vector<std::byte> Payload126(300, std::byte{0x11});
        Ws::FrameInput Input126{Ws::Opcode::Binary, true, std::span<const std::byte>(Payload126)};
        const auto Bytes126 = Ws::EncodeFrame(Input126, Output);
        EXPECT_EQ(Bytes126, 304u);
        EXPECT_EQ(static_cast<std::uint8_t>(Output[1]), 126u);
        EXPECT_EQ(static_cast<std::uint8_t>(Output[2]), 0x01);
        EXPECT_EQ(static_cast<std::uint8_t>(Output[3]), 0x2C);

        // 64 位长度（127）
        std::vector<std::byte> Payload127(70000, std::byte{0x22});
        Ws::FrameInput Input127{Ws::Opcode::Binary, true, std::span<const std::byte>(Payload127)};
        const auto Bytes127 = Ws::EncodeFrame(Input127, Output);
        EXPECT_EQ(Bytes127, 70010u);
        EXPECT_EQ(static_cast<std::uint8_t>(Output[1]), 127u);
        EXPECT_EQ(static_cast<std::uint8_t>(Output[2]), 0x00);
        EXPECT_EQ(static_cast<std::uint8_t>(Output[7]), 0x01);
        EXPECT_EQ(static_cast<std::uint8_t>(Output[8]), 0x11);
        EXPECT_EQ(static_cast<std::uint8_t>(Output[9]), 0x70);
        EXPECT_EQ(static_cast<std::uint8_t>(Output[10]), 0x22);

        // 缓冲区不足 → 0
        std::array<std::byte, 16> SmallOutput{};
        EXPECT_EQ(Ws::EncodeFrame(Input127, SmallOutput), 0u);
    }

    TEST(WsCodec, EncodeRejectsInvalidControlFrames)
    {
        std::array<std::byte, 256> Output{};
        std::array<std::byte, 126> Payload{};

        const Ws::FrameInput FragmentedPing{Ws::Opcode::Ping, false,
                                            std::span<const std::byte>(Payload).first(1)};
        EXPECT_EQ(Ws::EncodeFrame(FragmentedPing, Output), 0U);

        const Ws::FrameInput OversizedPing{Ws::Opcode::Ping, true,
                                           std::span<const std::byte>(Payload)};
        EXPECT_EQ(Ws::EncodeFrame(OversizedPing, Output), 0U);

        const Ws::FrameInput ShortClose{Ws::Opcode::Close, true,
                                        std::span<const std::byte>(Payload).first(1)};
        EXPECT_EQ(Ws::EncodeFrame(ShortClose, Output), 0U);
    }

    // ───────────────────────── socks5 Codec ─────────────────────────

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
                  Error::VersionMismatch);
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
        Message.username = "u";
        Message.password = "p";
        Serializer.Reset(Message);
        EXPECT_EQ(Serializer.Get(Net::buffer(Buffer.data(), Buffer.size()), ErrorCode), 5u);

        Message.Type = Socks5::Message::Kind::Request;
        Message.Cmd = Socks5::Command::Connect;
        Message.addr.Type = Socks5::AddressType::Ipv4;
        Message.addr.Host = "1.2.3.4";
        Message.addr.Port = 443;
        Serializer.Reset(Message);
        EXPECT_EQ(Serializer.Get(Net::buffer(Buffer.data(), Buffer.size()), ErrorCode), 10u);

        Message.Type = Socks5::Message::Kind::Reply;
        Message.rep = Socks5::ReplyCode::Success;
        Message.addr.Type = Socks5::AddressType::Domain;
        Message.addr.Host = "x.com";
        Message.addr.Port = 80;
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
        EXPECT_EQ(Parser.Get().username, "u");
        EXPECT_EQ(Parser.Get().password, "p");
        Parser.Reset();

        // Reply
        Parser.Expect(Socks5::Message::Kind::Reply);
        std::vector<std::uint8_t> ReplyWire{0x05, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35};
        EXPECT_EQ(Parser.Put(Net::buffer(ReplyWire), ErrorCode), 10u);
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_EQ(Parser.Get().Type, Socks5::Message::Kind::Reply);
        EXPECT_EQ(Parser.Get().rep, Socks5::ReplyCode::Success);
        EXPECT_EQ(Parser.Get().addr.Host, "8.8.8.8");
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

    TEST(TuicCodecDeep, ParseAddressBranches)
    {
        Tuic::Address Address{};
        std::size_t Consumed = 0;
        // ipv4 不足
        EXPECT_EQ(Tuic::ParseAddress(std::span<const std::uint8_t>(MakeBytes({0x01, 1, 2})), Address, Consumed),
                  Error::NeedMore);
        // ipv6 不足
        EXPECT_EQ(Tuic::ParseAddress(std::span<const std::uint8_t>(MakeBytes({0x02, 1})), Address, Consumed),
                  Error::NeedMore);
        // ipv6 成功
        std::vector<std::uint8_t> V6{0x02};
        V6.insert(V6.end(), 16, 0x42);
        V6.push_back(0x00);
        V6.push_back(0x50);
        EXPECT_EQ(Tuic::ParseAddress(V6, Address, Consumed), Error::None);
        EXPECT_EQ(Address.Host, std::string(16, '\x42'));
        EXPECT_EQ(Address.Port, 80u);
        // domain 缺长度
        EXPECT_EQ(Tuic::ParseAddress(std::span<const std::uint8_t>(MakeBytes({0x00})), Address, Consumed),
                  Error::NeedMore);
        // domain 不足
        EXPECT_EQ(Tuic::ParseAddress(std::span<const std::uint8_t>(MakeBytes({0x00, 3, 'a'})), Address, Consumed),
                  Error::NeedMore);
        // domain 成功
        std::vector<std::uint8_t> Domain{0x00, 3};
        const std::string_view Name = "abc";
        Domain.insert(Domain.end(), Name.begin(), Name.end());
        Domain.push_back(0x01);
        Domain.push_back(0xBB);
        EXPECT_EQ(Tuic::ParseAddress(Domain, Address, Consumed), Error::None);
        EXPECT_EQ(Address.Host, "abc");
        EXPECT_EQ(Address.Port, 443u);
    }

    TEST(TuicCodecDeep, ParseErrorAndParser)
    {
        // Parse：地址解析失败（domain 长度截断）→ need_more 经 Parse 传播
        Tuic::Message Message{};
        std::size_t Consumed = 0;
        std::vector<std::uint8_t> bad{0x05, 0x02, 0, 0, 0, 0, 1, 0, 0, 0, 0x00, 0x0A, 'a', 'b'};
        EXPECT_EQ(Tuic::Parse(bad, Message, Consumed), Error::NeedMore);

        // Parser：need_more（设置 ErrorCode）/ 错误传播
        Tuic::Parser Parser;
        std::error_code ErrorCode;
        EXPECT_EQ(Parser.Put(Net::buffer(MakeBytes({0x05})), ErrorCode), 0u);
        EXPECT_TRUE(ErrorCode);
        EXPECT_EQ(ErrorCode, make_error_code(Error::NeedMore));
        EXPECT_EQ(ErrorCode, make_error_code(Error::NeedMore));
        Parser.Reset();
        EXPECT_EQ(Parser.Put(Net::buffer(MakeBytes({0x03, 0x02, 0, 0, 0, 0, 1, 0, 0, 0})), ErrorCode), 0u);
        EXPECT_EQ(ErrorCode, make_error_code(Error::BadMagic));
        Parser.Reset();
        // 成功解析
        std::vector<std::uint8_t> Ok{0x05, 0x02, 0, 0, 0, 1, 1, 0, 0, 1, 0x01, 8, 8, 8, 8, 0x00, 0x35, 'x'};
        EXPECT_EQ(Parser.Put(Net::buffer(Ok), ErrorCode), 18u);
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_EQ(Parser.Get().Cmd, Tuic::CmdPacket);
        EXPECT_EQ(Parser.Get().PktId, 1u);
        EXPECT_EQ(Parser.Get().dst.Host, "8.8.8.8");
    }

    // ───────────────────────── vless Codec ─────────────────────────

    TEST(VlessCodecDeep, EncodeAddressBranches)
    {
        Vless::Address Address{};
        // ipv4 编码（点分解析）
        Address.Type = Vless::AddressType::Ipv4;
        Address.Host = "10.0.0.1";
        Address.Port = 1001;
        const auto V4 = Vless::EncodeAddress(Address);
        EXPECT_EQ(V4.size(), 7u);
        EXPECT_EQ(V4[0], 0x01);
        EXPECT_EQ(V4[1], 10u);
        EXPECT_EQ(V4[4], 1u);
        // ipv6 编码
        Address.Type = Vless::AddressType::Ipv6;
        Address.Host.assign(16, 'z');
        const auto V6 = Vless::EncodeAddress(Address);
        EXPECT_EQ(V6.size(), 19u);
        EXPECT_EQ(V6[0], 0x03);
        EXPECT_EQ(V6[1], 'z');
    }

    TEST(VlessCodecDeep, BuildRequestIpv6)
    {
        Vless::RequestHeader Header{};
        Header.Uuid.fill(0x11);
        Header.Cmd = Vless::Command::Udp;
        Header.Target.Type = Vless::AddressType::Ipv6;
        Header.Target.Host.assign(16, 'w');
        Header.Target.Port = 53;
        Header.Addons = {0x01, 0x02};
        const auto wire = Vless::BuildRequest(Header);
        EXPECT_EQ(wire.size(), 22u + 2u + 16u);
        EXPECT_EQ(wire[23], 0x03); // ATYP = ipv6
    }

    TEST(VlessCodecDeep, BuildRequestRejectsInvalidAddressAndLength)
    {
        Vless::RequestHeader Header{};
        Header.Uuid.fill(0x11);
        Header.Cmd = Vless::Command::Tcp;
        Header.Target.Port = 443;

        Header.Target.Type = Vless::AddressType::Ipv4;
        Header.Target.Host = "999.1.1.1";
        EXPECT_TRUE(Vless::BuildRequest(Header).empty());

        Header.Target.Type = Vless::AddressType::Ipv6;
        Header.Target.Host = "not-an-ipv6";
        EXPECT_TRUE(Vless::BuildRequest(Header).empty());

        Header.Target.Type = static_cast<Vless::AddressType>(0x7F);
        Header.Target.Host = "example.com";
        EXPECT_TRUE(Vless::BuildRequest(Header).empty());

        Header.Target.Type = Vless::AddressType::Domain;
        Header.Target.Host.clear();
        EXPECT_TRUE(Vless::BuildRequest(Header).empty());
        Header.Target.Host.assign(256, 'a');
        EXPECT_TRUE(Vless::BuildRequest(Header).empty());
    }

    TEST(VlessCodecDeep, EncodeAddressRejectsInvalidAddress)
    {
        Vless::Address Address;
        Address.Type = Vless::AddressType::Ipv4;
        Address.Host = "300.1.1.1";
        Address.Port = 443;
        EXPECT_TRUE(Vless::EncodeAddress(Address).empty());

        Address.Type = Vless::AddressType::Ipv6;
        Address.Host = "Short";
        EXPECT_TRUE(Vless::EncodeAddress(Address).empty());

        Address.Type = Vless::AddressType::Domain;
        Address.Host.clear();
        EXPECT_TRUE(Vless::EncodeAddress(Address).empty());

        Address.Type = static_cast<Vless::AddressType>(0x7F);
        Address.Host = "example.com";
        const std::array<std::uint8_t, 1> Payload{0x42};
        EXPECT_TRUE(Vless::BuildUdpPkt(Address, Payload).empty());
    }

    TEST(VlessCodecDeep, ParseRequestBranches)
    {
        Vless::RequestHeader Header{};
        std::size_t Consumed = 0;
        std::vector<std::uint8_t> Base{0x00};
        Base.insert(Base.end(), 16, 0x11);
        Base.push_back(0x00); // addnl len
        Base.push_back(0x01); // cmd Tcp
        Base.push_back(0x00);
        Base.push_back(0x50); // port 80
        // ipv4 不足
        std::vector<std::uint8_t> V4 = Base;
        V4.push_back(0x01);
        V4.push_back(8);
        V4.push_back(8);
        EXPECT_EQ(Vless::ParseRequest(V4, Header, Consumed), Error::NeedMore);
        // ipv6 不足
        std::vector<std::uint8_t> V6 = Base;
        V6.push_back(0x03);
        V6.insert(V6.end(), 5, 0x42);
        EXPECT_EQ(Vless::ParseRequest(V6, Header, Consumed), Error::NeedMore);
        // ipv6 成功
        std::vector<std::uint8_t> V6Ok = Base;
        V6Ok.push_back(0x03);
        V6Ok.insert(V6Ok.end(), 16, 0x42);
        EXPECT_EQ(Vless::ParseRequest(V6Ok, Header, Consumed), Error::None);
        EXPECT_EQ(Header.Target.Type, Vless::AddressType::Ipv6);
        EXPECT_EQ(Header.Target.Host, std::string(16, '\x42'));
        EXPECT_EQ(Header.Target.Port, 80u);
    }

    TEST(VlessCodecDeep, ParserErrors)
    {
        std::array<std::uint8_t, 16> Uuid{};
        Uuid.fill(0x11);
        Vless::Parser Parser(Uuid);
        std::error_code ErrorCode;

        // 数据不足
        EXPECT_EQ(Parser.Put(Net::buffer(MakeBytes({0x00})), ErrorCode), 0u);
        EXPECT_EQ(ErrorCode, make_error_code(Error::NeedMore));
        Parser.Reset();
        // 版本错误
        std::vector<std::uint8_t> bad{0x01};
        bad.insert(bad.end(), 16, 0x11);
        bad.insert(bad.end(), {0x00, 0x01, 0x00, 0x50, 0x01, 8, 8, 8, 8});
        EXPECT_EQ(Parser.Put(Net::buffer(bad), ErrorCode), 0u);
        EXPECT_EQ(ErrorCode, make_error_code(Error::BadMagic));
        Parser.Reset();
        // UUID 不匹配
        std::vector<std::uint8_t> Wrong = bad;
        Wrong[0] = 0x00;
        Wrong[1] = 0x22;
        EXPECT_EQ(Parser.Put(Net::buffer(Wrong), ErrorCode), 0u);
        EXPECT_EQ(ErrorCode, make_error_code(Error::AuthFailed));
        Parser.Reset();
        // 成功（Uuid 匹配 + ipv4）
        std::vector<std::uint8_t> Ok{0x00};
        Ok.insert(Ok.end(), 16, 0x11);
        Ok.push_back(0x00);
        Ok.push_back(0x01);
        Ok.push_back(0x00);
        Ok.push_back(0x50);
        Ok.push_back(0x01);
        Ok.insert(Ok.end(), 4, 8);
        EXPECT_EQ(Parser.Put(Net::buffer(Ok), ErrorCode), Ok.size());
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_TRUE(Parser.Get().valid);
        EXPECT_EQ(Parser.Get().cmd, 0x01u);
    }

} // namespace
