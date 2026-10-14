/**
 * @file Ss2022DatagramErrorTest.cpp
 * @brief Shadowsocks 2022 数据报错误矩阵行为契约。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Shadowsocks2022 = Preview::Shadowsocks2022;
    using Preview::AsBytes;
    using Preview::AsU8Span;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::PreviewMockTransport;
    using Preview::Transmission;
    using Datagram = Shadowsocks2022::Dgram<>;
    using SharedDatagram = std::shared_ptr<Datagram>;
    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    struct RootCompletion final
    {
        std::exception_ptr Failure;
    };

    auto CompleteRoot(
        RootCompletion &State,
        std::exception_ptr Failure) -> void
    {
        if (!State.Failure)
        {
            State.Failure = std::move(Failure);
        }
    }

    /** @brief 驱动根协程直至真实完成，并保留首个异常。 */
    auto RunCoroutine(
        Net::io_context &IoContext,
        Net::awaitable<void> Operation) -> void
    {
        RootCompletion State;
        auto Completion = [&State](std::exception_ptr Failure)
        { CompleteRoot(State, std::move(Failure)); };
        IoContext.restart();
        Net::co_spawn(IoContext, std::move(Operation), std::move(Completion));
        IoContext.run();
        if (State.Failure)
        {
            std::rethrow_exception(State.Failure);
        }
    }

    /** @brief 关闭数据报 owner，确保断言失败或异常退出也释放底层传输。 */
    struct DatagramCleanup final
    {
        SharedDatagram Datagram;

        ~DatagramCleanup()
        {
            if (Datagram)
            {
                Datagram->Close();
            }
        }
    };

    /// dgram 错误矩阵使用有限注入流，耗尽后按旧桩契约显式返回 EOF。
    auto MakeMock(Net::any_io_executor Executor)
        -> std::shared_ptr<PreviewMockTransport>
    {
        auto Mock = std::make_shared<PreviewMockTransport>(Executor);
        Mock->EofOnDrain = true;
        Mock->TransportKind = Transmission::Type::Udp;
        return Mock;
    }

    /// 构造 Shadowsocks 2022 目标地址。
    auto MakeShadowsocks2022Address() -> Shadowsocks2022::Address
    {
        Shadowsocks2022::Address Address{};
        Address.Type = Shadowsocks2022::AddressType::Ipv4;
        Address.Host = "1.2.3.4";
        Address.Port = 80;
        return Address;
    }

    /// 构造 SS2022 UDP 会话密钥（16 字节）。
    auto MakeShadowsocks2022Key() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Key{};
        for (std::size_t Index = 0; Index < Key.size(); ++Index)
        {
            Key[Index] = static_cast<std::uint8_t>(0xA0 + Index);
        }
        return Key;
    }

    struct DatagramPacketRequest final
    {
        std::array<std::uint8_t, 16> Key;
        std::uint8_t Type;
        std::vector<std::uint8_t> Address;
    };

    auto MakeShadowsocks2022Packet(DatagramPacketRequest Request)
        -> std::vector<std::uint8_t>
    {
        std::array<std::uint8_t, 16> SeparatePlain{};
        std::copy_n(Request.Key.begin(), 8, SeparatePlain.begin());
        SeparatePlain.back() = 1;
        const auto Separate = Shadowsocks2022::detail::CryptSeparate(
            Request.Key,
            std::span<const std::uint8_t, Shadowsocks2022::SeparateHdrLen>(
                SeparatePlain),
            true);
        if (!Separate)
        {
            return {};
        }
        const auto SessionId = std::span<const std::uint8_t>(
            SeparatePlain.data(), Shadowsocks2022::SessionIdLen);
        const auto Subkey = Shadowsocks2022::SessionKey(
            Request.Key, SessionId, Shadowsocks2022::AeadKeyLen);
        std::array<std::uint8_t, 12> Nonce{};
        std::memcpy(
            Nonce.data(),
            SeparatePlain.data() + Shadowsocks2022::SessionIdLen / 2,
            Shadowsocks2022::SessionIdLen / 2);
        std::memcpy(
            Nonce.data() + Shadowsocks2022::SessionIdLen / 2,
            SeparatePlain.data() + Shadowsocks2022::SessionIdLen,
            Shadowsocks2022::PacketIdLen);
        std::vector<std::uint8_t> Plain{Request.Type};
        Plain.insert(Plain.end(), 8, 0);
        Plain.insert(Plain.end(), Request.Address.begin(), Request.Address.end());
        Plain.insert(Plain.end(), {0, 0});
        const auto Body = Shadowsocks2022::detail::UdpSeal(
            Shadowsocks2022::detail::UdpSealInput{Subkey, Nonce, Plain, {}});
        if (Body.empty())
        {
            return {};
        }
        std::vector<std::uint8_t> Packet(Separate->begin(), Separate->end());
        Packet.insert(Packet.end(), Body.begin(), Body.end());
        return Packet;
    }

    struct DatagramOperation final
    {
        bool Send{false};
        bool ExpectEmptyPayload{false};
    };

    struct DatagramCase final
    {
        std::vector<std::uint8_t> Wire;
        Error Expected;
        DatagramOperation Operation;
    };

    struct DatagramFaults final
    {
        bool FailRead{false};
        bool FailWrite{false};
    };

    struct DatagramErrorRequest final
    {
        Net::io_context &IoContext;
        DatagramCase Case;
        DatagramFaults Faults;
    };

    auto RunDatagramError(DatagramErrorRequest Request) -> Net::awaitable<void>
    {
        auto Raw = MakeMock(Request.IoContext.get_executor());
        Raw->ToRead = std::move(Request.Case.Wire);
        Raw->FailNextRead = Request.Faults.FailRead;
        Raw->FailNextWrite = Request.Faults.FailWrite;
        auto DatagramValue = std::make_shared<Datagram>(
            Raw, MakeShadowsocks2022Key());
        DatagramCleanup Cleanup{DatagramValue};
        if (Request.Case.Operation.Send)
        {
            const std::string Payload = "x";
            const auto ErrorValue = co_await DatagramValue->AsyncSendTo(
                MakeShadowsocks2022Address(), AsU8Span(Payload));
            EXPECT_EQ(ErrorValue, Request.Case.Expected);
            co_return;
        }
        Shadowsocks2022::Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ErrorValue = co_await DatagramValue->AsyncReceiveFrom(
            Source, Payload);
        EXPECT_EQ(ErrorValue, Request.Case.Expected);
        if (Request.Case.Operation.ExpectEmptyPayload)
        {
            EXPECT_TRUE(Payload.empty());
        }
    }

    auto RunSendPartialWrite(const SharedDatagram &DatagramValue)
        -> Net::awaitable<void>
    {
        DatagramCleanup Cleanup{DatagramValue};
        const auto ErrorValue = co_await DatagramValue->AsyncSendTo(
            MakeShadowsocks2022Address(), AsU8Span(std::string_view{"x"}));
        EXPECT_EQ(ErrorValue, Error::IoError);
    }

    auto RunClosedState(const SharedDatagram &DatagramValue)
        -> Net::awaitable<void>
    {
        DatagramCleanup Cleanup{DatagramValue};
        const std::string Payload = "x";
        EXPECT_EQ(
            co_await DatagramValue->AsyncSendTo(
                MakeShadowsocks2022Address(), AsU8Span(Payload)),
            Error::NotOpen);
        Shadowsocks2022::Address Source;
        std::vector<std::uint8_t> Received;
        EXPECT_EQ(
            co_await DatagramValue->AsyncReceiveFrom(Source, Received),
            Error::UnexpectedEof);
    }
} // namespace

TEST(Ss2022DgramErr, SendWriteFail)
{
    Net::io_context IoContext;
    RunCoroutine(
        IoContext,
        RunDatagramError(DatagramErrorRequest{
            IoContext,
            DatagramCase{{}, Error::IoError, DatagramOperation{true, false}},
            DatagramFaults{false, true}}));
}

TEST(Ss2022DgramErr, SendPartialWrite)
{
    Net::io_context IoContext;
    auto Raw = MakeMock(IoContext.get_executor());
    Raw->MaxWrite = 8;
    auto DatagramValue = std::make_shared<Datagram>(
        Raw, MakeShadowsocks2022Key());
    RunCoroutine(IoContext, RunSendPartialWrite(DatagramValue));
}

TEST(Ss2022DgramErr, ReceiveIoError)
{
    Net::io_context IoContext;
    RunCoroutine(
        IoContext,
        RunDatagramError(DatagramErrorRequest{
            IoContext,
            DatagramCase{{}, Error::IoError, DatagramOperation{}},
            DatagramFaults{true, false}}));
}

TEST(Ss2022DgramErr, ReceiveEof)
{
    Net::io_context IoContext;
    RunCoroutine(
        IoContext,
        RunDatagramError(DatagramErrorRequest{
            IoContext,
            DatagramCase{{}, Error::UnexpectedEof, DatagramOperation{}},
            DatagramFaults{false, false}}));
}

TEST(Ss2022DgramErr, ReceiveTooShort)
{
    Net::io_context IoContext;
    RunCoroutine(
        IoContext,
        RunDatagramError(DatagramErrorRequest{
            IoContext,
            DatagramCase{
                {0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
                Error::BadLength,
                DatagramOperation{}},
            DatagramFaults{false, false}}));
}

TEST(Ss2022DgramErr, ReceiveBadSessionId)
{
    Net::io_context IoContext;
    auto Key = MakeShadowsocks2022Key();
    auto Packet = MakeShadowsocks2022Packet(
        DatagramPacketRequest{Key, 0x01, {}});
    Packet[0] ^= 0xFF;
    RunCoroutine(
        IoContext,
        RunDatagramError(DatagramErrorRequest{
            IoContext,
            DatagramCase{
                std::move(Packet), Error::BadAuth, DatagramOperation{}},
            DatagramFaults{false, false}}));
}

TEST(Ss2022DgramErr, ReceiveBadType)
{
    Net::io_context IoContext;
    const auto Key = MakeShadowsocks2022Key();
    RunCoroutine(
        IoContext,
        RunDatagramError(DatagramErrorRequest{
            IoContext,
            DatagramCase{
                MakeShadowsocks2022Packet(DatagramPacketRequest{Key, 0x02, {}}),
                Error::BadMessage,
                DatagramOperation{}},
            DatagramFaults{false, false}}));
}

TEST(Ss2022DgramErr, ReceiveDomainTruncated)
{
    Net::io_context IoContext;
    const auto Key = MakeShadowsocks2022Key();
    RunCoroutine(
        IoContext,
        RunDatagramError(DatagramErrorRequest{
            IoContext,
            DatagramCase{
                MakeShadowsocks2022Packet(
                    DatagramPacketRequest{Key, 0x00, {0x03, 0xFF}}),
                Error::BadMessage,
                DatagramOperation{}},
            DatagramFaults{false, false}}));
}

TEST(Ss2022DgramErr, ClosedStateOperations)
{
    Net::io_context IoContext;
    auto DatagramValue = std::make_shared<Datagram>(
        MakeMock(IoContext.get_executor()), MakeShadowsocks2022Key());
    DatagramValue->Close();
    RunCoroutine(IoContext, RunClosedState(DatagramValue));
}
