/**
 * @file TrojanDatagramErrorTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
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
#include <system_error>
#include <vector>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>
#include <Prism/Protocols/Trojan/Trojan.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Trojan = Prism::Trojan;
    using Prism::AsBytes;
    using Prism::AsU8Span;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using Prism::PrismMockTransport;
    using Prism::Transmission;
    using DatagramRunResult = Prism::Contract::Io::PacketTransferResult;

    auto DatagramStatus(const DatagramRunResult& Result) -> Prism::Fault::Code
    {
        return Result.Failure.Code;
    }

    auto FaultStatus(Error Value) -> Prism::Fault::Code
    {
        return Prism::Fault::ToCode(Prism::make_error_code(Value));
    }

    /// 运行协程直至完成（异常重抛）
    template <typename A>
    auto RunCoroutine(Net::io_context &IoContext, A Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Coroutine),
                      [&](std::exception_ptr ErrorValue)
                      {
                          Exception = ErrorValue;
                          IoContext.stop();
                      });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }
    /// dgram 错误矩阵使用有限注入流，耗尽后按旧桩契约显式返回 EOF。
    auto MakeMock(Net::any_io_executor Executor) -> std::shared_ptr<PrismMockTransport>
    {
        auto Mock = std::make_shared<PrismMockTransport>(Executor);
        Mock->EofOnDrain = true;
        Mock->TransportKind = Prism::Transmission::Type::Udp;
        return Mock;
    }
    /// 构造 trojan 目标地址
    auto MakeTrojanAddress() -> Trojan::Address
    {
        Trojan::Address Address{};
        Address.Type = Trojan::AddressType::Ipv4;
        Address.Host = "1.2.3.4";
        Address.Port = 80;
        return Address;
    }

    /** @brief 关闭 Dgram 并依次排空本层与底层活动。 */
    auto CloseAndDrainDatagram(
        std::shared_ptr<Trojan::Dgram<>> Datagram,
        std::shared_ptr<PrismMockTransport> RawTransport) -> Net::awaitable<void>
    {
        const auto Close = Datagram->Close();
        EXPECT_TRUE(Close);
        const auto DatagramActivity = Datagram->Activity();
        const auto DatagramDrain = co_await DatagramActivity->Drain();
        EXPECT_TRUE(DatagramDrain);
        EXPECT_TRUE(DatagramActivity->IsRetired());
        const auto RawActivity = RawTransport->Activity();
        const auto RawDrain = co_await RawActivity->Drain();
        EXPECT_TRUE(RawDrain);
        EXPECT_TRUE(RawTransport->IsClosed());
        EXPECT_TRUE(RawActivity->IsRetired());
    }

    /** @brief 验证 Trojan LEN/CRLF 头部截断映射为 BadMessage。 */
    auto RunReceiveLenHeadEof(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        // LEN(2) + CRLF(2) 头部缺失 → BadMessage
        auto RawTransport = MakeMock(IoContext.get_executor());
        RawTransport->ToRead = {0x01, 1, 2, 3, 4, 0x00, 0x50};
        auto Datagram = std::make_shared<Trojan::Dgram<>>(RawTransport);
        Trojan::Address Source;
        std::vector<std::uint8_t> Output;
        const auto ErrorCode = co_await Datagram->AsyncReceiveFrom(Source, Output);
        EXPECT_EQ(DatagramStatus(ErrorCode), Prism::Fault::Code::BadMessage);
    }

    /** @brief 验证 Trojan 非法 CRLF 魔数仍返回原有协议错误。 */
    auto RunReceiveBadCrlf(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        // CRLF 魔数非法 → bad_magic
        auto RawTransport = MakeMock(IoContext.get_executor());
        RawTransport->ToRead = {0x01, 1, 2, 3, 4, 0x00, 0x50, 0x00, 0x05, 'X', 'Y'};
        auto Datagram = std::make_shared<Trojan::Dgram<>>(RawTransport);
        Trojan::Address Source;
        std::vector<std::uint8_t> Output;
        const auto ErrorCode = co_await Datagram->AsyncReceiveFrom(Source, Output);
        EXPECT_EQ(DatagramStatus(ErrorCode), FaultStatus(Error::BadMagic));
    }

    /** @brief 验证 Trojan 声明长度大于实际载荷映射为 BadMessage。 */
    auto RunReceivePayloadTruncated(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        // LEN 声明 5，实际仅 2 字节载荷 → BadMessage
        auto RawTransport = MakeMock(IoContext.get_executor());
        RawTransport->ToRead = {0x01, 1, 2, 3, 4, 0x00, 0x50, 0x00, 0x05, '\r', '\n', 'h', 'e'};
        auto Datagram = std::make_shared<Trojan::Dgram<>>(RawTransport);
        Trojan::Address Source;
        std::vector<std::uint8_t> Output;
        const auto ErrorCode = co_await Datagram->AsyncReceiveFrom(Source, Output);
        EXPECT_EQ(DatagramStatus(ErrorCode), Prism::Fault::Code::BadMessage);
    }

    /** @brief 验证 Trojan 载荷读取注入失败仍返回原有 I/O 错误。 */
    auto RunReceivePayloadIoError(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto RawTransport = MakeMock(IoContext.get_executor());
        RawTransport->ToRead = {0x01, 1, 2, 3, 4, 0x00, 0x50, 0x00, 0x05, '\r', '\n'};
        RawTransport->ReadFailAt = 5; // 第 5 次读取 = 载荷读取
        auto Datagram = std::make_shared<Trojan::Dgram<>>(RawTransport);
        Trojan::Address Source;
        std::vector<std::uint8_t> Output;
        const auto ErrorCode = co_await Datagram->AsyncReceiveFrom(Source, Output);
        EXPECT_EQ(DatagramStatus(ErrorCode), FaultStatus(Error::IoError));
        co_await CloseAndDrainDatagram(Datagram, RawTransport);
    }

    /** @brief 验证部分写入后原生错误仍由 Trojan 数据报 API 保留。 */
    auto RunSendNativePartialFailure(
        Net::io_context &IoContext, std::error_code Native) -> Net::awaitable<void>
    {
        auto RawTransport = MakeMock(IoContext.get_executor());
        RawTransport->SetWriteError(Native);
        RawTransport->WriteErrorBytes = 1;
        auto Datagram = std::make_shared<Trojan::Dgram<>>(RawTransport);
        const std::string Payload = "partial-native";
        const auto Result = co_await Datagram->AsyncSendTo(
            MakeTrojanAddress(), AsU8Span(Payload));
        EXPECT_TRUE(Result.Failure.Failed());
        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Result.Failure.Native, Native);
        EXPECT_EQ(Result.PayloadBytes, 0U);
        EXPECT_EQ(Result.WireBytes, 1U);
        EXPECT_EQ(RawTransport->Written.size(), 1U);
        co_await CloseAndDrainDatagram(Datagram, RawTransport);
    }

    /** @brief 验证 overreport 的未确认字节不计入 Trojan wire 进度。 */
    auto RunSendOverreportedWrite(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto RawTransport = MakeMock(IoContext.get_executor());
        RawTransport->OverreportWrite = true;
        auto Datagram = std::make_shared<Trojan::Dgram<>>(RawTransport);
        const std::string Payload = "overreported";
        const auto Result = co_await Datagram->AsyncSendTo(
            MakeTrojanAddress(), AsU8Span(Payload));
        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::InvalidArgument);
        EXPECT_FALSE(Result.Failure.Native);
        EXPECT_EQ(Result.PayloadBytes, 0U);
        EXPECT_EQ(Result.WireBytes, 0U);
        EXPECT_TRUE(RawTransport->Written.empty());
        co_await CloseAndDrainDatagram(Datagram, RawTransport);
    }

    /** @brief 验证关闭后的 Trojan 数据报收发错误。 */
    auto RunClosedState(std::shared_ptr<PrismMockTransport> Raw) -> Net::awaitable<void>
    {
        auto Datagram = std::make_shared<Trojan::Dgram<>>(Raw);
        const auto Close = Datagram->Close();
        EXPECT_TRUE(Close);
        const std::string Payload = "x";
        const auto SendError = co_await Datagram->AsyncSendTo(
            MakeTrojanAddress(), AsU8Span(Payload));
        EXPECT_EQ(DatagramStatus(SendError), Prism::Fault::Code::Canceled);
        Trojan::Address Source;
        std::vector<std::uint8_t> Output;
        const auto ReceiveError = co_await Datagram->AsyncReceiveFrom(Source, Output);
        EXPECT_EQ(DatagramStatus(ReceiveError), Prism::Fault::Code::Canceled);
        const auto Drain = co_await Datagram->Activity()->Drain();
        EXPECT_TRUE(Drain);
        const auto RawActivity = Raw->Activity();
        const auto RawDrain = co_await RawActivity->Drain();
        EXPECT_TRUE(RawDrain);
        EXPECT_TRUE(RawActivity->IsRetired());
    }

} // namespace

TEST(TrojanDgramErr, SendWriteFail)
    {
        Net::io_context IoContext;

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     auto RawTransport = MakeMock(IoContext.get_executor());
                     RawTransport->FailNextWrite = true;
                     auto Datagram = std::make_shared<Trojan::Dgram<>>(RawTransport);
                     const std::string Payload = "x";
                     const auto ErrorCode = co_await Datagram->AsyncSendTo(MakeTrojanAddress(), AsU8Span(Payload));
                     EXPECT_EQ(DatagramStatus(ErrorCode), FaultStatus(Error::IoError));
                     co_await CloseAndDrainDatagram(Datagram, RawTransport);
                 });
    }

TEST(TrojanDgramErr, SendNativePartialFailure)
    {
        Net::io_context IoContext;
        const auto Native = std::make_error_code(std::errc::connection_reset);
        RunCoroutine(IoContext, RunSendNativePartialFailure(IoContext, Native));
    }

TEST(TrojanDgramErr, SendOverreportedWriteReportsNoWireBytes)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunSendOverreportedWrite(IoContext));
    }

TEST(TrojanDgramErr, ReceiveHeadEof)
    {
        Net::io_context IoContext;

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     auto RawTransport = MakeMock(IoContext.get_executor());
                     auto Datagram = std::make_shared<Trojan::Dgram<>>(RawTransport);
                     Trojan::Address Source;
                     std::vector<std::uint8_t> Output;
                     const auto ErrorCode = co_await Datagram->AsyncReceiveFrom(Source, Output);
                     EXPECT_EQ(DatagramStatus(ErrorCode), Prism::Fault::Code::Eof);
                 });
    }

TEST(TrojanDgramErr, ReceiveBadAtyp)
    {
        Net::io_context IoContext;

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     auto RawTransport = MakeMock(IoContext.get_executor());
                     RawTransport->ToRead = {0x99};
                     auto Datagram = std::make_shared<Trojan::Dgram<>>(RawTransport);
                     Trojan::Address Source;
                     std::vector<std::uint8_t> Output;
                     const auto ErrorCode = co_await Datagram->AsyncReceiveFrom(Source, Output);
                     EXPECT_EQ(DatagramStatus(ErrorCode), FaultStatus(Error::BadMessage));
                 });
    }

TEST(TrojanDgramErr, ReceiveDomainTruncated)
    {
        Net::io_context IoContext;

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     auto RawTransport = MakeMock(IoContext.get_executor());
                     RawTransport->ToRead = {0x03, 0x05, 'a', 'b'};
                     auto Datagram = std::make_shared<Trojan::Dgram<>>(RawTransport);
                     Trojan::Address Source;
                     std::vector<std::uint8_t> Output;
                     const auto ErrorCode = co_await Datagram->AsyncReceiveFrom(Source, Output);
                     EXPECT_EQ(DatagramStatus(ErrorCode), Prism::Fault::Code::BadMessage);
                 });
    }

TEST(TrojanDgramErr, ReceivePortEof)
    {
        Net::io_context IoContext;

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     auto RawTransport = MakeMock(IoContext.get_executor());
                     RawTransport->ToRead = {0x01, 1, 2, 3, 4};
                     auto Datagram = std::make_shared<Trojan::Dgram<>>(RawTransport);
                     Trojan::Address Source;
                     std::vector<std::uint8_t> Output;
                     const auto ErrorCode = co_await Datagram->AsyncReceiveFrom(Source, Output);
                     EXPECT_EQ(DatagramStatus(ErrorCode), Prism::Fault::Code::BadMessage);
                 });
    }

TEST(TrojanDgramErr, ReceiveLenHeadEof)
    {
        Net::io_context IoContext;

        RunCoroutine(IoContext, RunReceiveLenHeadEof(IoContext));
    }

TEST(TrojanDgramErr, ReceiveBadCrlf)
    {
        Net::io_context IoContext;

        RunCoroutine(IoContext, RunReceiveBadCrlf(IoContext));
    }

TEST(TrojanDgramErr, ReceivePayloadTruncated)
    {
        Net::io_context IoContext;

        RunCoroutine(IoContext, RunReceivePayloadTruncated(IoContext));
    }

TEST(TrojanDgramErr, ReceivePayloadIoError)
    {
        Net::io_context IoContext;

        RunCoroutine(IoContext, RunReceivePayloadIoError(IoContext));
    }

TEST(TrojanDgramErr, ClosedStateOperations)
    {
        Net::io_context IoContext;

        RunCoroutine(IoContext, RunClosedState(MakeMock(IoContext.get_executor())));
    }
