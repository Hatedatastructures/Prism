/**
 * @file Hysteria2ConnErrorMatrix.cpp
 * @brief Hysteria2 Conn/Dgram 错误分支矩阵测试（覆盖率第 2 轮）
 * @details 针对 Hysteria2ConnSession 未覆盖的分支点逐项补齐：
 * 1. Conn：握手发送失败（认证帧 / TCP 帧）、握手各阶段 EOF、
 *    数据报发送 I/O 错误、数据报接收帧错误（EOF / 非法 ATYP /
 *    载荷 I/O 错误）、地址体截断、握手后对端关闭透传
 * 2. Dgram：发送 I/O 错误、接收各阶段 EOF（端口 / 载荷）、
 *    载荷 I/O 错误、地址体截断、透传写错误
 * @note 使用 ScriptedTransmission 桩注入读取/写入错误与截断数据，
 *      无需依赖对端行为即可覆盖全部错误分支。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/co_composed.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Detail/IoCompletion.hpp>
#include <Preview/Protocols/Hysteria2/Hysteria2.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Hysteria2 = Preview::Hysteria2;

    /// 运行协程直至完成（异常重抛）
    template <typename Awaitable>
    auto RunCoroutine(Net::io_context &IoContext, Awaitable Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Coroutine),
                      [&](std::exception_ptr ExceptionPointer)
                      {
                          Exception = ExceptionPointer;
                          IoContext.stop();
                      });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    /// 构造 hysteria2 目标地址
    auto MakeAddress(Hysteria2::AddressType Type, std::string Host, std::uint16_t Port)
        -> Hysteria2::Address
    {
        Hysteria2::Address AddressValue{};
        AddressValue.Type = Type;
        AddressValue.Host = std::move(Host);
        AddressValue.Port = Port;
        return AddressValue;
    }

    /// 可编程传输桩：注入读取数据、捕获写入、按需模拟读写错误与写入限额
    class ScriptedTransmission final : public Preview::Transmission
    {
    public:
        explicit ScriptedTransmission(Net::any_io_executor Executor)
            : Preview::Transmission(Executor), Executor_(std::move(Executor))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Udp;
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<ReadWork>(
                ReadInput{std::static_pointer_cast<ScriptedTransmission>(
                              Preview::Transmission::shared_from_this()),
                          Buffer},
                std::move(Handler));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<WriteWork>(
                WriteInput{std::static_pointer_cast<ScriptedTransmission>(
                               Preview::Transmission::shared_from_this()),
                           Buffer},
                std::move(Handler));
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(
                Executor_, std::move(Handler), Preview::IoResult{0, {}});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed = true;
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

        std::vector<std::uint8_t> ToRead;
        std::vector<std::uint8_t> Written;
        bool WriteFail{false};
        bool WriteThrow{false};
        std::size_t WriteLimit{std::numeric_limits<std::size_t>::max()};
        std::size_t WritesDone{0};
        std::size_t ReadFailAt{std::numeric_limits<std::size_t>::max()};
        std::size_t ReadsDone{0};
        bool OverreportRead{false};
        bool OverreportWrite{false};
        bool EofOnDrain{false};
        bool Closed{false};

    private:
        struct ReadInput final
        {
            std::shared_ptr<ScriptedTransmission> Owner;
            std::span<std::byte> Buffer;
        };
        struct WriteInput final
        {
            std::shared_ptr<ScriptedTransmission> Owner;
            std::span<const std::byte> Buffer;
        };
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadPartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Preview::IoResult)>(
                Net::co_composed<void(Preview::IoResult)>(Work{}, Executor()),
                Handler, std::move(Value));
        }
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer)
            -> Net::awaitable<Preview::IoResult>
        {
            co_await Net::post(Executor_, Net::use_awaitable);
            ++ReadsDone;
            if (ReadsDone >= ReadFailAt)
            {
                co_return Preview::IoResult{
                    0, Preview::Fault::FromNative(Preview::make_error_code(Preview::Error::IoError))};
            }
            if (OverreportRead)
            {
                co_return Preview::IoResult{Buffer.size() + 1, {}};
            }
            if (ReadPosition_ >= ToRead.size())
            {
                co_return Preview::IoResult{
                    0, EofOnDrain ? Preview::Fault::Failure{Preview::Fault::Code::Eof}
                                  : Preview::Fault::Failure{}};
            }
            const auto Count = std::min(Buffer.size(), ToRead.size() - ReadPosition_);
            std::memcpy(Buffer.data(), ToRead.data() + ReadPosition_, Count);
            ReadPosition_ += Count;
            co_return Preview::IoResult{Count, {}};
        }
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<Preview::IoResult>
        {
            if (WriteThrow)
            {
                throw std::runtime_error("Scripted write throw");
            }
            if (WriteFail || WritesDone >= WriteLimit)
            {
                co_return Preview::IoResult{
                    0, Preview::Fault::FromNative(Preview::make_error_code(Preview::Error::IoError))};
            }
            const auto *Source = reinterpret_cast<const std::uint8_t *>(Buffer.data());
            Written.insert(Written.end(), Source, Source + Buffer.size());
            ++WritesDone;
            if (OverreportWrite)
            {
                co_return Preview::IoResult{Buffer.size() + 1, {}};
            }
            co_return Preview::IoResult{Buffer.size(), {}};
        }

        Net::any_io_executor Executor_;
        std::size_t ReadPosition_{0};
    };

    struct WriteCase final
    {
        Net::io_context &IoContext;
        bool Fail{false};
        bool Throw{false};
        std::size_t Limit{std::numeric_limits<std::size_t>::max()};
        Hysteria2::Address Target;
        Preview::Error Expected{Preview::Error::IoError};
        bool CheckWritten{false};
    };

    auto RunWriteCase(WriteCase Request) -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<ScriptedTransmission>(
            Request.IoContext.get_executor());
        Raw->WriteFail = Request.Fail;
        Raw->WriteThrow = Request.Throw;
        Raw->WriteLimit = Request.Limit;
        auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");
        const auto ErrorValue = co_await Connection->WriteHandshake(Request.Target);
        EXPECT_EQ(ErrorValue, Request.Expected);
        if (Request.CheckWritten)
        {
            EXPECT_FALSE(Raw->Written.empty());
        }
    }

    struct ReadCase final
    {
        Net::io_context &IoContext;
        std::vector<std::uint8_t> Wire;
        Preview::Error Expected;
    };

    auto RunReadCase(ReadCase Request) -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<ScriptedTransmission>(
            Request.IoContext.get_executor());
        Raw->ToRead = std::move(Request.Wire);
        Raw->EofOnDrain = true;
        auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");
        auto [ErrorValue, MessageValue] = co_await Connection->ReadHandshake();
        EXPECT_EQ(ErrorValue, Request.Expected);
        (void)MessageValue;
    }

    enum class DatagramMode
    {
        Send,
        Receive
    };

    struct ConnDgramCase final
    {
        Net::io_context &IoContext;
        std::vector<std::uint8_t> Wire;
        Preview::Error Expected;
        DatagramMode Mode;
        bool Overreport{false};
        bool FailAfterHandshake{false};
        bool FailWrite{false};
    };

    auto RunConnDgramCase(ConnDgramCase Request) -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<ScriptedTransmission>(
            Request.IoContext.get_executor());
        Raw->ToRead = std::move(Request.Wire);
        Raw->OverreportRead = Request.Overreport;
        auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");
        const auto Target = MakeAddress(
            Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
        EXPECT_EQ(co_await Connection->WriteHandshake(Target),
                  Preview::Error::None);
        Raw->WriteFail = Request.FailWrite;
        if (Request.FailAfterHandshake)
        {
            Raw->ReadFailAt = Raw->ReadsDone + 1;
        }
        if (Request.Mode == DatagramMode::Send)
        {
            const std::string Text = "x";
            const auto Payload = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Text.data()), Text.size());
            EXPECT_EQ(co_await Connection->AsyncSendDatagram(Target, Payload),
                      Request.Expected);
            co_return;
        }
        Hysteria2::Address Source;
        std::vector<std::uint8_t> Payload;
        EXPECT_EQ(co_await Connection->AsyncReceiveDatagram(Source, Payload),
                  Request.Expected);
    }

    struct DgramCase final
    {
        Net::io_context &IoContext;
        std::vector<std::uint8_t> Wire;
        Preview::Error Expected;
        DatagramMode Mode;
        bool OverreportRead{false};
        bool OverreportWrite{false};
        bool FailRead{false};
        bool FailWrite{false};
        bool PassthroughWrite{false};
    };

    auto RunDgramCase(DgramCase Request) -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<ScriptedTransmission>(
            Request.IoContext.get_executor());
        Raw->ToRead = std::move(Request.Wire);
        Raw->OverreportRead = Request.OverreportRead;
        Raw->OverreportWrite = Request.OverreportWrite;
        Raw->ReadFailAt = Request.FailRead
                              ? 1
                              : std::numeric_limits<std::size_t>::max();
        Raw->WriteFail = Request.FailWrite;
        auto Datagram = std::make_shared<Hysteria2::Dgram<>>(Raw);
        if (Request.Mode == DatagramMode::Send)
        {
            const std::string Text = "x";
            if (Request.PassthroughWrite)
            {
                const auto Result = co_await Datagram->WriteSome(
                    std::as_bytes(std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(Text.data()), Text.size())));
                EXPECT_TRUE(Result.Failure.Failed());
                EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::IoError);
                co_return;
            }
            const auto Target = MakeAddress(
                Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
            const auto Payload = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Text.data()), Text.size());
            EXPECT_EQ(co_await Datagram->AsyncSendTo(Target, Payload),
                      Request.Expected);
            co_return;
        }
        Hysteria2::Address Source;
        std::vector<std::uint8_t> Payload;
        EXPECT_EQ(co_await Datagram->AsyncReceiveFrom(Source, Payload),
                  Request.Expected);
    }

    auto RunPassthrough(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto [ClientValue, ServerValue] =
            Preview::MakeMemoryPair(IoContext.get_executor());
        auto Stream = std::make_shared<Preview::MemoryStream>(std::move(ClientValue));
        auto ServerMemory = std::make_shared<Preview::MemoryStream>(std::move(ServerValue));
        auto Connection = std::make_shared<Hysteria2::Conn<>>(Stream, "pw");
        const auto Target = MakeAddress(
            Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
        EXPECT_EQ(co_await Connection->WriteHandshake(Target),
                  Preview::Error::None);
        EXPECT_TRUE(ServerMemory->Close());
        std::array<std::byte, 64> Buffer{};
        const auto ReadResult = co_await Connection->ReadSome(Buffer);
        EXPECT_EQ(ReadResult.Bytes, 0u);
        EXPECT_EQ(ReadResult.Failure.Code, Preview::Fault::Code::Eof);
        const auto WriteResult = co_await Connection->WriteSome(
            std::span<const std::byte>(Buffer.data(), 4));
        EXPECT_EQ(WriteResult.Bytes, 0u);
        EXPECT_EQ(WriteResult.Failure.Code, Preview::Fault::Code::ConnectionAborted);
    }

    TEST(Hysteria2ConnError, WriteHandshakeAuthSendFail)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunWriteCase(WriteCase{
            IoContext, true, false, std::numeric_limits<std::size_t>::max(),
            MakeAddress(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80),
            Preview::Error::IoError, false}));
    }

    TEST(Hysteria2ConnError, WriteHandshakeAuthSendThrow)
    {
        Net::io_context IoContext;
        EXPECT_THROW(RunCoroutine(IoContext, RunWriteCase(WriteCase{
            IoContext, false, true, std::numeric_limits<std::size_t>::max(),
            MakeAddress(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80),
            Preview::Error::IoError, false})), std::runtime_error);
    }

    TEST(Hysteria2ConnError, WriteHandshakeTcpFrameSendFail)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunWriteCase(WriteCase{
            IoContext, false, false, 1,
            MakeAddress(Hysteria2::AddressType::Domain, "example.com", 443),
            Preview::Error::IoError, true}));
    }

    TEST(Hysteria2ConnError, ReadHandshakeEofOnAuthHead)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunReadCase({IoContext, {}, Preview::Error::IoError}));
    }

    TEST(Hysteria2ConnError, ReadHandshakeEofOnAuthBody)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunReadCase({IoContext, {0x01, 0x10}, Preview::Error::IoError}));
    }

    TEST(Hysteria2ConnError, ReadHandshakeEofOnTargetAddress)
    {
        Net::io_context IoContext;
        const auto Auth = Hysteria2::MakeAuthRequest("pw");
        std::vector<std::uint8_t> Wire(Auth.begin(), Auth.end());
        Wire.insert(Wire.end(), {0x01, 0x01, 0xAA});
        RunCoroutine(IoContext, RunReadCase({IoContext, std::move(Wire), Preview::Error::IoError}));
    }

    TEST(Hysteria2ConnError, ReadHandshakeRejectsUnknownKindBeforeAddress)
    {
        Net::io_context IoContext;
        const auto Auth = Hysteria2::MakeAuthRequest("pw");
        const auto Target = MakeAddress(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
        const std::span<const std::uint8_t> EmptyPayload;
        auto Frame = Hysteria2::BuildTcp(Target, EmptyPayload);
        ASSERT_FALSE(Frame.empty());
        Frame[0] = 0x7F;
        std::vector<std::uint8_t> Wire(Auth.begin(), Auth.end());
        Wire.insert(Wire.end(), Frame.begin(), Frame.end());
        RunCoroutine(IoContext, RunReadCase({IoContext, std::move(Wire), Preview::Error::BadMessage}));
    }

    TEST(Hysteria2ConnError, ReadHandshakeBadAtypTargetFrame)
    {
        Net::io_context IoContext;
        const auto Auth = Hysteria2::MakeAuthRequest("pw");
        std::vector<std::uint8_t> Wire(Auth.begin(), Auth.end());
        Wire.insert(Wire.end(), {0x01, 0x99});
        RunCoroutine(IoContext, RunReadCase({IoContext, std::move(Wire), Preview::Error::BadMessage}));
    }

    TEST(Hysteria2ConnError, SendDatagramIoError)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunConnDgramCase({IoContext, {}, Preview::Error::IoError, DatagramMode::Send, false, false, true}));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramEofOnFrame)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunConnDgramCase({IoContext, {}, Preview::Error::UnexpectedEof, DatagramMode::Receive}));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramBadAtyp)
    {
        Net::io_context IoContext;
        std::vector<std::uint8_t> Wire{0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x99};
        RunCoroutine(IoContext, RunConnDgramCase({IoContext, std::move(Wire), Preview::Error::BadMessage, DatagramMode::Receive}));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramTruncatedIds)
    {
        Net::io_context IoContext;
        std::vector<std::uint8_t> Wire{0x02, 1, 2, 3};
        RunCoroutine(IoContext, RunConnDgramCase({IoContext, std::move(Wire), Preview::Error::NeedMore, DatagramMode::Receive}));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramTruncatedAtyp)
    {
        Net::io_context IoContext;
        std::vector<std::uint8_t> Wire{0x02, 0, 0, 0, 0, 0, 0, 0, 0};
        RunCoroutine(IoContext, RunConnDgramCase({IoContext, std::move(Wire), Preview::Error::NeedMore, DatagramMode::Receive}));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramTruncatedPort)
    {
        Net::io_context IoContext;
        std::vector<std::uint8_t> Wire{0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4};
        RunCoroutine(IoContext, RunConnDgramCase({IoContext, std::move(Wire), Preview::Error::NeedMore, DatagramMode::Receive}));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramPayloadIoError)
    {
        Net::io_context IoContext;
        std::vector<std::uint8_t> Wire{
            0x02, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50};
        RunCoroutine(IoContext, RunConnDgramCase({IoContext, std::move(Wire), Preview::Error::IoError, DatagramMode::Receive, false, true}));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramRejectsOverreportedRead)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunConnDgramCase({IoContext, {}, Preview::Error::BadLength, DatagramMode::Receive, true}));
    }

    TEST(Hysteria2ConnError, DgramRejectsOverreportedRead)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramCase({IoContext, {}, Preview::Error::BadLength, DatagramMode::Receive, true}));
    }

    TEST(Hysteria2DgramError, SendToRejectsOverreportedWrite)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramCase({IoContext, {}, Preview::Error::BadLength, DatagramMode::Send, false, true}));
    }

    TEST(Hysteria2ConnError, ReadHandshakeAddressBodyEof)
    {
        Net::io_context IoContext;
        const auto Auth = Hysteria2::MakeAuthRequest("pw");
        std::vector<std::uint8_t> Wire(Auth.begin(), Auth.end());
        Wire.insert(Wire.end(), {0x01, 0x02, 0x05, 'a', 'b'});
        RunCoroutine(IoContext, RunReadCase({IoContext, std::move(Wire), Preview::Error::IoError}));
    }

    TEST(Hysteria2ConnError, PassthroughPeerClosed)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunPassthrough(IoContext));
    }

    TEST(Hysteria2DgramError, SendToIoError)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramCase({IoContext, {}, Preview::Error::IoError, DatagramMode::Send,
                                               false, false, false, true}));
    }

    TEST(Hysteria2DgramError, ReceiveTruncatedPort)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramCase({
            IoContext, {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4},
            Preview::Error::NeedMore, DatagramMode::Receive}));
    }

    TEST(Hysteria2DgramError, ReceiveEmptyPayload)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramCase({
            IoContext, {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50},
            Preview::Error::None, DatagramMode::Receive}));
    }

    TEST(Hysteria2DgramError, ReceiveIoError)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramCase({
            IoContext, {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50},
            Preview::Error::IoError, DatagramMode::Receive, false, false, true}));
    }

    TEST(Hysteria2DgramError, ReceiveTruncatedAddressBody)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramCase({
            IoContext, {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x05, 'a', 'b'},
            Preview::Error::NeedMore, DatagramMode::Receive}));
    }

    TEST(Hysteria2DgramError, PassthroughWriteIoError)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramCase({
            IoContext, {}, Preview::Error::IoError, DatagramMode::Send,
            false, false, false, true, true}));
    }
} // namespace
