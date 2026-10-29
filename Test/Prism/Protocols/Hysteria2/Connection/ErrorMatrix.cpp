/**
 * @file ErrorMatrix.cpp
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
#include <boost/asio/as_tuple.hpp>
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
#include <optional>
#include <span>
#include <string>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Hysteria2/Hysteria2.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Hysteria2 = Prism::Hysteria2;

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

    /** @brief 关闭测试载体并等待它自己的 I/O 预约退出。 */
    auto CloseAndDrain(Prism::Transmission &Carrier) -> Net::awaitable<void>
    {
        const auto Closed = Carrier.Close();
        EXPECT_TRUE(Closed);
        const auto Activity = Carrier.Activity();
        EXPECT_TRUE(Activity != nullptr);
        if (Activity)
        {
            const auto Drained = co_await Activity->Drain();
            EXPECT_TRUE(Drained);
        }
    }

    /** @brief 等待已由协议载体关闭的底层测试传输退出。 */
    auto DrainActivity(Prism::Transmission &Carrier) -> Net::awaitable<void>
    {
        const auto Activity = Carrier.Activity();
        EXPECT_TRUE(Activity != nullptr);
        if (Activity)
        {
            const auto Drained = co_await Activity->Drain();
            EXPECT_TRUE(Drained);
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
    class ScriptedTransmission final : public Prism::Transmission
    {
    public:
        explicit ScriptedTransmission(Net::any_io_executor Executor)
            : Prism::Transmission(Executor), Executor_(std::move(Executor))
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
                              Prism::Transmission::shared_from_this()),
                          Buffer},
                std::move(Handler));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<WriteWork>(
                WriteInput{std::static_pointer_cast<ScriptedTransmission>(
                               Prism::Transmission::shared_from_this()),
                           Buffer},
                std::move(Handler));
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), Prism::IoResult{0, {}});
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
        bool ReadFailureWithBytesAtEnd{false};
        std::size_t ReadsDone{0};
        bool OverreportRead{false};
        bool OverreportWrite{false};
        bool EofOnDrain{false};
        bool Closed{false};

        [[nodiscard]] auto ReadPosition() const noexcept -> std::size_t
        {
            return ReadPosition_;
        }

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
                Prism::Transmission::ConfigureIo(Operation);
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
                Prism::Transmission::ConfigureIo(Operation);
                auto [Exception, Result] = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer),
                    Net::as_tuple(Net::deferred));
                if (Exception)
                {
                    co_return std::tuple{Prism::IoResult{
                        0, Prism::Fault::FromNative(
                            Prism::make_error_code(Prism::Error::IoError))}};
                }
                co_return std::tuple{Result};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()),
                Handler, std::move(Value));
        }
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            co_await Net::post(Executor_, Net::use_awaitable);
            ++ReadsDone;
            if (ReadsDone >= ReadFailAt)
            {
                co_return Prism::IoResult{
                    0, Prism::Fault::FromNative(Prism::make_error_code(Prism::Error::IoError))};
            }
            if (OverreportRead)
            {
                co_return Prism::IoResult{Buffer.size() + 1, {}};
            }
            if (ReadPosition_ >= ToRead.size())
            {
                co_return Prism::IoResult{
                    0, EofOnDrain ? Prism::Fault::Failure{Prism::Fault::Code::Eof}
                                  : Prism::Fault::Failure{}};
            }
            const auto Count = std::min(Buffer.size(), ToRead.size() - ReadPosition_);
            std::memcpy(Buffer.data(), ToRead.data() + ReadPosition_, Count);
            ReadPosition_ += Count;
            if (ReadFailureWithBytesAtEnd && ReadPosition_ == ToRead.size())
            {
                ReadFailureWithBytesAtEnd = false;
                co_return Prism::IoResult{
                    Count, Prism::Fault::FromNative(
                        Prism::make_error_code(Prism::Error::IoError))};
            }
            co_return Prism::IoResult{Count, {}};
        }
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            if (WriteThrow)
            {
                throw std::runtime_error("Scripted write throw");
            }
            if (WriteFail || WritesDone >= WriteLimit)
            {
                co_return Prism::IoResult{
                    0, Prism::Fault::FromNative(Prism::make_error_code(Prism::Error::IoError))};
            }
            const auto *Source = reinterpret_cast<const std::uint8_t *>(Buffer.data());
            Written.insert(Written.end(), Source, Source + Buffer.size());
            ++WritesDone;
            if (OverreportWrite)
            {
                co_return Prism::IoResult{Buffer.size() + 1, {}};
            }
            co_return Prism::IoResult{Buffer.size(), {}};
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
        Prism::Error Expected{Prism::Error::IoError};
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
        Prism::Error Expected;
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
        Prism::Error Expected;
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
                  Prism::Error::None);
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
        Prism::Error Expected;
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
                EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::IoError);
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
            Prism::MakeMemoryPair(IoContext.get_executor());
        auto Stream = std::make_shared<Prism::MemoryStream>(std::move(ClientValue));
        auto ServerMemory = std::make_shared<Prism::MemoryStream>(std::move(ServerValue));
        auto Connection = std::make_shared<Hysteria2::Conn<>>(Stream, "pw");
        const auto Target = MakeAddress(
            Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
        EXPECT_EQ(co_await Connection->WriteHandshake(Target),
                  Prism::Error::None);
        EXPECT_TRUE(ServerMemory->Close());
        std::array<std::byte, 64> Buffer{};
        const auto ReadResult = co_await Connection->ReadSome(Buffer);
        EXPECT_EQ(ReadResult.Bytes, 0u);
        EXPECT_EQ(ReadResult.Failure.Code, Prism::Fault::Code::Eof);
        const auto WriteResult = co_await Connection->WriteSome(
            std::span<const std::byte>(Buffer.data(), 4));
        EXPECT_EQ(WriteResult.Bytes, 0u);
        EXPECT_EQ(WriteResult.Failure.Code, Prism::Fault::Code::ConnectionAborted);
    }

    TEST(Hysteria2ConnError, WriteHandshakeAuthSendFail)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunWriteCase(WriteCase{
            IoContext, true, false, std::numeric_limits<std::size_t>::max(),
            MakeAddress(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80),
            Prism::Error::IoError, false}));
    }

    TEST(Hysteria2ConnError, WriteHandshakeAuthSendThrow)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunWriteCase(WriteCase{
            IoContext, false, true, std::numeric_limits<std::size_t>::max(),
            MakeAddress(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80),
            Prism::Error::IoError, false}));
    }

    TEST(Hysteria2ConnError, WriteHandshakeTcpFrameSendFail)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunWriteCase(WriteCase{
            IoContext, false, false, 1,
            MakeAddress(Hysteria2::AddressType::Domain, "example.com", 443),
            Prism::Error::IoError, true}));
    }

    TEST(Hysteria2ConnError, ReadHandshakeEofOnAuthHead)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunReadCase({IoContext, {}, Prism::Error::IoError}));
    }

    TEST(Hysteria2ConnError, ReadHandshakeEofOnAuthBody)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunReadCase({IoContext, {0x01, 0x10}, Prism::Error::IoError}));
    }

    TEST(Hysteria2ConnError, ReadHandshakeEofOnTargetAddress)
    {
        Net::io_context IoContext;
        const auto Auth = Hysteria2::MakeAuthRequest("pw");
        std::vector<std::uint8_t> Wire(Auth.begin(), Auth.end());
        Wire.insert(Wire.end(), {0x01, 0x01, 0xAA});
        RunCoroutine(IoContext, RunReadCase({IoContext, std::move(Wire), Prism::Error::UnexpectedEof}));
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
        RunCoroutine(IoContext, RunReadCase({IoContext, std::move(Wire), Prism::Error::BadMessage}));
    }

    TEST(Hysteria2ConnError, ReadHandshakeBadAtypTargetFrame)
    {
        Net::io_context IoContext;
        const auto Auth = Hysteria2::MakeAuthRequest("pw");
        std::vector<std::uint8_t> Wire(Auth.begin(), Auth.end());
        Wire.insert(Wire.end(), {0x01, 0x99});
        RunCoroutine(IoContext, RunReadCase({IoContext, std::move(Wire), Prism::Error::BadMessage}));
    }

    TEST(Hysteria2ConnError, SendDatagramIoError)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunConnDgramCase({IoContext, {}, Prism::Error::IoError, DatagramMode::Send, false, false, true}));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramEofOnFrame)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunConnDgramCase({IoContext, {}, Prism::Error::UnexpectedEof, DatagramMode::Receive}));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramBadAtyp)
    {
        Net::io_context IoContext;
        std::vector<std::uint8_t> Wire{0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x99};
        RunCoroutine(IoContext, RunConnDgramCase({IoContext, std::move(Wire), Prism::Error::BadMessage, DatagramMode::Receive}));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramTruncatedIds)
    {
        Net::io_context IoContext;
        std::vector<std::uint8_t> Wire{0x02, 1, 2, 3};
        RunCoroutine(IoContext, RunConnDgramCase({IoContext, std::move(Wire), Prism::Error::NeedMore, DatagramMode::Receive}));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramTruncatedAtyp)
    {
        Net::io_context IoContext;
        std::vector<std::uint8_t> Wire{0x02, 0, 0, 0, 0, 0, 0, 0, 0};
        RunCoroutine(IoContext, RunConnDgramCase({IoContext, std::move(Wire), Prism::Error::NeedMore, DatagramMode::Receive}));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramTruncatedPort)
    {
        Net::io_context IoContext;
        std::vector<std::uint8_t> Wire{0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4};
        RunCoroutine(IoContext, RunConnDgramCase({IoContext, std::move(Wire), Prism::Error::NeedMore, DatagramMode::Receive}));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramPayloadIoError)
    {
        Net::io_context IoContext;
        std::vector<std::uint8_t> Wire{
            0x02, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50};
        RunCoroutine(IoContext, RunConnDgramCase({IoContext, std::move(Wire), Prism::Error::IoError, DatagramMode::Receive, false, true}));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramRejectsOverreportedRead)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunConnDgramCase({IoContext, {}, Prism::Error::BadLength, DatagramMode::Receive, true}));
    }

    TEST(Hysteria2ConnError, DgramRejectsOverreportedRead)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramCase({IoContext, {}, Prism::Error::BadLength, DatagramMode::Receive, true}));
    }

    TEST(Hysteria2DgramError, SendToRejectsOverreportedWrite)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramCase({IoContext, {}, Prism::Error::BadLength, DatagramMode::Send, false, true}));
    }

    TEST(Hysteria2ConnError, ReadHandshakeAddressBodyEof)
    {
        Net::io_context IoContext;
        const auto Auth = Hysteria2::MakeAuthRequest("pw");
        std::vector<std::uint8_t> Wire(Auth.begin(), Auth.end());
        Wire.insert(Wire.end(), {0x01, 0x02, 0x05, 'a', 'b'});
        RunCoroutine(IoContext, RunReadCase({IoContext, std::move(Wire), Prism::Error::UnexpectedEof}));
    }

    TEST(Hysteria2ConnError, PassthroughPeerClosed)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunPassthrough(IoContext));
    }

    TEST(Hysteria2DgramError, SendToIoError)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramCase({IoContext, {}, Prism::Error::IoError, DatagramMode::Send,
                                               false, false, false, true}));
    }

    TEST(Hysteria2DgramError, ReceiveTruncatedPort)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramCase({
            IoContext, {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4},
            Prism::Error::NeedMore, DatagramMode::Receive}));
    }

    TEST(Hysteria2DgramError, ReceiveEmptyPayload)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramCase({
            IoContext, {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50},
            Prism::Error::None, DatagramMode::Receive}));
    }

    TEST(Hysteria2DgramError, ReceiveIoError)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramCase({
            IoContext, {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50},
            Prism::Error::IoError, DatagramMode::Receive, false, false, true}));
    }

    TEST(Hysteria2DgramError, ReceiveTruncatedAddressBody)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramCase({
            IoContext, {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x05, 'a', 'b'},
            Prism::Error::NeedMore, DatagramMode::Receive}));
    }

    TEST(Hysteria2DgramError, PassthroughWriteIoError)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunDgramCase({
            IoContext, {}, Prism::Error::IoError, DatagramMode::Send,
            false, false, false, true, true}));
    }

    /** @brief 帧载荷完整到达后延后同次读取的终态。 */
    auto RunReadFrameRetainsUdpPayloadWithTerminal(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        const auto Target = MakeAddress(
            Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
        const std::string Payload{"abc"};
        const auto PayloadBytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(Payload.data()), Payload.size());
        const auto Wire = Hysteria2::BuildUdp(
            Hysteria2::UdpFrameInput{7U, 11U, &Target, PayloadBytes});
        auto Raw = std::make_shared<ScriptedTransmission>(std::move(Executor));
        Raw->ToRead = Wire;
        Raw->ReadFailureWithBytesAtEnd = true;
        Hysteria2::Message MessageValue;
        std::optional<Prism::Fault::Failure> PendingTerminal;

        const auto ErrorValue = co_await Hysteria2::Detail::ReadFrame(
            Raw, MessageValue, PendingTerminal);
        EXPECT_EQ(ErrorValue, Prism::Error::None);
        EXPECT_EQ(MessageValue.payload, Payload);
        EXPECT_TRUE(PendingTerminal.has_value());
        const auto Reads = Raw->ReadsDone;
        std::array<std::uint8_t, 1> NextField{};
        EXPECT_TRUE(co_await Hysteria2::Detail::ReadExact(
            Raw, NextField, PendingTerminal));
        EXPECT_EQ(Raw->ReadsDone, Reads);
        EXPECT_EQ(Raw->ReadPosition(), Wire.size());
        co_await CloseAndDrain(*Raw);
    }

    /** @brief 精确字段保留部分字节并在终态后停止重读。 */
    auto RunReadExactRetainsCompletedPrefixAndStopsOnTerminal(
        Net::any_io_executor Executor) -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<ScriptedTransmission>(std::move(Executor));
        Raw->ToRead = {0xD1, 0xD2};
        Raw->ReadFailureWithBytesAtEnd = true;
        std::array<std::uint8_t, 4> Destination{};
        std::optional<Prism::Fault::Failure> PendingTerminal;

        EXPECT_TRUE(co_await Hysteria2::Detail::ReadExact(
            Raw, Destination, PendingTerminal));
        EXPECT_EQ(Raw->ReadsDone, 1U);
        co_await CloseAndDrain(*Raw);
        EXPECT_EQ(Destination[0], 0xD1);
        EXPECT_EQ(Destination[1], 0xD2);
        EXPECT_TRUE(PendingTerminal.has_value());
        EXPECT_TRUE(co_await Hysteria2::Detail::ReadExact(
            Raw, Destination, PendingTerminal));
        EXPECT_EQ(Raw->ReadsDone, 1U);
    }

    /** @brief Conn 数据报保留本次读取中已交付的完整 payload。 */
    auto RunReceiveDatagramRetainsPayloadWithTerminal(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        const auto Target = MakeAddress(
            Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
        const std::vector<std::uint8_t> Payload{0xB1, 0xB2};
        const auto PayloadBytes = std::span<const std::uint8_t>(Payload);
        const auto Wire = Hysteria2::BuildUdp(
            Hysteria2::UdpFrameInput{3U, 5U, &Target, PayloadBytes});
        auto Raw = std::make_shared<ScriptedTransmission>(std::move(Executor));
        Raw->ToRead = Wire;
        auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");

        EXPECT_EQ(co_await Connection->WriteHandshake(Target), Prism::Error::None);
        Raw->ReadFailureWithBytesAtEnd = true;
        Hysteria2::Address Source;
        std::vector<std::uint8_t> Received;
        const auto ErrorValue = co_await Connection->AsyncReceiveDatagram(Source, Received);
        EXPECT_EQ(ErrorValue, Prism::Error::None);
        EXPECT_EQ(Source.Type, Target.Type);
        EXPECT_EQ(Source.Host, Target.Host);
        EXPECT_EQ(Source.Port, Target.Port);
        EXPECT_EQ(Received, Payload);
        EXPECT_EQ(Raw->ReadPosition(), Wire.size());
        const auto Reads = Raw->ReadsDone;
        EXPECT_EQ(
            co_await Connection->AsyncReceiveDatagram(Source, Received),
            Prism::Error::IoError);
        EXPECT_EQ(
            co_await Connection->AsyncReceiveDatagram(Source, Received),
            Prism::Error::IoError);
        EXPECT_EQ(Raw->ReadsDone, Reads);
        co_await CloseAndDrain(*Connection);
        co_await DrainActivity(*Raw);
    }

    /** @brief Dgram 数据报保留本次读取中已交付的完整 payload。 */
    auto RunDgramReceiveFromRetainsPayloadWithTerminal(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        const auto Target = MakeAddress(
            Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
        const std::vector<std::uint8_t> Payload{0xC1, 0xC2};
        const auto PayloadBytes = std::span<const std::uint8_t>(Payload);
        const auto Wire = Hysteria2::BuildUdp(
            Hysteria2::UdpFrameInput{9U, 13U, &Target, PayloadBytes});
        auto Raw = std::make_shared<ScriptedTransmission>(std::move(Executor));
        Raw->ToRead = Wire;
        Raw->ReadFailureWithBytesAtEnd = true;
        auto Datagram = std::make_shared<Hysteria2::Dgram<>>(Raw);
        Hysteria2::Address Source;
        std::vector<std::uint8_t> Received;

        const auto ErrorValue = co_await Datagram->AsyncReceiveFrom(Source, Received);
        EXPECT_EQ(ErrorValue, Prism::Error::None);
        EXPECT_EQ(Source.Type, Target.Type);
        EXPECT_EQ(Source.Host, Target.Host);
        EXPECT_EQ(Source.Port, Target.Port);
        EXPECT_EQ(Received, Payload);
        EXPECT_EQ(Raw->ReadPosition(), Wire.size());
        const auto Reads = Raw->ReadsDone;
        EXPECT_EQ(
            co_await Datagram->AsyncReceiveFrom(Source, Received),
            Prism::Error::IoError);
        EXPECT_EQ(
            co_await Datagram->AsyncReceiveFrom(Source, Received),
            Prism::Error::IoError);
        EXPECT_EQ(Raw->ReadsDone, Reads);
        co_await CloseAndDrain(*Datagram);
        co_await DrainActivity(*Raw);
    }

    TEST(Hysteria2ConnError, ReadFrameRetainsUdpPayloadWithTerminal)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext,
            RunReadFrameRetainsUdpPayloadWithTerminal(IoContext.get_executor()));
    }

    TEST(Hysteria2ConnError, ReadExactRetainsCompletedPrefixAndStopsOnTerminal)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext,
            RunReadExactRetainsCompletedPrefixAndStopsOnTerminal(IoContext.get_executor()));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramRetainsPayloadWithTerminal)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext,
            RunReceiveDatagramRetainsPayloadWithTerminal(IoContext.get_executor()));
    }

    TEST(Hysteria2DgramError, ReceiveFromRetainsPayloadWithTerminal)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext,
            RunDgramReceiveFromRetainsPayloadWithTerminal(IoContext.get_executor()));
    }
} // namespace
