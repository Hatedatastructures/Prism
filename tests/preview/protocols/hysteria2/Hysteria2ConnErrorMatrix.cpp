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

#include <preview/Transport/MemoryStream.hpp>
#include <preview/Protocols/Hysteria2/Hysteria2.hpp>
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
        /**
         * @brief 构造桩
         * @param Executor 执行器
         */
        explicit ScriptedTransmission(Net::any_io_executor Executor) : Executor_(std::move(Executor))
        {
        }

        /** @brief 获取执行器 */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Udp;
        }

        /**
         * @brief 读取：注入队列消费，耗尽返回 EOF，可注入错误
         * @details 每次读取前经 post 挂起一次，覆盖协程挂起/恢复分支。
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            ErrorCode.clear();
            const auto AwaitableToken = Net::use_awaitable;
            co_await Net::post(Executor_, AwaitableToken);
            ++ReadsDone;
            if (ReadsDone >= ReadFailAt)
            {
                ErrorCode = Preview::make_error_code(Preview::Error::IoError);
                co_return 0;
            }
            if (OverreportRead)
            {
                ErrorCode.clear();
                co_return Buffer.size() + 1;
            }
            if (ReadPosition_ >= ToRead.size())
            {
                ErrorCode.clear();
                co_return 0; // EOF
            }
            const auto Count = std::min(Buffer.size(), ToRead.size() - ReadPosition_);
            std::memcpy(Buffer.data(), ToRead.data() + ReadPosition_, Count);
            ReadPosition_ += Count;
            ErrorCode.clear();
            co_return Count;
        }

        /**
         * @brief 写入：捕获数据，超限额返回错误，可注入错误与异常
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            ErrorCode.clear();
            if (WriteThrow)
            {
                throw std::runtime_error("Scripted write throw");
            }
            if (WriteFail || WritesDone >= WriteLimit)
            {
                ErrorCode = Preview::make_error_code(Preview::Error::IoError);
                co_return 0;
            }
            const auto *Source = reinterpret_cast<const std::uint8_t *>(Buffer.data());
            Written.insert(Written.end(), Source, Source + Buffer.size());
            ++WritesDone;
            if (OverreportWrite)
            {
                co_return Buffer.size() + 1;
            }
            co_return Buffer.size();
        }

        /** @brief 关闭桩（后续读返回 EOF） */
        auto Close() -> void override
        {
            Closed = true;
        }

        /** @brief 取消挂起操作 */
        auto Cancel() -> void override
        {
        }

        std::vector<std::uint8_t> ToRead; ///< 注入读取数据
        std::vector<std::uint8_t> Written; ///< 捕获写入数据
        bool WriteFail{false};            ///< 下次写入返回 io_error
        bool WriteThrow{false};           ///< 写入抛异常（协程异常路径）
        std::size_t WriteLimit{std::numeric_limits<std::size_t>::max()}; ///< 允许成功写入次数上限
        std::size_t WritesDone{0};        ///< 已成功写入次数
        std::size_t ReadFailAt{std::numeric_limits<std::size_t>::max()}; ///< 第 N 次读取返回 io_error
        std::size_t ReadsDone{0};          ///< 已执行读取次数
        bool OverreportRead{false};        ///< 返回超过目标缓冲区的字节数
        bool OverreportWrite{false};       ///< 写入返回超过目标缓冲区的字节数
        bool Closed{false};                 ///< 关闭标志

    private:
        Net::any_io_executor Executor_;
        std::size_t ReadPosition_{0};
    };

    /// 构造服务端握手输入（认证帧 + TCP 目标帧）
    auto MakeServerHandshakeBytes(const std::string &Password, const Hysteria2::Address &Target)
        -> std::vector<std::uint8_t>
    {
        const auto Auth = Hysteria2::MakeAuthRequest(Password);
        const std::span<const std::uint8_t> EmptyPayload;
        const auto Tcp = Hysteria2::BuildTcp(Target, EmptyPayload);
        std::vector<std::uint8_t> Wire(Auth.begin(), Auth.end());
        Wire.insert(Wire.end(), Tcp.begin(), Tcp.end());
        return Wire;
    }

    TEST(Hysteria2ConnError, WriteHandshakeAuthSendFail)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->WriteFail = true;
            auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");
            const auto Target = MakeAddress(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
            const auto ErrorValue = co_await Connection->WriteHandshake(Target);
            EXPECT_EQ(ErrorValue, Preview::Error::IoError);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2ConnError, WriteHandshakeAuthSendThrow)
    {
        Net::io_context IoContext;

        // 底层写入抛异常 → 异常穿透协程边界
        auto ThrowingCoroutine = [&]() -> Net::awaitable<void>
        {
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->WriteThrow = true;
            auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");
            const auto Target = MakeAddress(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
            const auto ErrorValue = co_await Connection->WriteHandshake(Target);
            (void)ErrorValue;
        };
        EXPECT_THROW(RunCoroutine(IoContext, std::move(ThrowingCoroutine)), std::runtime_error);
    }

    TEST(Hysteria2ConnError, WriteHandshakeTcpFrameSendFail)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            // 认证帧写成功（限额 1），TCP 帧写失败 → io_error
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->WriteLimit = 1;
            auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");
            const auto Target = MakeAddress(Hysteria2::AddressType::Domain, "example.com", 443);
            const auto ErrorValue = co_await Connection->WriteHandshake(Target);
            EXPECT_EQ(ErrorValue, Preview::Error::IoError);
            EXPECT_FALSE(Raw->Written.empty());
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2ConnError, ReadHandshakeEofOnAuthHead)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            // 对端立即关闭 → 读认证帧头失败 → io_error
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");
            auto [ErrorValue, MessageValue] = co_await Connection->ReadHandshake();
            EXPECT_EQ(ErrorValue, Preview::Error::IoError);
            (void)MessageValue;
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2ConnError, ReadHandshakeEofOnAuthBody)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            // 认证帧头合法但长度字段后的正文缺失 → io_error
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->ToRead = {0x01, 0x10};
            auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");
            auto [ErrorValue, MessageValue] = co_await Connection->ReadHandshake();
            EXPECT_EQ(ErrorValue, Preview::Error::IoError);
            (void)MessageValue;
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2ConnError, ReadHandshakeEofOnTargetAddress)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            // 认证帧合法，TCP 帧只有 Kind + ATYP + 1 字节地址 → io_error
            const auto Auth = Hysteria2::MakeAuthRequest("pw");
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->ToRead.assign(Auth.begin(), Auth.end());
            Raw->ToRead.insert(Raw->ToRead.end(), {0x01, 0x01, 0xAA});
            auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");
            auto [ErrorValue, MessageValue] = co_await Connection->ReadHandshake();
            EXPECT_EQ(ErrorValue, Preview::Error::IoError);
            (void)MessageValue;
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2ConnError, ReadHandshakeRejectsUnknownKindBeforeAddress)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            const auto Auth = Hysteria2::MakeAuthRequest("pw");
            const auto Target = MakeAddress(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
            const std::span<const std::uint8_t> EmptyPayload;
            auto TargetFrame = Hysteria2::BuildTcp(Target, EmptyPayload);
            if (TargetFrame.empty())
            {
                ADD_FAILURE() << "BuildTcp returned an empty target frame";
                co_return;
            }
            TargetFrame[0] = 0x7F; // 未定义 Kind，不应进入地址解析

            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->ToRead.assign(Auth.begin(), Auth.end());
            Raw->ToRead.insert(Raw->ToRead.end(), TargetFrame.begin(), TargetFrame.end());
            auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");
            auto [ErrorValue, MessageValue] = co_await Connection->ReadHandshake();
            EXPECT_EQ(ErrorValue, Preview::Error::BadMessage);
            (void)MessageValue;
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2ConnError, ReadHandshakeBadAtypTargetFrame)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            // 认证帧合法，TCP 帧 ATYP 非法（0x99）→ bad_message
            const auto Auth = Hysteria2::MakeAuthRequest("pw");
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->ToRead.assign(Auth.begin(), Auth.end());
            Raw->ToRead.insert(Raw->ToRead.end(), {0x01, 0x99});
            auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");
            auto [ErrorValue, MessageValue] = co_await Connection->ReadHandshake();
            EXPECT_EQ(ErrorValue, Preview::Error::BadMessage);
            (void)MessageValue;
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2ConnError, SendDatagramIoError)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            // 握手成功后写失败 → 数据报发送 io_error
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");
            const auto Target = MakeAddress(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
            auto HandshakeError = co_await Connection->WriteHandshake(Target);
            EXPECT_EQ(HandshakeError, Preview::Error::None);
            Raw->WriteFail = true;
            const std::string PayloadText = "x";
            const auto Payload = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(PayloadText.data()), PayloadText.size());
            const auto ErrorValue = co_await Connection->AsyncSendDatagram(Target, Payload);
            EXPECT_EQ(ErrorValue, Preview::Error::IoError);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramEofOnFrame)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            // 握手合法，随后对端关闭 → 数据报接收帧头 EOF → unexpected_eof
            const auto Target = MakeAddress(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->ToRead = MakeServerHandshakeBytes("pw", Target);
            auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");
            auto [HandshakeError, MessageValue] = co_await Connection->ReadHandshake();
            EXPECT_EQ(HandshakeError, Preview::Error::None);
            (void)MessageValue;
            Hysteria2::Address Source;
            std::vector<std::uint8_t> Payload;
            const auto ErrorValue = co_await Connection->AsyncReceiveDatagram(Source, Payload);
            EXPECT_EQ(ErrorValue, Preview::Error::UnexpectedEof);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramBadAtyp)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            // 握手合法，UDP 帧 ATYP 非法 → bad_message
            const auto Target = MakeAddress(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->ToRead = MakeServerHandshakeBytes("pw", Target);
            Raw->ToRead.insert(Raw->ToRead.end(), {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x99});
            auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");
            auto [HandshakeError, MessageValue] = co_await Connection->ReadHandshake();
            EXPECT_EQ(HandshakeError, Preview::Error::None);
            (void)MessageValue;
            Hysteria2::Address Source;
            std::vector<std::uint8_t> Payload;
            const auto ErrorValue = co_await Connection->AsyncReceiveDatagram(Source, Payload);
            EXPECT_EQ(ErrorValue, Preview::Error::BadMessage);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramTruncatedIds)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            // UDP 数据报 Kind 后 Id 只有 3 字节 → need_more
            const auto Target = MakeAddress(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->ToRead = MakeServerHandshakeBytes("pw", Target);
            Raw->ToRead.insert(Raw->ToRead.end(), {0x02, 1, 2, 3});
            auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");
            auto [HandshakeError, MessageValue] = co_await Connection->ReadHandshake();
            EXPECT_EQ(HandshakeError, Preview::Error::None);
            (void)MessageValue;
            Hysteria2::Address Source;
            std::vector<std::uint8_t> Payload;
            const auto ErrorValue = co_await Connection->AsyncReceiveDatagram(Source, Payload);
            EXPECT_EQ(ErrorValue, Preview::Error::NeedMore);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramTruncatedAtyp)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            // UDP 数据报 Id 完整但 ATYP 缺失 → need_more
            const auto Target = MakeAddress(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->ToRead = MakeServerHandshakeBytes("pw", Target);
            Raw->ToRead.insert(Raw->ToRead.end(), {0x02, 0, 0, 0, 0, 0, 0, 0, 0});
            auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");
            auto [HandshakeError, MessageValue] = co_await Connection->ReadHandshake();
            EXPECT_EQ(HandshakeError, Preview::Error::None);
            (void)MessageValue;
            Hysteria2::Address Source;
            std::vector<std::uint8_t> Payload;
            const auto ErrorValue = co_await Connection->AsyncReceiveDatagram(Source, Payload);
            EXPECT_EQ(ErrorValue, Preview::Error::NeedMore);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramTruncatedPort)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            // UDP 数据报地址体完整但端口缺失 → need_more
            const auto Target = MakeAddress(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->ToRead = MakeServerHandshakeBytes("pw", Target);
            Raw->ToRead.insert(Raw->ToRead.end(), {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4});
            auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");
            auto [HandshakeError, MessageValue] = co_await Connection->ReadHandshake();
            EXPECT_EQ(HandshakeError, Preview::Error::None);
            (void)MessageValue;
            Hysteria2::Address Source;
            std::vector<std::uint8_t> Payload;
            const auto ErrorValue = co_await Connection->AsyncReceiveDatagram(Source, Payload);
            // UDP 已保留完整数据报边界；截断数据报是 need_more，
            // 而不是流式 EOF。
            EXPECT_EQ(ErrorValue, Preview::Error::NeedMore);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramPayloadIoError)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            // UDP 数据报读取本身注入错误 → io_error
            const auto Target = MakeAddress(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->ToRead = MakeServerHandshakeBytes("pw", Target);
            Raw->ToRead.insert(Raw->ToRead.end(),
                               {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50});
            auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");
            auto [HandshakeError, MessageValue] = co_await Connection->ReadHandshake();
            EXPECT_EQ(HandshakeError, Preview::Error::None);
            (void)MessageValue;
            Raw->ReadFailAt = Raw->ReadsDone + 1;
            Hysteria2::Address Source;
            std::vector<std::uint8_t> Payload;
            const auto ErrorValue = co_await Connection->AsyncReceiveDatagram(Source, Payload);
            EXPECT_EQ(ErrorValue, Preview::Error::IoError);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2ConnError, ReceiveDatagramRejectsOverreportedRead)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            const auto Target = MakeAddress(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->ToRead = MakeServerHandshakeBytes("pw", Target);
            auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");
            auto [HandshakeError, MessageValue] = co_await Connection->ReadHandshake();
            EXPECT_EQ(HandshakeError, Preview::Error::None);
            (void)MessageValue;

            Raw->OverreportRead = true;
            Hysteria2::Address Source;
            std::vector<std::uint8_t> Payload;
            const auto ErrorValue = co_await Connection->AsyncReceiveDatagram(Source, Payload);
            EXPECT_EQ(ErrorValue, Preview::Error::BadLength);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2ConnError, DgramRejectsOverreportedRead)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->OverreportRead = true;
            auto Datagram = std::make_shared<Hysteria2::Dgram<>>(Raw);
            Hysteria2::Address Source;
            std::vector<std::uint8_t> Payload;
            EXPECT_EQ(co_await Datagram->AsyncReceiveFrom(Source, Payload), Preview::Error::BadLength);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2DgramError, SendToRejectsOverreportedWrite)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->OverreportWrite = true;
            auto Datagram = std::make_shared<Hysteria2::Dgram<>>(Raw);
            const std::string PayloadText = "x";
            const auto Target = MakeAddress(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
            const auto Payload = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(PayloadText.data()), PayloadText.size());
            const auto ErrorValue = co_await Datagram->AsyncSendTo(Target, Payload);
            EXPECT_EQ(ErrorValue, Preview::Error::BadLength);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2ConnError, ReadHandshakeAddressBodyEof)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            // 域名地址：长度 5 但仅注入 2 字节 → 地址体截断 io_error
            const auto Auth = Hysteria2::MakeAuthRequest("pw");
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->ToRead.assign(Auth.begin(), Auth.end());
            Raw->ToRead.insert(Raw->ToRead.end(), {0x01, 0x02, 0x05, 'a', 'b'});
            auto Connection = std::make_shared<Hysteria2::Conn<>>(Raw, "pw");
            auto [ErrorValue, MessageValue] = co_await Connection->ReadHandshake();
            EXPECT_EQ(ErrorValue, Preview::Error::IoError);
            (void)MessageValue;
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2ConnError, PassthroughPeerClosed)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = Preview::MakeMemoryPair(IoContext.get_executor());

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            // 握手成功后对端关闭：读返回 0，写返回 broken_pipe
            auto Stream = std::make_shared<Preview::MemoryStream>(std::move(ClientStream));
            auto Connection = std::make_shared<Hysteria2::Conn<>>(Stream, "pw");
            const auto Target = MakeAddress(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
            auto HandshakeError = co_await Connection->WriteHandshake(Target);
            EXPECT_EQ(HandshakeError, Preview::Error::None);
            ServerStream.Close();
            std::array<std::byte, 64> Buffer{};
            std::error_code ErrorCode;
            const auto ReadCount = co_await Connection->async_read_some(Buffer, ErrorCode);
            EXPECT_EQ(ReadCount, 0u);
            EXPECT_FALSE(ErrorCode);
            const auto WriteBuffer = std::span<const std::byte>(Buffer.data(), 4);
            const auto WriteCount = co_await Connection->async_write_some(WriteBuffer, ErrorCode);
            EXPECT_EQ(WriteCount, 0u);
            const auto ExpectedValue = static_cast<int>(Net::error::broken_pipe);
            EXPECT_EQ(ErrorCode.value(), ExpectedValue);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2DgramError, SendToIoError)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->WriteFail = true;
            auto Datagram = std::make_shared<Hysteria2::Dgram<>>(Raw);
            const std::string PayloadText = "x";
            const auto Target = MakeAddress(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
            const auto Payload = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(PayloadText.data()), PayloadText.size());
            const auto ErrorValue = co_await Datagram->AsyncSendTo(Target, Payload);
            EXPECT_EQ(ErrorValue, Preview::Error::IoError);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2DgramError, ReceiveTruncatedPort)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            // 头 + 地址体完整，端口缺失 → need_more
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->ToRead = {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4};
            auto Datagram = std::make_shared<Hysteria2::Dgram<>>(Raw);
            Hysteria2::Address Source;
            std::vector<std::uint8_t> Payload;
            const auto ErrorValue = co_await Datagram->AsyncReceiveFrom(Source, Payload);
            // UDP 已保留完整数据报边界；截断数据报是 need_more，
            // 而不是流式 EOF。
            EXPECT_EQ(ErrorValue, Preview::Error::NeedMore);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2DgramError, ReceiveEmptyPayload)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            // 帧头和地址完整，空载荷是合法数据报
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->ToRead = {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50};
            auto Datagram = std::make_shared<Hysteria2::Dgram<>>(Raw);
            Hysteria2::Address Source;
            std::vector<std::uint8_t> Payload;
            const auto ErrorValue = co_await Datagram->AsyncReceiveFrom(Source, Payload);
            EXPECT_EQ(ErrorValue, Preview::Error::None);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2DgramError, ReceiveIoError)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            // UDP 数据报读取注入错误 → io_error
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->ToRead = {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50};
            Raw->ReadFailAt = 1;
            auto Datagram = std::make_shared<Hysteria2::Dgram<>>(Raw);
            Hysteria2::Address Source;
            std::vector<std::uint8_t> Payload;
            const auto ErrorValue = co_await Datagram->AsyncReceiveFrom(Source, Payload);
            EXPECT_EQ(ErrorValue, Preview::Error::IoError);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2DgramError, ReceiveTruncatedAddressBody)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            // UDP 数据报域名地址：长度 5 但仅注入 2 字节 → need_more
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->ToRead = {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x05, 'a', 'b'};
            auto Datagram = std::make_shared<Hysteria2::Dgram<>>(Raw);
            Hysteria2::Address Source;
            std::vector<std::uint8_t> Payload;
            const auto ErrorValue = co_await Datagram->AsyncReceiveFrom(Source, Payload);
            EXPECT_EQ(ErrorValue, Preview::Error::NeedMore);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

    TEST(Hysteria2DgramError, PassthroughWriteIoError)
    {
        Net::io_context IoContext;

        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            // 透传写注入错误 → io_error
            auto Raw = std::make_shared<ScriptedTransmission>(IoContext.get_executor());
            Raw->WriteFail = true;
            auto Datagram = std::make_shared<Hysteria2::Dgram<>>(Raw);
            std::array<std::byte, 8> Buffer{};
            std::error_code ErrorCode;
            const auto WriteBuffer = std::span<const std::byte>(Buffer.data(), 4);
            const auto WriteCount = co_await Datagram->async_write_some(WriteBuffer, ErrorCode);
            EXPECT_EQ(WriteCount, 0u);
            EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::IoError));
        };
        RunCoroutine(IoContext, std::move(Coroutine));
    }

} // namespace
