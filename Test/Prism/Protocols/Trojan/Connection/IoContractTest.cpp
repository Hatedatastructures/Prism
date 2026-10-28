/**
 * @file IoContractTest.cpp
 * @brief Trojan 组合 I/O 违反底层长度契约时的行为测试。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Protocols/Trojan/Trojan.hpp>
#include <TestSupport/Prism/MockTransport.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Trojan = Prism::Trojan;
    using Prism::PrismMockTransport;

    /** @brief 验证 Trojan 组合读写拒绝底层 overreport。 */
    auto RunOverreportedComposite(
        const std::shared_ptr<PrismMockTransport> &Raw,
        const std::shared_ptr<Trojan::Conn<>> &Connection) -> Net::awaitable<void>
    {
        std::array<std::byte, 2> Buffer{};
        Raw->OverreportRead = true;
        const auto Read = co_await Connection->ReadSome(Buffer);
        EXPECT_EQ(Read.Bytes, 0U);
        EXPECT_EQ(Prism::Fault::ToNative(Read.Failure),
                  Prism::make_error_code(Prism::Error::BrokenPipe));
        Raw->OverreportRead = false;
        Raw->OverreportWrite = true;
        const auto Written = co_await Connection->WriteSome(Buffer);
        EXPECT_EQ(Written.Bytes, 0U);
        EXPECT_EQ(Prism::Fault::ToNative(Written.Failure),
                  Prism::make_error_code(Prism::Error::BrokenPipe));
    }

    /** @brief 同次终止失败仍保留已读地址体与超读尾部。 */
    auto RunTerminalReadPreservesAddressAndTail(
        const std::shared_ptr<PrismMockTransport> &Raw,
        const std::shared_ptr<Trojan::Conn<>> &Connection) -> Net::awaitable<void>
    {
        const Trojan::Address ExpectedTarget{
            Trojan::AddressType::Ipv4, "192.0.2.17", 443};
        auto Wire = Trojan::BuildRequest(
            Trojan::Credential("pw123456"), Trojan::Command::Connect, ExpectedTarget);
        const std::array<std::uint8_t, 2> TailBytes{0xA5U, 0x5AU};
        Wire.insert(Wire.end(), TailBytes.begin(), TailBytes.end());
        Raw->ToRead.assign(Wire.begin(), Wire.end());
        Raw->ReadErrorBytes = Raw->ToRead.size();
        Raw->SetReadError(std::make_error_code(std::errc::connection_reset));

        const auto Handshake = co_await Connection->ReadHandshake();
        EXPECT_TRUE(Handshake);
        EXPECT_EQ(Raw->ReadsDone, 1U);
        if (Handshake)
        {
            EXPECT_EQ(Handshake->Cmd, Trojan::Command::Connect);
            EXPECT_EQ(Handshake->Target.Type, ExpectedTarget.Type);
            EXPECT_EQ(Handshake->Target.Host, ExpectedTarget.Host);
            EXPECT_EQ(Handshake->Target.Port, ExpectedTarget.Port);

            std::array<std::byte, 2> Tail{};
            const auto ReadTail = co_await Connection->ReadSome(Tail);
            EXPECT_EQ(ReadTail.Bytes, Tail.size());
            EXPECT_FALSE(ReadTail.Failure.Failed());
            EXPECT_EQ(Tail[0], std::byte{0xA5});
            EXPECT_EQ(Tail[1], std::byte{0x5A});
            EXPECT_EQ(Raw->ReadsDone, 1U);

            std::array<std::byte, 1> TerminalProbe{};
            const auto Terminal = co_await Connection->ReadSome(TerminalProbe);
            EXPECT_EQ(Terminal.Bytes, 0U);
            EXPECT_EQ(Prism::Fault::ToNative(Terminal.Failure),
                      std::make_error_code(std::errc::connection_reset));
            EXPECT_EQ(Raw->ReadsDone, 1U);
        }

        const auto Closed = Connection->Close();
        EXPECT_TRUE(Closed);
        const auto ConnectionDrain = co_await Connection->Activity()->Drain();
        EXPECT_TRUE(ConnectionDrain);
        EXPECT_TRUE(Connection->Activity()->IsRetired());
        const auto RawDrain = co_await Raw->Activity()->Drain();
        EXPECT_TRUE(RawDrain);
        EXPECT_TRUE(Raw->Activity()->IsRetired());
    }

    auto RunCoroutine(Net::io_context &IoContext, Net::awaitable<void> Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Coroutine),
                      [&Exception, &IoContext](std::exception_ptr Failure)
                      {
                          Exception = std::move(Failure);
                          IoContext.stop();
                      });
        IoContext.run();
        if (Exception) std::rethrow_exception(Exception);
    }

    TEST(TrojanConnSession, RejectsOverreportedCompositeReadWrite)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<PrismMockTransport>(IoContext.get_executor());
        auto Connection = std::make_shared<Trojan::Conn<>>(Raw, "pw123456");
        RunCoroutine(IoContext, RunOverreportedComposite(Raw, Connection));
    }

    TEST(TrojanConnSession, PreservesBytesFromTerminalReadForAddressAndTail)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<PrismMockTransport>(IoContext.get_executor());
        auto Connection = std::make_shared<Trojan::Conn<>>(Raw, "pw123456");
        RunCoroutine(IoContext, RunTerminalReadPreservesAddressAndTail(Raw, Connection));
    }
} // namespace
