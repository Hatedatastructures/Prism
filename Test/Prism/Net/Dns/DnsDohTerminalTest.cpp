/**
 * @file DnsDohTerminalTest.cpp
 * @brief DoH 分块读取在同次字节与终态完成时的边界测试。
 */

#include "DnsUpstreamTestSupport.hpp"

#include <Prism/Foundation/Error.hpp>
#include <Prism/Net/Dns/AttemptDeadline.hpp>
#include <Prism/Net/Dns/Detail/DohResponse.hpp>
#include <Prism/Net/Dns/Detail/TlsTransport.hpp>
#include <Prism/Net/Dns/Transport.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace Dns = Prism::Network::Dns;

    class ScriptedDohTls final
    {
    public:
        ScriptedDohTls(std::vector<std::uint8_t> Input,
                       const boost::system::error_code Failure,
                       const std::size_t ChunkBytes = 0U)
            : Input_(std::move(Input)), Failure_(Failure), ChunkBytes_(ChunkBytes)
        {
        }

        auto ReadSome(const std::span<std::uint8_t> Buffer,
                      Dns::Detail::AttemptDeadline Deadline)
            -> Net::awaitable<Dns::Detail::TlsReadResult>
        {
            (void)Deadline;
            ++ReadCalls_;
            auto ReadLimit = Buffer.size();
            if (ChunkBytes_ != 0U && ReadLimit > ChunkBytes_)
            {
                ReadLimit = ChunkBytes_;
            }
            const auto Count = ReadLimit < Input_.size() ? ReadLimit : Input_.size();
            for (std::size_t Index = 0; Index < Count; ++Index)
            {
                Buffer[Index] = Input_[Index];
            }
            Input_.erase(Input_.begin(), Input_.begin() + static_cast<std::ptrdiff_t>(Count));
            auto Failure = boost::system::error_code{};
            if (Input_.empty())
            {
                Failure = Failure_;
                if (Failure)
                {
                    TerminalBytes_ = Count;
                }
            }
            co_return Dns::Detail::TlsReadResult{Count, Failure};
        }

        auto Close() -> void
        {
            ++CloseCalls_;
            Open_ = false;
        }

        [[nodiscard]] auto IsOpen() const noexcept -> bool
        {
            return Open_;
        }

        [[nodiscard]] auto ReadCalls() const noexcept -> std::size_t
        {
            return ReadCalls_;
        }

        [[nodiscard]] auto CloseCalls() const noexcept -> std::size_t
        {
            return CloseCalls_;
        }

        [[nodiscard]] auto RemainingBytes() const noexcept -> std::size_t
        {
            return Input_.size();
        }

        [[nodiscard]] auto TerminalBytes() const noexcept -> std::size_t
        {
            return TerminalBytes_;
        }

    private:
        std::vector<std::uint8_t> Input_;
        boost::system::error_code Failure_;
        std::size_t ChunkBytes_{0U};
        std::size_t ReadCalls_{0};
        std::size_t CloseCalls_{0};
        std::size_t TerminalBytes_{0U};
        bool Open_{true};
    };

    struct ScriptedDohOwner final
    {
        ScriptedDohOwner(std::vector<std::uint8_t> Input,
                         const boost::system::error_code Failure,
                         const std::size_t ChunkBytes = 0U)
            : Tls(std::move(Input), Failure, ChunkBytes)
        {
        }

        ScriptedDohTls Tls;
    };

    [[nodiscard]] auto MakeHttpResponse(const std::span<const std::uint8_t> Body)
        -> std::vector<std::uint8_t>
    {
        auto Header = std::string("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: ");
        Header += std::to_string(Body.size());
        Header += "\r\n\r\n";
        std::vector<std::uint8_t> Input;
        Input.reserve(Header.size() + Body.size());
        for (const auto Character : Header)
        {
            Input.push_back(static_cast<std::uint8_t>(Character));
        }
        Input.insert(Input.end(), Body.begin(), Body.end());
        return Input;
    }

    auto ReadDohResponse(std::shared_ptr<ScriptedDohOwner> Owner,
                         Dns::EcResult<std::vector<std::uint8_t>> *Result)
        -> Net::awaitable<void>
    {
        *Result = co_await Dns::Detail::ReceiveDohResponse(
            std::move(Owner), Dns::Detail::AttemptDeadline::FromBudget(
                                  std::chrono::milliseconds(1000)));
    }
} // namespace

TEST(DnsDohTerminal, CompleteHttpAndDnsResponseWinsOverNativeResetAndRetiresLink)
{
    Net::io_context IoContext;
    const std::vector<std::uint8_t> Query{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 'd', 'o', 'h', 0x00, 0x00, 0x01, 0x00, 0x01};
    const auto ExpectedBody = BuildDnsNoDataResponse(Query);
    const auto Reset = Net::error::make_error_code(Net::error::connection_reset);
    auto Owner = std::make_shared<ScriptedDohOwner>(MakeHttpResponse(ExpectedBody), Reset);
    Dns::EcResult<std::vector<std::uint8_t>> Result;

    RunCoro(IoContext, ReadDohResponse(Owner, &Result));

    ASSERT_TRUE(Result);
    EXPECT_EQ(*Result, ExpectedBody);
    EXPECT_EQ(Owner->Tls.ReadCalls(), 1U);
    EXPECT_EQ(Owner->Tls.CloseCalls(), 1U);
    EXPECT_FALSE(Owner->Tls.IsOpen());
}

TEST(DnsDohTerminal, FragmentedCompleteResponseWinsOverResetOnFinalPositiveRead)
{
    Net::io_context IoContext;
    const std::vector<std::uint8_t> Query{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 'd', 'o', 'h', 0x00, 0x00, 0x01, 0x00, 0x01};
    const auto ExpectedBody = BuildDnsNoDataResponse(Query);
    auto Response = MakeHttpResponse(ExpectedBody);
    const auto Reset = Net::error::make_error_code(Net::error::connection_reset);
    constexpr std::size_t ChunkBytes{17U};
    const auto ExpectedReadCalls = (Response.size() + ChunkBytes - 1U) / ChunkBytes;
    auto Owner = std::make_shared<ScriptedDohOwner>(
        std::move(Response), Reset, ChunkBytes);
    Dns::EcResult<std::vector<std::uint8_t>> Result;

    RunCoro(IoContext, ReadDohResponse(Owner, &Result));

    ASSERT_TRUE(Result);
    EXPECT_EQ(*Result, ExpectedBody);
    EXPECT_EQ(Owner->Tls.ReadCalls(), ExpectedReadCalls);
    EXPECT_EQ(Owner->Tls.RemainingBytes(), 0U);
    EXPECT_GT(Owner->Tls.TerminalBytes(), 0U);
    EXPECT_EQ(Owner->Tls.CloseCalls(), 1U);
    EXPECT_FALSE(Owner->Tls.IsOpen());
}

TEST(DnsDohTerminal, CompleteHttpResponseDoesNotConsumeDeadline)
{
    Net::io_context IoContext;
    const std::vector<std::uint8_t> Query{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 'd', 'o', 'h', 0x00, 0x00, 0x01, 0x00, 0x01};
    const auto ExpectedBody = BuildDnsNoDataResponse(Query);
    const auto Timeout = Prism::make_error_code(Prism::Error::Timeout);
    auto Owner = std::make_shared<ScriptedDohOwner>(MakeHttpResponse(ExpectedBody), Timeout);
    Dns::EcResult<std::vector<std::uint8_t>> Result;

    RunCoro(IoContext, ReadDohResponse(Owner, &Result));

    ASSERT_FALSE(Result);
    EXPECT_EQ(Result.error(), Timeout);
    EXPECT_EQ(Owner->Tls.ReadCalls(), 1U);
    EXPECT_EQ(Owner->Tls.CloseCalls(), 1U);
    EXPECT_FALSE(Owner->Tls.IsOpen());
}

TEST(DnsDohTerminal, CompleteHttpResponsePreservesAsioCancellation)
{
    Net::io_context IoContext;
    const std::vector<std::uint8_t> Query{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 'd', 'o', 'h', 0x00, 0x00, 0x01, 0x00, 0x01};
    const auto ExpectedBody = BuildDnsNoDataResponse(Query);
    const auto Canceled = Net::error::operation_aborted;
    auto Owner = std::make_shared<ScriptedDohOwner>(MakeHttpResponse(ExpectedBody), Canceled);
    Dns::EcResult<std::vector<std::uint8_t>> Result;

    RunCoro(IoContext, ReadDohResponse(Owner, &Result));

    ASSERT_FALSE(Result);
    EXPECT_EQ(Result.error(), Canceled);
    EXPECT_EQ(Owner->Tls.ReadCalls(), 1U);
    EXPECT_EQ(Owner->Tls.CloseCalls(), 1U);
    EXPECT_FALSE(Owner->Tls.IsOpen());
}

TEST(DnsDohTerminal, PartialHttpResponsePreservesAsioCancellation)
{
    Net::io_context IoContext;
    const auto Canceled = Net::error::operation_aborted;
    const std::vector<std::uint8_t> Partial{
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0'};
    auto Owner = std::make_shared<ScriptedDohOwner>(Partial, Canceled);
    Dns::EcResult<std::vector<std::uint8_t>> Result;

    RunCoro(IoContext, ReadDohResponse(Owner, &Result));

    ASSERT_FALSE(Result);
    EXPECT_EQ(Result.error(), Canceled);
    EXPECT_EQ(Owner->Tls.ReadCalls(), 1U);
    EXPECT_EQ(Owner->Tls.CloseCalls(), 1U);
    EXPECT_FALSE(Owner->Tls.IsOpen());
}
