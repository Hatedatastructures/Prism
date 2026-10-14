/**
 * @file TrojanConnIoContractTest.cpp
 * @brief Trojan 组合 I/O 违反底层长度契约时的行为测试。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <exception>
#include <memory>
#include <utility>

#include <Preview/Protocols/Trojan/Trojan.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Trojan = Preview::Trojan;
    using Preview::PreviewMockTransport;

    /** @brief 验证 Trojan 组合读写拒绝底层 overreport。 */
    auto RunOverreportedComposite(
        const std::shared_ptr<PreviewMockTransport> &Raw,
        const std::shared_ptr<Trojan::Conn<>> &Connection) -> Net::awaitable<void>
    {
        std::array<std::byte, 2> Buffer{};
        Raw->OverreportRead = true;
        const auto Read = co_await Connection->ReadSome(Buffer);
        EXPECT_EQ(Read.Bytes, 0U);
        EXPECT_EQ(Preview::Fault::ToNative(Read.Failure),
                  Preview::make_error_code(Preview::Error::BrokenPipe));
        Raw->OverreportRead = false;
        Raw->OverreportWrite = true;
        const auto Written = co_await Connection->WriteSome(Buffer);
        EXPECT_EQ(Written.Bytes, 0U);
        EXPECT_EQ(Preview::Fault::ToNative(Written.Failure),
                  Preview::make_error_code(Preview::Error::BrokenPipe));
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
        auto Raw = std::make_shared<PreviewMockTransport>(IoContext.get_executor());
        auto Connection = std::make_shared<Trojan::Conn<>>(Raw, "pw123456");
        RunCoroutine(IoContext, RunOverreportedComposite(Raw, Connection));
    }
} // namespace
