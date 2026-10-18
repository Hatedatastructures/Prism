/**
 * @file TlsRecognitionPipelineTest.cpp
 * @brief 生产 Probe 的错误进度保留契约。
 */

#include "TlsReassemblyTestSupport.hpp"

TEST(TlsReassemblyTest, ProbePreservesBytesReturnedWithReadError)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Prefix = AsBytes(std::vector<std::uint8_t>{'G'});
        Transport->Push(Prefix, std::make_error_code(std::errc::connection_reset));
        rec::ProbeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await rec::Probe(*Transport);
                });

        EXPECT_FALSE(Result.success);
        ASSERT_EQ(Result.PreReadSize, Prefix.size());
        EXPECT_EQ(Result.PreRead.front(), Prefix.front());
    }
