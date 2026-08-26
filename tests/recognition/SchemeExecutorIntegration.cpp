/**
 * @file SchemeExecutorIntegration.cpp
 * @brief Preview recognition 识别管线 3 场景（detect 确定命中/回落/预读回注）
 */

#include <gtest/gtest.h>

#include <common/Core/Recognition/Recognition.hpp>
#include <common/Core/Recognition/Protocol.hpp>
#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Core/Transport/Preview.hpp>

TEST(RecognitionPipeline, DeterministicHit)
{
    // 单一 VLESS 结构化特征应确定命中
    std::vector<std::uint8_t> vless = {0x00,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 0x00, 0x01, 0x00,0x50, 0x01};
    EXPECT_EQ(Preview::Recognition::Detect(vless), Preview::Recognition::ProtocolType::Vless);
}

TEST(RecognitionPipeline, MultiCandidateFallback)
{
    // 未知数据应回落 unknown，且 pipeline 能正确回注
    std::vector<std::uint8_t> unknown = {0xFF,0xFF,0xFF};
    EXPECT_EQ(Preview::Recognition::Detect(unknown), Preview::Recognition::ProtocolType::Unknown);
}

TEST(RecognitionPipeline, PreviewRewind)
{
    namespace net = boost::asio;
    net::io_context ioc;
    auto [a,b] = Preview::MakeMemoryPair(ioc.get_executor());
    const std::string payload = "hello Preview";
    bool done = false;
    net::co_spawn(ioc, [&]() -> net::awaitable<void> {
        auto preread = std::span<const std::byte>(reinterpret_cast<const std::byte*>(payload.data()), payload.size());
        auto wrapped = Preview::Transport::WrapWithPreview(
            std::make_shared<Preview::MemoryStream>(std::move(b)), preread);
        std::array<std::byte,64> buf{};
        std::error_code ec;
        const auto n = co_await wrapped->async_read_some(buf, ec);
        EXPECT_EQ(n, payload.size());
        EXPECT_FALSE(ec);
        done = true;
    }, [&](std::exception_ptr e){ if(e) ADD_FAILURE(); ioc.stop(); });
    ioc.run();
    EXPECT_TRUE(done);
}
