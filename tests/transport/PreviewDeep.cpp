/**
 * @file PreviewDeep.cpp
 * @brief transport/Preview 深度纯函数测试
 * @details 通过 #include 源文件访问 Preview.cpp 中所有同步函数，
 *          覆盖构造函数、Executor、Close、Cancel、TransportType、
 *          NextLayer、WrapWithPreview 以及 completion-handler 重载。
 */

#include <prism/diagnose/log.hpp>
#include <prism/foundation/foundation.hpp>

#include "../../src/prism/net/transport/preview.cpp"
#include "TestSupport/Production/ProductionMockTransport.hpp"
#include <gtest/gtest.h>

using Psm::Testing::ProductionMockTransport;

namespace
{
    namespace psm_transport = psm::transport;
    auto make_mock() -> std::shared_ptr<ProductionMockTransport>
    {
        return std::make_shared<ProductionMockTransport>();
    }

    // ─── 构造函数测试 ──────────────────────────

    TEST(PreviewDeep, ConstructWithData)
    {
        auto mock = make_mock();
        const std::byte Data[] = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
        psm::transport::preview p(psm::transport::shared_transmission(mock), Data);

        // 验证 NextLayer 返回内部指针
        EXPECT_EQ(p.next_layer(), mock.get()) << "construct: NextLayer == mock";
        EXPECT_NE(p.inner(), nullptr) << "construct: Inner not null";
    }

    TEST(PreviewDeep, ConstructEmptyData)
    {
        auto mock = make_mock();
        psm::transport::preview p(psm::transport::shared_transmission(mock), std::span<const std::byte>{});

        EXPECT_EQ(p.next_layer(), mock.get()) << "construct: Empty preread -> NextLayer Ok";
    }

    TEST(PreviewDeep, ConstructNullInner)
    {
        psm::transport::preview p(nullptr, std::span<const std::byte>{});

        EXPECT_EQ(p.next_layer(), nullptr) << "construct: null Inner -> NextLayer null";
        EXPECT_EQ(p.inner(), nullptr) << "construct: null Inner -> Inner null";
    }

    TEST(PreviewDeep, ConstructLargeData)
    {
        auto mock = make_mock();
        std::vector<std::byte> big(4096, std::byte{0xAA});
        psm::transport::preview p(psm::transport::shared_transmission(mock), std::span<const std::byte>{big.data(), big.size()});

        EXPECT_EQ(p.next_layer(), mock.get()) << "construct: large preread -> Ok";
    }

    // ─── Executor() 测试 ──────────────────────

    TEST(PreviewDeep, ExecutorNullInner)
    {
        psm::transport::preview p(nullptr, std::span<const std::byte>{});
        auto ex = p.executor();
        // 空 Executor（默认构造）
        EXPECT_TRUE(!ex) << "Executor: null Inner -> Empty Executor";
    }

    TEST(PreviewDeep, ExecutorValidInner)
    {
        auto mock = make_mock();
        auto mock_ex = mock->executor();
        psm::transport::preview p(psm::transport::shared_transmission(mock), std::span<const std::byte>{});
        auto ex = p.executor();
        EXPECT_TRUE(!!ex) << "Executor: valid Inner -> non-Empty Executor";
    }

    // ─── Close() 测试 ─────────────────────────

    TEST(PreviewDeep, CloseNullInner)
    {
        psm::transport::preview p(nullptr, std::span<const std::byte>{});
        // Close() 对 null Inner 不应崩溃，且后续操作应安全
        p.close();
        p.close();
        EXPECT_TRUE(true) << "Close: null Inner -> idempotent, no crash";
    }

    TEST(PreviewDeep, CloseValidInner)
    {
        auto mock = make_mock();
        psm::transport::preview p(psm::transport::shared_transmission(mock), std::span<const std::byte>{});
        p.close();
        EXPECT_TRUE(mock->IsClosed()) << "Close: valid Inner -> mock closed";
    }

    // ─── Cancel() 测试 ────────────────────────

    TEST(PreviewDeep, CancelNullInner)
    {
        psm::transport::preview p(nullptr, std::span<const std::byte>{});
        p.cancel();
        p.cancel();
        EXPECT_TRUE(true) << "Cancel: null Inner -> idempotent, no crash";
    }

    TEST(PreviewDeep, CancelValidInner)
    {
        auto mock = make_mock();
        psm::transport::preview p(psm::transport::shared_transmission(mock), std::span<const std::byte>{});
        p.cancel();
        EXPECT_TRUE(mock->IsCancelled()) << "Cancel: valid Inner -> mock cancelled";
    }

    // ─── TransportType() 测试 ─────────────────

    TEST(PreviewDeep, TransportTypeNullInner)
    {
        psm::transport::preview p(nullptr, std::span<const std::byte>{});
        EXPECT_EQ(p.transport_type(), psm::transport::transmission::type::tcp) << "TransportType: null Inner -> Tcp";
    }

    TEST(PreviewDeep, TransportTypeValidInner)
    {
        auto mock = make_mock();
        psm::transport::preview p(psm::transport::shared_transmission(mock), std::span<const std::byte>{});
        // ProductionMockTransport 使用默认 TransportType() → 沿 NextLayer 链，最终返回 Tcp
        EXPECT_EQ(p.transport_type(), psm::transport::transmission::type::tcp) << "TransportType: mock Inner -> Tcp";
    }

    // ─── NextLayer() 测试 ────────────────────

    TEST(PreviewDeep, NextLayerMutable)
    {
        auto mock = make_mock();
        psm::transport::preview p(psm::transport::shared_transmission(mock), std::span<const std::byte>{});
        auto *nl = p.next_layer();
        EXPECT_EQ(nl, mock.get()) << "NextLayer: mutable == mock";
    }

    TEST(PreviewDeep, NextLayerConst)
    {
        auto mock = make_mock();
        const psm::transport::preview p(psm::transport::shared_transmission(mock), std::span<const std::byte>{});
        const auto *nl = p.next_layer();
        EXPECT_EQ(nl, mock.get()) << "NextLayer: const == mock";
    }

    TEST(PreviewDeep, NextLayerNull)
    {
        psm::transport::preview p(nullptr, std::span<const std::byte>{});
        EXPECT_EQ(p.next_layer(), nullptr) << "NextLayer: null Inner -> null";
    }

    // ─── Inner() 测试 ─────────────────────────

    TEST(PreviewDeep, InnerReturnsSharedPtr)
    {
        auto mock = make_mock();
        psm::transport::preview p(psm::transport::shared_transmission(mock), std::span<const std::byte>{});
        auto Inner = p.inner();
        EXPECT_EQ(Inner, mock) << "Inner: returns same shared_ptr";
    }

    // ─── WrapWithPreview() 测试 ──────────────

    TEST(PreviewDeep, WrapWithPreviewEmptyData)
    {
        auto mock = make_mock();
        auto original = psm::transport::shared_transmission(mock);
        auto Result = psm::transport::wrap_with_preview(original, std::span<const std::byte>{});
        // Data 为空 → 不包装，返回原始
        EXPECT_EQ(Result.get(), mock.get()) << "wrap: Empty Data -> original ptr";
    }

    TEST(PreviewDeep, WrapWithPreviewWithData)
    {
        auto mock = make_mock();
        auto original = psm::transport::shared_transmission(mock);
        const std::byte Data[] = {std::byte{0x01}, std::byte{0x02}};
        auto Result = psm::transport::wrap_with_preview(original, Data);
        // Data 非空 → 包装为 Preview
        EXPECT_NE(Result.get(), mock.get()) << "wrap: with Data -> different ptr";
        auto *pv = dynamic_cast<psm::transport::preview *>(Result.get());
        EXPECT_NE(pv, nullptr) << "wrap: Result is Preview";
        EXPECT_TRUE(pv->next_layer() == mock.get()) << "wrap: Preview wraps mock";
    }

    // ─── completion-handler async_read_some 测试 ──

    TEST(PreviewDeep, CompletionReadWithPreread)
    {
        auto mock = make_mock();
        const std::byte preread_data[] = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}};
        psm::transport::preview p(psm::transport::shared_transmission(mock), preread_data);

        std::byte buf[8]{};
        boost::system::error_code result_ec;
        std::size_t result_n = 0;
        bool called = false;

        p.async_read_some(std::span<std::byte>{buf, 4},
                          [&](boost::system::error_code ec, std::size_t n)
                          {
                              result_ec = ec;
                              result_n = n;
                              called = true;
                          });

        EXPECT_TRUE(called) << "completion_read: handler called immediately with preread";
        EXPECT_TRUE(!result_ec) << "completion_read: no Error";
        EXPECT_EQ(result_n, 3) << "completion_read: 3 Bytes from preread";
        EXPECT_EQ(buf[0], std::byte{0xAA}) << "completion_read: byte 0 correct";
        EXPECT_EQ(buf[1], std::byte{0xBB}) << "completion_read: byte 1 correct";
        EXPECT_EQ(buf[2], std::byte{0xCC}) << "completion_read: byte 2 correct";
    }

    TEST(PreviewDeep, CompletionReadPrereadExhaustedThenMockInner)
    {
        auto mock = make_mock();
        const std::byte preread_data[] = {std::byte{0x01}};
        psm::transport::preview p(psm::transport::shared_transmission(mock), preread_data);

        // 消耗 preread
        std::byte buf1[4]{};
        bool called1 = false;
        p.async_read_some(std::span<std::byte>{buf1, 4},
                          [&](boost::system::error_code, std::size_t) { called1 = true; });
        EXPECT_TRUE(called1) << "completion_read_exhaust: first Read Done";

        // 第二次读 → preread 已耗尽，委托给 mock Inner
        // mock 有 io_context，需要 Run 才能完成
        std::byte buf2[4]{};
        bool called2 = false;
        boost::system::error_code result_ec2;
        p.async_read_some(std::span<std::byte>{buf2, 4},
                          [&](boost::system::error_code ec, std::size_t)
                          {
                              result_ec2 = ec;
                              called2 = true;
                          });

        // 注入数据让 mock 完成
        mock->InjectRead(std::vector<std::byte>(2, std::byte{0x55}));
        mock->GetIoContext().run();

        EXPECT_TRUE(called2) << "completion_read_exhaust: second Read completed";
        EXPECT_TRUE(!result_ec2) << "completion_read_exhaust: second Read no Error";
    }

    TEST(PreviewDeep, CompletionReadNullInnerNoPreread)
    {
        psm::transport::preview p(nullptr, std::span<const std::byte>{});

        std::byte buf[4]{};
        boost::system::error_code result_ec;
        std::size_t result_n = 99;
        bool called = false;

        p.async_read_some(std::span<std::byte>{buf, 4},
                          [&](boost::system::error_code ec, std::size_t n)
                          {
                              result_ec = ec;
                              result_n = n;
                              called = true;
                          });

        EXPECT_TRUE(called) << "completion_read_null: handler called";
        EXPECT_NE(result_ec.value(), 0) << "completion_read_null: Error set";
        EXPECT_EQ(result_n, 0) << "completion_read_null: 0 Bytes";
    }

    // ─── completion-handler async_write_some 测试 ──

    TEST(PreviewDeep, CompletionWriteNullInner)
    {
        psm::transport::preview p(nullptr, std::span<const std::byte>{});

        const std::byte Data[] = {std::byte{0x01}};
        boost::system::error_code result_ec;
        std::size_t result_n = 99;
        bool called = false;

        p.async_write_some(std::span<const std::byte>{Data, 1},
                           [&](boost::system::error_code ec, std::size_t n)
                           {
                               result_ec = ec;
                               result_n = n;
                               called = true;
                           });

        EXPECT_TRUE(called) << "completion_write_null: handler called";
        EXPECT_NE(result_ec.value(), 0) << "completion_write_null: Error set";
        EXPECT_EQ(result_n, 0) << "completion_write_null: 0 Bytes";
    }

    TEST(PreviewDeep, CompletionWriteValidInner)
    {
        auto mock = make_mock();
        psm::transport::preview p(psm::transport::shared_transmission(mock), std::span<const std::byte>{});

        const std::byte Data[] = {std::byte{0xAA}, std::byte{0xBB}};
        boost::system::error_code result_ec;
        std::size_t result_n = 0;
        bool called = false;

        p.async_write_some(std::span<const std::byte>{Data, 2},
                           [&](boost::system::error_code ec, std::size_t n)
                           {
                               result_ec = ec;
                               result_n = n;
                               called = true;
                           });

        // mock 的 async_write_some 需要 io_context Run
        mock->GetIoContext().run();
        EXPECT_TRUE(called) << "completion_write: handler called";
        EXPECT_TRUE(!result_ec) << "completion_write: no Error";
        EXPECT_EQ(result_n, 2) << "completion_write: 2 Bytes";
    }

    // ─── lowest_layer 测试 ────────────────────

    TEST(PreviewDeep, lowest_layer)
    {
        auto mock = make_mock();
        psm::transport::preview p(psm::transport::shared_transmission(mock), std::span<const std::byte>{});
        auto *ll = p.lowest_layer<ProductionMockTransport>();
        EXPECT_EQ(ll, mock.get()) << "lowest_layer: navigates to mock";
    }

    TEST(PreviewDeep, LowestLayerNull)
    {
        psm::transport::preview p(nullptr, std::span<const std::byte>{});
        auto *ll = p.lowest_layer<psm::transport::transmission>();
        EXPECT_EQ(ll, &p) << "lowest_layer: null Inner -> self";
    }

} // namespace
