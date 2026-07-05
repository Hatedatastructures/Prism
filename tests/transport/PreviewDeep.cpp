/**
 * @file PreviewDeep.cpp
 * @brief transport/preview 深度纯函数测试
 * @details 通过 #include 源文件访问 preview.cpp 中所有同步函数，
 *          覆盖构造函数、executor、close、cancel、transport_type、
 *          next_layer、wrap_with_preview 以及 completion-handler 重载。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>


#include <gtest/gtest.h>
#include "common/MockTransport.hpp"

#include "../../src/prism/net/transport/preview.cpp"

using psm::testing::MockTransport;

namespace
{
    namespace transport = psm::transport;
    using transport::preview;
    using transport::shared_transmission;
    using transport::transmission;

    auto make_mock() -> std::shared_ptr<MockTransport>
    {
        return std::make_shared<MockTransport>();
    }

    // ─── 构造函数测试 ──────────────────────────

    TEST(PreviewDeep, ConstructWithData)
    {
        auto mock = make_mock();
        const std::byte data[] = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
        preview p(shared_transmission(mock), data);

        // 验证 next_layer 返回内部指针
        EXPECT_TRUE(p.next_layer() == mock.get()) << "construct: next_layer == mock";
        EXPECT_TRUE(p.inner() != nullptr) << "construct: inner not null";
    }

    TEST(PreviewDeep, ConstructEmptyData)
    {
        auto mock = make_mock();
        preview p(shared_transmission(mock), std::span<const std::byte>{});

        EXPECT_TRUE(p.next_layer() == mock.get()) << "construct: empty preread -> next_layer ok";
    }

    TEST(PreviewDeep, ConstructNullInner)
    {
        preview p(nullptr, std::span<const std::byte>{});

        EXPECT_TRUE(p.next_layer() == nullptr) << "construct: null inner -> next_layer null";
        EXPECT_TRUE(p.inner() == nullptr) << "construct: null inner -> inner null";
    }

    TEST(PreviewDeep, ConstructLargeData)
    {
        auto mock = make_mock();
        std::vector<std::byte> big(4096, std::byte{0xAA});
        preview p(shared_transmission(mock), std::span<const std::byte>{big.data(), big.size()});

        EXPECT_TRUE(p.next_layer() == mock.get()) << "construct: large preread -> ok";
    }

    // ─── executor() 测试 ──────────────────────

    TEST(PreviewDeep, ExecutorNullInner)
    {
        preview p(nullptr, std::span<const std::byte>{});
        auto ex = p.executor();
        // 空 executor（默认构造）
        EXPECT_TRUE(!ex) << "executor: null inner -> empty executor";
    }

    TEST(PreviewDeep, ExecutorValidInner)
    {
        auto mock = make_mock();
        auto mock_ex = mock->executor();
        preview p(shared_transmission(mock), std::span<const std::byte>{});
        auto ex = p.executor();
        EXPECT_TRUE(!!ex) << "executor: valid inner -> non-empty executor";
    }

    // ─── close() 测试 ─────────────────────────

    TEST(PreviewDeep, CloseNullInner)
    {
        preview p(nullptr, std::span<const std::byte>{});
        // close() 对 null inner 不应崩溃，且后续操作应安全
        p.close();
        p.close();
        EXPECT_TRUE(true) << "close: null inner -> idempotent, no crash";
    }

    TEST(PreviewDeep, CloseValidInner)
    {
        auto mock = make_mock();
        preview p(shared_transmission(mock), std::span<const std::byte>{});
        p.close();
        EXPECT_TRUE(mock->is_closed()) << "close: valid inner -> mock closed";
    }

    // ─── cancel() 测试 ────────────────────────

    TEST(PreviewDeep, CancelNullInner)
    {
        preview p(nullptr, std::span<const std::byte>{});
        p.cancel();
        p.cancel();
        EXPECT_TRUE(true) << "cancel: null inner -> idempotent, no crash";
    }

    TEST(PreviewDeep, CancelValidInner)
    {
        auto mock = make_mock();
        preview p(shared_transmission(mock), std::span<const std::byte>{});
        p.cancel();
        EXPECT_TRUE(mock->is_cancelled()) << "cancel: valid inner -> mock cancelled";
    }

    // ─── transport_type() 测试 ─────────────────

    TEST(PreviewDeep, TransportTypeNullInner)
    {
        preview p(nullptr, std::span<const std::byte>{});
        EXPECT_TRUE(p.transport_type() == transmission::type::tcp)
            << "transport_type: null inner -> tcp";
    }

    TEST(PreviewDeep, TransportTypeValidInner)
    {
        auto mock = make_mock();
        preview p(shared_transmission(mock), std::span<const std::byte>{});
        // MockTransport 使用默认 transport_type() → 沿 next_layer 链，最终返回 tcp
        EXPECT_TRUE(p.transport_type() == transmission::type::tcp)
            << "transport_type: mock inner -> tcp";
    }

    // ─── next_layer() 测试 ────────────────────

    TEST(PreviewDeep, NextLayerMutable)
    {
        auto mock = make_mock();
        preview p(shared_transmission(mock), std::span<const std::byte>{});
        auto *nl = p.next_layer();
        EXPECT_TRUE(nl == mock.get()) << "next_layer: mutable == mock";
    }

    TEST(PreviewDeep, NextLayerConst)
    {
        auto mock = make_mock();
        const preview p(shared_transmission(mock), std::span<const std::byte>{});
        const auto *nl = p.next_layer();
        EXPECT_TRUE(nl == mock.get()) << "next_layer: const == mock";
    }

    TEST(PreviewDeep, NextLayerNull)
    {
        preview p(nullptr, std::span<const std::byte>{});
        EXPECT_TRUE(p.next_layer() == nullptr) << "next_layer: null inner -> null";
    }

    // ─── inner() 测试 ─────────────────────────

    TEST(PreviewDeep, InnerReturnsSharedPtr)
    {
        auto mock = make_mock();
        preview p(shared_transmission(mock), std::span<const std::byte>{});
        auto inner = p.inner();
        EXPECT_TRUE(inner == mock) << "inner: returns same shared_ptr";
    }

    // ─── wrap_with_preview() 测试 ──────────────

    TEST(PreviewDeep, WrapWithPreviewEmptyData)
    {
        auto mock = make_mock();
        auto original = shared_transmission(mock);
        auto result = transport::wrap_with_preview(original, std::span<const std::byte>{});
        // data 为空 → 不包装，返回原始
        EXPECT_TRUE(result.get() == mock.get()) << "wrap: empty data -> original ptr";
    }

    TEST(PreviewDeep, WrapWithPreviewWithData)
    {
        auto mock = make_mock();
        auto original = shared_transmission(mock);
        const std::byte data[] = {std::byte{0x01}, std::byte{0x02}};
        auto result = transport::wrap_with_preview(original, data);
        // data 非空 → 包装为 preview
        EXPECT_TRUE(result.get() != mock.get()) << "wrap: with data -> different ptr";
        auto *pv = dynamic_cast<preview *>(result.get());
        EXPECT_TRUE(pv != nullptr) << "wrap: result is preview";
        EXPECT_TRUE(pv->next_layer() == mock.get()) << "wrap: preview wraps mock";
    }

    // ─── completion-handler async_read_some 测试 ──

    TEST(PreviewDeep, CompletionReadWithPreread)
    {
        auto mock = make_mock();
        const std::byte preread_data[] = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}};
        preview p(shared_transmission(mock), preread_data);

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
        EXPECT_TRUE(!result_ec) << "completion_read: no error";
        EXPECT_TRUE(result_n == 3) << "completion_read: 3 bytes from preread";
        EXPECT_TRUE(buf[0] == std::byte{0xAA}) << "completion_read: byte 0 correct";
        EXPECT_TRUE(buf[1] == std::byte{0xBB}) << "completion_read: byte 1 correct";
        EXPECT_TRUE(buf[2] == std::byte{0xCC}) << "completion_read: byte 2 correct";
    }

    TEST(PreviewDeep, CompletionReadPrereadExhaustedThenMockInner)
    {
        auto mock = make_mock();
        const std::byte preread_data[] = {std::byte{0x01}};
        preview p(shared_transmission(mock), preread_data);

        // 消耗 preread
        std::byte buf1[4]{};
        bool called1 = false;
        p.async_read_some(std::span<std::byte>{buf1, 4},
            [&](boost::system::error_code, std::size_t) { called1 = true; });
        EXPECT_TRUE(called1) << "completion_read_exhaust: first read done";

        // 第二次读 → preread 已耗尽，委托给 mock inner
        // mock 有 io_context，需要 run 才能完成
        std::byte buf2[4]{};
        bool called2 = false;
        boost::system::error_code result_ec2;
        p.async_read_some(std::span<std::byte>{buf2, 4},
            [&](boost::system::error_code ec, std::size_t) { result_ec2 = ec; called2 = true; });

        // 注入数据让 mock 完成
        mock->inject_read(std::vector<std::byte>(2, std::byte{0x55}));
        mock->get_io_context().run();

        EXPECT_TRUE(called2) << "completion_read_exhaust: second read completed";
        EXPECT_TRUE(!result_ec2) << "completion_read_exhaust: second read no error";
    }

    TEST(PreviewDeep, CompletionReadNullInnerNoPreread)
    {
        preview p(nullptr, std::span<const std::byte>{});

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
        EXPECT_TRUE(result_ec.value() != 0) << "completion_read_null: error set";
        EXPECT_TRUE(result_n == 0) << "completion_read_null: 0 bytes";
    }

    // ─── completion-handler async_write_some 测试 ──

    TEST(PreviewDeep, CompletionWriteNullInner)
    {
        preview p(nullptr, std::span<const std::byte>{});

        const std::byte data[] = {std::byte{0x01}};
        boost::system::error_code result_ec;
        std::size_t result_n = 99;
        bool called = false;

        p.async_write_some(std::span<const std::byte>{data, 1},
            [&](boost::system::error_code ec, std::size_t n)
            {
                result_ec = ec;
                result_n = n;
                called = true;
            });

        EXPECT_TRUE(called) << "completion_write_null: handler called";
        EXPECT_TRUE(result_ec.value() != 0) << "completion_write_null: error set";
        EXPECT_TRUE(result_n == 0) << "completion_write_null: 0 bytes";
    }

    TEST(PreviewDeep, CompletionWriteValidInner)
    {
        auto mock = make_mock();
        preview p(shared_transmission(mock), std::span<const std::byte>{});

        const std::byte data[] = {std::byte{0xAA}, std::byte{0xBB}};
        boost::system::error_code result_ec;
        std::size_t result_n = 0;
        bool called = false;

        p.async_write_some(std::span<const std::byte>{data, 2},
            [&](boost::system::error_code ec, std::size_t n)
            {
                result_ec = ec;
                result_n = n;
                called = true;
            });

        // mock 的 async_write_some 需要 io_context run
        mock->get_io_context().run();
        EXPECT_TRUE(called) << "completion_write: handler called";
        EXPECT_TRUE(!result_ec) << "completion_write: no error";
        EXPECT_TRUE(result_n == 2) << "completion_write: 2 bytes";
    }

    // ─── lowest_layer 测试 ────────────────────

    TEST(PreviewDeep, LowestLayer)
    {
        auto mock = make_mock();
        preview p(shared_transmission(mock), std::span<const std::byte>{});
        auto *ll = p.lowest_layer<MockTransport>();
        EXPECT_TRUE(ll == mock.get()) << "lowest_layer: navigates to mock";
    }

    TEST(PreviewDeep, LowestLayerNull)
    {
        preview p(nullptr, std::span<const std::byte>{});
        auto *ll = p.lowest_layer<transmission>();
        EXPECT_TRUE(ll == &p) << "lowest_layer: null inner -> self";
    }

} // namespace
