/**
 * @file PreviewDeep.cpp
 * @brief transport/preview 深度纯函数测试
 * @details 通过 #include 源文件访问 preview.cpp 中所有同步函数，
 *          覆盖构造函数、executor、close、cancel、transport_type、
 *          next_layer、wrap_with_preview 以及 completion-handler 重载。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"
#include "common/MockTransport.hpp"

#include "../src/prism/transport/preview.cpp"

using psm::testing::TestRunner;
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

    void TestConstructWithData(TestRunner &runner)
    {
        auto mock = make_mock();
        const std::byte data[] = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
        preview p(shared_transmission(mock), data);

        // 验证 next_layer 返回内部指针
        runner.Check(p.next_layer() == mock.get(), "construct: next_layer == mock");
        runner.Check(p.inner() != nullptr, "construct: inner not null");
    }

    void TestConstructEmptyData(TestRunner &runner)
    {
        auto mock = make_mock();
        preview p(shared_transmission(mock), std::span<const std::byte>{});

        runner.Check(p.next_layer() == mock.get(), "construct: empty preread -> next_layer ok");
    }

    void TestConstructNullInner(TestRunner &runner)
    {
        preview p(nullptr, std::span<const std::byte>{});

        runner.Check(p.next_layer() == nullptr, "construct: null inner -> next_layer null");
        runner.Check(p.inner() == nullptr, "construct: null inner -> inner null");
    }

    void TestConstructLargeData(TestRunner &runner)
    {
        auto mock = make_mock();
        std::vector<std::byte> big(4096, std::byte{0xAA});
        preview p(shared_transmission(mock), std::span<const std::byte>{big.data(), big.size()});

        runner.Check(p.next_layer() == mock.get(), "construct: large preread -> ok");
    }

    // ─── executor() 测试 ──────────────────────

    void TestExecutorNullInner(TestRunner &runner)
    {
        preview p(nullptr, std::span<const std::byte>{});
        auto ex = p.executor();
        // 空 executor（默认构造）
        runner.Check(!ex, "executor: null inner -> empty executor");
    }

    void TestExecutorValidInner(TestRunner &runner)
    {
        auto mock = make_mock();
        auto mock_ex = mock->executor();
        preview p(shared_transmission(mock), std::span<const std::byte>{});
        auto ex = p.executor();
        runner.Check(!!ex, "executor: valid inner -> non-empty executor");
    }

    // ─── close() 测试 ─────────────────────────

    void TestCloseNullInner(TestRunner &runner)
    {
        preview p(nullptr, std::span<const std::byte>{});
        // 不崩溃
        p.close();
        runner.Check(true, "close: null inner -> no crash");
    }

    void TestCloseValidInner(TestRunner &runner)
    {
        auto mock = make_mock();
        preview p(shared_transmission(mock), std::span<const std::byte>{});
        p.close();
        runner.Check(mock->is_closed(), "close: valid inner -> mock closed");
    }

    // ─── cancel() 测试 ────────────────────────

    void TestCancelNullInner(TestRunner &runner)
    {
        preview p(nullptr, std::span<const std::byte>{});
        p.cancel();
        runner.Check(true, "cancel: null inner -> no crash");
    }

    void TestCancelValidInner(TestRunner &runner)
    {
        auto mock = make_mock();
        preview p(shared_transmission(mock), std::span<const std::byte>{});
        p.cancel();
        runner.Check(mock->is_cancelled(), "cancel: valid inner -> mock cancelled");
    }

    // ─── transport_type() 测试 ─────────────────

    void TestTransportTypeNullInner(TestRunner &runner)
    {
        preview p(nullptr, std::span<const std::byte>{});
        runner.Check(p.transport_type() == transmission::type::tcp,
                     "transport_type: null inner -> tcp");
    }

    void TestTransportTypeValidInner(TestRunner &runner)
    {
        auto mock = make_mock();
        preview p(shared_transmission(mock), std::span<const std::byte>{});
        // MockTransport 使用默认 transport_type() → 沿 next_layer 链，最终返回 tcp
        runner.Check(p.transport_type() == transmission::type::tcp,
                     "transport_type: mock inner -> tcp");
    }

    // ─── next_layer() 测试 ────────────────────

    void TestNextLayerMutable(TestRunner &runner)
    {
        auto mock = make_mock();
        preview p(shared_transmission(mock), std::span<const std::byte>{});
        auto *nl = p.next_layer();
        runner.Check(nl == mock.get(), "next_layer: mutable == mock");
    }

    void TestNextLayerConst(TestRunner &runner)
    {
        auto mock = make_mock();
        const preview p(shared_transmission(mock), std::span<const std::byte>{});
        const auto *nl = p.next_layer();
        runner.Check(nl == mock.get(), "next_layer: const == mock");
    }

    void TestNextLayerNull(TestRunner &runner)
    {
        preview p(nullptr, std::span<const std::byte>{});
        runner.Check(p.next_layer() == nullptr, "next_layer: null inner -> null");
    }

    // ─── inner() 测试 ─────────────────────────

    void TestInnerReturnsSharedPtr(TestRunner &runner)
    {
        auto mock = make_mock();
        preview p(shared_transmission(mock), std::span<const std::byte>{});
        auto inner = p.inner();
        runner.Check(inner == mock, "inner: returns same shared_ptr");
    }

    // ─── wrap_with_preview() 测试 ──────────────

    void TestWrapWithPreviewEmptyData(TestRunner &runner)
    {
        auto mock = make_mock();
        auto original = shared_transmission(mock);
        auto result = transport::wrap_with_preview(original, std::span<const std::byte>{});
        // data 为空 → 不包装，返回原始
        runner.Check(result.get() == mock.get(), "wrap: empty data -> original ptr");
    }

    void TestWrapWithPreviewWithData(TestRunner &runner)
    {
        auto mock = make_mock();
        auto original = shared_transmission(mock);
        const std::byte data[] = {std::byte{0x01}, std::byte{0x02}};
        auto result = transport::wrap_with_preview(original, data);
        // data 非空 → 包装为 preview
        runner.Check(result.get() != mock.get(), "wrap: with data -> different ptr");
        auto *pv = dynamic_cast<preview *>(result.get());
        runner.Check(pv != nullptr, "wrap: result is preview");
        runner.Check(pv->next_layer() == mock.get(), "wrap: preview wraps mock");
    }

    // ─── completion-handler async_read_some 测试 ──

    void TestCompletionReadWithPreread(TestRunner &runner)
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

        runner.Check(called, "completion_read: handler called immediately with preread");
        runner.Check(!result_ec, "completion_read: no error");
        runner.Check(result_n == 3, "completion_read: 3 bytes from preread");
        runner.Check(buf[0] == std::byte{0xAA}, "completion_read: byte 0 correct");
        runner.Check(buf[1] == std::byte{0xBB}, "completion_read: byte 1 correct");
        runner.Check(buf[2] == std::byte{0xCC}, "completion_read: byte 2 correct");
    }

    void TestCompletionReadPrereadExhaustedThenNullInner(TestRunner &runner)
    {
        auto mock = make_mock();
        const std::byte preread_data[] = {std::byte{0x01}};
        preview p(shared_transmission(mock), preread_data);

        // 消耗 preread
        std::byte buf1[4]{};
        bool called1 = false;
        p.async_read_some(std::span<std::byte>{buf1, 4},
            [&](boost::system::error_code, std::size_t) { called1 = true; });
        runner.Check(called1, "completion_read_exhaust: first read done");

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

        runner.Check(called2, "completion_read_exhaust: second read completed");
        runner.Check(!result_ec2, "completion_read_exhaust: second read no error");
    }

    void TestCompletionReadNullInnerNoPreread(TestRunner &runner)
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

        runner.Check(called, "completion_read_null: handler called");
        runner.Check(result_ec.value() != 0, "completion_read_null: error set");
        runner.Check(result_n == 0, "completion_read_null: 0 bytes");
    }

    // ─── completion-handler async_write_some 测试 ──

    void TestCompletionWriteNullInner(TestRunner &runner)
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

        runner.Check(called, "completion_write_null: handler called");
        runner.Check(result_ec.value() != 0, "completion_write_null: error set");
        runner.Check(result_n == 0, "completion_write_null: 0 bytes");
    }

    void TestCompletionWriteValidInner(TestRunner &runner)
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
        runner.Check(called, "completion_write: handler called");
        runner.Check(!result_ec, "completion_write: no error");
        runner.Check(result_n == 2, "completion_write: 2 bytes");
    }

    // ─── lowest_layer 测试 ────────────────────

    void TestLowestLayer(TestRunner &runner)
    {
        auto mock = make_mock();
        preview p(shared_transmission(mock), std::span<const std::byte>{});
        auto *ll = p.lowest_layer<MockTransport>();
        runner.Check(ll == mock.get(), "lowest_layer: navigates to mock");
    }

    void TestLowestLayerNull(TestRunner &runner)
    {
        preview p(nullptr, std::span<const std::byte>{});
        auto *ll = p.lowest_layer<transmission>();
        runner.Check(ll == &p, "lowest_layer: null inner -> self");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("PreviewDeep");

    TestConstructWithData(runner);
    TestConstructEmptyData(runner);
    TestConstructNullInner(runner);
    TestConstructLargeData(runner);

    TestExecutorNullInner(runner);
    TestExecutorValidInner(runner);

    TestCloseNullInner(runner);
    TestCloseValidInner(runner);

    TestCancelNullInner(runner);
    TestCancelValidInner(runner);

    TestTransportTypeNullInner(runner);
    TestTransportTypeValidInner(runner);

    TestNextLayerMutable(runner);
    TestNextLayerConst(runner);
    TestNextLayerNull(runner);

    TestInnerReturnsSharedPtr(runner);

    TestWrapWithPreviewEmptyData(runner);
    TestWrapWithPreviewWithData(runner);

    TestCompletionReadWithPreread(runner);
    TestCompletionReadPrereadExhaustedThenNullInner(runner);
    TestCompletionReadNullInnerNoPreread(runner);

    TestCompletionWriteNullInner(runner);
    TestCompletionWriteValidInner(runner);

    TestLowestLayer(runner);
    TestLowestLayerNull(runner);

    return runner.Summary();
}
