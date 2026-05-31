/**
 * @file PreviewTransport.cpp
 * @brief transport::preview 预读回放传输层测试
 * @details 通过 MockTransport 驱动 preview 的读写、关闭、取消操作，
 *          验证预读缓冲区回放、耗尽后委托、空 inner 降级路径。
 */

#include <prism/memory.hpp>
#include <prism/transport/preview.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"
#include "common/MockTransport.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

using psm::testing::TestRunner;
using psm::testing::MockTransport;

namespace
{
    namespace transport = psm::transport;
    namespace net = boost::asio;

    // ─── 构造 + transport_type ──────────────────────

    void TestPreviewTransportType(TestRunner &runner)
    {
        auto mock = std::make_shared<MockTransport>();
        std::array<std::byte, 4> preread{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
        auto pv = std::make_shared<transport::preview>(mock, preread, psm::memory::current_resource());

        runner.Check(pv->transport_type() == transport::transmission::type::tcp,
                     "preview: transport_type == tcp");
    }

    void TestPreviewNextLayer(TestRunner &runner)
    {
        auto mock = std::make_shared<MockTransport>();
        std::array<std::byte, 2> preread{std::byte{0xAA}, std::byte{0xBB}};
        auto pv = std::make_shared<transport::preview>(mock, preread);

        runner.Check(pv->next_layer() != nullptr, "preview: next_layer != null");
        runner.Check(pv->next_layer() == mock.get(), "preview: next_layer == mock");
        runner.Check(pv->inner() == mock, "preview: inner() == mock");
    }

    void TestPreviewExecutor(TestRunner &runner)
    {
        auto mock = std::make_shared<MockTransport>();
        std::array<std::byte, 2> preread{};
        auto pv = std::make_shared<transport::preview>(mock, preread);

        auto ex = pv->executor();
        runner.Check(ex != net::any_io_executor{}, "preview: executor valid");
    }

    // ─── async_read_some 预读回放 ───────────────────

    void TestPreviewReadFromPreread(TestRunner &runner)
    {
        auto mock = std::make_shared<MockTransport>();
        std::array<std::byte, 4> preread{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
        auto pv = std::make_shared<transport::preview>(mock, preread);

        std::array<std::byte, 4> buf{};
        bool done = false;

        auto read_task = [&]() -> net::awaitable<void>
        {
            std::error_code ec;
            auto n = co_await pv->async_read_some(buf, ec);
            runner.Check(!ec, "preview read: no error");
            runner.Check(n == 4, "preview read: read 4 bytes from preread");
            runner.Check(buf[0] == std::byte{0x01}, "preview read: buf[0] correct");
            runner.Check(buf[3] == std::byte{0x04}, "preview read: buf[3] correct");
            done = true;
        };

        net::co_spawn(mock->get_io_context(), read_task(), net::detached);
        mock->get_io_context().run();
        runner.Check(done, "preview read: completed");
    }

    void TestPreviewReadPartial(TestRunner &runner)
    {
        auto mock = std::make_shared<MockTransport>();
        std::array<std::byte, 4> preread{std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};
        auto pv = std::make_shared<transport::preview>(mock, preread);

        // 读取 2 字节 → 消耗一半 preread
        std::array<std::byte, 2> buf1{};
        std::array<std::byte, 2> buf2{};
        int phase = 0;

        auto read_task = [&]() -> net::awaitable<void>
        {
            std::error_code ec;
            auto n1 = co_await pv->async_read_some(buf1, ec);
            runner.Check(n1 == 2, "partial read 1: 2 bytes");
            runner.Check(buf1[0] == std::byte{0xAA}, "partial read 1: buf[0]=0xAA");
            phase = 1;

            auto n2 = co_await pv->async_read_some(buf2, ec);
            runner.Check(n2 == 2, "partial read 2: 2 bytes");
            runner.Check(buf2[0] == std::byte{0xCC}, "partial read 2: buf[0]=0xCC");
            phase = 2;
        };

        net::co_spawn(mock->get_io_context(), read_task(), net::detached);
        mock->get_io_context().run();
        runner.Check(phase == 2, "partial read: both phases completed");
    }

    void TestPreviewReadDelegatesToInner(TestRunner &runner)
    {
        auto mock = std::make_shared<MockTransport>();
        // 空 preread → 直接委托 inner
        auto pv = std::make_shared<transport::preview>(mock, std::span<const std::byte>{});

        mock->inject_read(std::vector<std::byte>{std::byte{0x99}, std::byte{0x88}});

        std::array<std::byte, 4> buf{};
        bool done = false;

        auto read_task = [&]() -> net::awaitable<void>
        {
            std::error_code ec;
            auto n = co_await pv->async_read_some(buf, ec);
            runner.Check(!ec, "delegate read: no error");
            runner.Check(n == 2, "delegate read: 2 bytes from mock");
            runner.Check(buf[0] == std::byte{0x99}, "delegate read: buf[0]=0x99");
            done = true;
        };

        net::co_spawn(mock->get_io_context(), read_task(), net::detached);
        mock->get_io_context().run();
        runner.Check(done, "delegate read: completed");
    }

    // ─── async_write_some ──────────────────────────

    void TestPreviewWrite(TestRunner &runner)
    {
        auto mock = std::make_shared<MockTransport>();
        std::array<std::byte, 2> preread{};
        auto pv = std::make_shared<transport::preview>(mock, preread);

        std::array<std::byte, 3> data{std::byte{0x11}, std::byte{0x22}, std::byte{0x33}};
        bool done = false;

        auto write_task = [&]() -> net::awaitable<void>
        {
            std::error_code ec;
            auto n = co_await pv->async_write_some(data, ec);
            runner.Check(!ec, "write: no error");
            runner.Check(n == 3, "write: 3 bytes");
            done = true;
        };

        net::co_spawn(mock->get_io_context(), write_task(), net::detached);
        mock->get_io_context().run();
        runner.Check(done, "write: completed");
        runner.Check(mock->written_data().size() == 3, "write: mock captured 3 bytes");
        runner.Check(mock->written_data()[0] == std::byte{0x11}, "write: byte 0 correct");
    }

    // ─── close / cancel ────────────────────────────

    void TestPreviewClose(TestRunner &runner)
    {
        auto mock = std::make_shared<MockTransport>();
        std::array<std::byte, 2> preread{};
        auto pv = std::make_shared<transport::preview>(mock, preread);

        runner.Check(!mock->is_closed(), "before close: mock not closed");
        pv->close();
        runner.Check(mock->is_closed(), "after close: mock closed");
    }

    void TestPreviewCancel(TestRunner &runner)
    {
        auto mock = std::make_shared<MockTransport>();
        std::array<std::byte, 2> preread{};
        auto pv = std::make_shared<transport::preview>(mock, preread);

        runner.Check(!mock->is_cancelled(), "before cancel: mock not cancelled");
        pv->cancel();
        runner.Check(mock->is_cancelled(), "after cancel: mock cancelled");
    }

    // ─── wrap_with_preview ─────────────────────────

    void TestWrapWithPreviewData(TestRunner &runner)
    {
        auto mock = std::make_shared<MockTransport>();
        std::array<std::byte, 3> data{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};

        auto wrapped = transport::wrap_with_preview(mock, data);
        runner.Check(wrapped != mock, "wrap: returns different pointer");
        auto *inner = wrapped->next_layer();
        runner.Check(inner != nullptr, "wrap: has next_layer");
    }

    void TestWrapWithPreviewEmpty(TestRunner &runner)
    {
        auto mock = std::make_shared<MockTransport>();
        auto wrapped = transport::wrap_with_preview(mock, std::span<const std::byte>{});
        runner.Check(wrapped == mock, "wrap empty: returns same pointer");
    }

    // ─── write 错误：inner 为空 ────────────────────

    void TestPreviewWriteNullInner(TestRunner &runner)
    {
        // 用空 preread 构造，inner=nullptr
        auto pv = std::make_shared<transport::preview>(nullptr, std::span<const std::byte>{});

        std::array<std::byte, 2> data{std::byte{0x01}, std::byte{0x02}};
        bool done = false;

        auto write_task = [&]() -> net::awaitable<void>
        {
            std::error_code ec;
            auto n = co_await pv->async_write_some(data, ec);
            runner.Check(ec == std::make_error_code(std::errc::bad_file_descriptor),
                         "write null: bad_file_descriptor");
            runner.Check(n == 0, "write null: 0 bytes");
            done = true;
        };

        net::io_context ioc;
        // preview 需要 executor，但 inner 为空时直接返回错误不会用 executor
        // 需要 executor 是因为 async_write_some 需要协程支持
        // 直接跑协程会失败因为 inner=nullptr → executor() 返回空
        // 改为通过 co_spawn 手动跑
        net::co_spawn(ioc, write_task(), net::detached);
        ioc.run();
        runner.Check(done, "write null: completed");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("PreviewTransport");

    TestPreviewTransportType(runner);
    TestPreviewNextLayer(runner);
    TestPreviewExecutor(runner);
    TestPreviewReadFromPreread(runner);
    TestPreviewReadPartial(runner);
    TestPreviewReadDelegatesToInner(runner);
    TestPreviewWrite(runner);
    TestPreviewClose(runner);
    TestPreviewCancel(runner);
    TestWrapWithPreviewData(runner);
    TestWrapWithPreviewEmpty(runner);
    TestPreviewWriteNullInner(runner);

    return runner.Summary();
}
