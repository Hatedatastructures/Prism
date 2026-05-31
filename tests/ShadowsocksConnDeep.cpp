/**
 * @file ShadowsocksConnDeep.cpp
 * @brief SS2022 conn 深度纯函数测试
 * @details 通过 #include 源文件访问 conn.cpp 中所有编译行，覆盖
 *          构造函数、close/cancel、executor、next_layer、target 等公开接口。
 *          derive_aead_context 为 private，通过已有的 ShadowsocksConnPure 测试逻辑验证。
 *          协程方法（handshake/read/write）不在本测试范围。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/MockTransport.hpp"
#include "common/TestRunner.hpp"

#include "../src/prism/protocol/shadowsocks/conn.cpp"

using psm::testing::TestRunner;
using psm::testing::MockTransport;

namespace
{
    namespace ss = psm::protocol::shadowsocks;

    // base64 编码的 16 字节全零 PSK
    consteval auto psk128_b64() -> const char *
    {
        return "AAAAAAAAAAAAAAAAAAAAAA==";
    }

    // base64 编码的 32 字节全零 PSK
    consteval auto psk256_b64() -> const char *
    {
        return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    }

    auto make_mock_transport() -> std::shared_ptr<MockTransport>
    {
        return std::make_shared<MockTransport>();
    }

    auto make_salts() -> std::shared_ptr<ss::salt_pool>
    {
        return std::make_shared<ss::salt_pool>();
    }

    // ─── 构造函数 ──────────────────────────────

    void TestConnConstructAes128(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));
        runner.Check(true, "conn: construct aes-128 no crash");
    }

    void TestConnConstructAes256(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = psk256_b64();
        cfg.method = "2022-blake3-aes-256-gcm";

        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));
        runner.Check(true, "conn: construct aes-256 no crash");
    }

    void TestConnConstructChaCha20(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = psk256_b64();
        cfg.method = "2022-blake3-chacha20-poly1305";

        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));
        runner.Check(true, "conn: construct chacha20 no crash");
    }

    void TestConnConstructInvalidPsk(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = "!!!invalid-base64!!!";

        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));
        runner.Check(true, "conn: invalid PSK handled gracefully");
    }

    void TestConnConstructEmptyPsk(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = "";

        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));
        runner.Check(true, "conn: empty PSK handled gracefully");
    }

    void TestConnConfigFields(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();
        cfg.enable_tcp = false;
        cfg.enable_udp = true;
        cfg.timestamp_window = 120;
        cfg.salt_ttl = 300;
        cfg.idle_timeout = 180;

        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));
        runner.Check(true, "conn: custom config fields no crash");
    }

    // ─── close / cancel ────────────────────────

    void TestConnClose(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));
        c.close();
        runner.Check(true, "conn: close no crash");
    }

    void TestConnCancel(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));
        c.cancel();
        runner.Check(true, "conn: cancel no crash");
    }

    void TestConnCloseIdempotent(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));
        c.close();
        c.close();
        c.close();
        runner.Check(true, "conn: multiple close no crash");
    }

    void TestConnCancelThenClose(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));
        c.cancel();
        c.close();
        runner.Check(true, "conn: cancel then close no crash");
    }

    // ─── next_layer ────────────────────────────

    void TestConnNextLayer(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = make_mock_transport();
        auto *raw = mock.get();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        auto *nl = c.next_layer();
        runner.Check(nl != nullptr, "conn: next_layer not null");
        runner.Check(nl == raw, "conn: next_layer points to original transport");
    }

    void TestConnNextLayerConst(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = make_mock_transport();
        auto *raw = mock.get();
        auto salts = make_salts();
        const ss::conn c(std::move(mock), cfg, std::move(salts));

        const auto *nl = c.next_layer();
        runner.Check(nl != nullptr, "conn: const next_layer not null");
        runner.Check(nl == raw, "conn: const next_layer points to original transport");
    }

    // ─── target() 访问器 ───────────────────────

    void TestConnTargetDefault(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        const auto &t = c.target();
        runner.Check(t.host.empty(), "conn: default target host empty");
        runner.Check(t.port == "80", "conn: default target port is 80");
    }

    // ─── executor ──────────────────────────────

    void TestConnExecutor(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = make_mock_transport();
        auto salts = make_salts();
        ss::conn c(std::move(mock), cfg, std::move(salts));

        auto ex = c.executor();
        (void)ex;
        runner.Check(true, "conn: executor() no crash");
    }

    // ─── make_conn 工厂函数 ────────────────────

    void TestMakeConnFactory(TestRunner &runner)
    {
        ss::config cfg;
        cfg.psk = psk128_b64();

        auto mock = make_mock_transport();
        auto salts = make_salts();
        auto c = ss::make_conn(std::move(mock), cfg, std::move(salts));
        runner.Check(c != nullptr, "make_conn: returns non-null shared_ptr");
        runner.Check(c->next_layer() != nullptr, "make_conn: next_layer accessible");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("ShadowsocksConnDeep");

    TestConnConstructAes128(runner);
    TestConnConstructAes256(runner);
    TestConnConstructChaCha20(runner);
    TestConnConstructInvalidPsk(runner);
    TestConnConstructEmptyPsk(runner);
    TestConnConfigFields(runner);

    TestConnClose(runner);
    TestConnCancel(runner);
    TestConnCloseIdempotent(runner);
    TestConnCancelThenClose(runner);

    TestConnNextLayer(runner);
    TestConnNextLayerConst(runner);

    TestConnTargetDefault(runner);
    TestConnExecutor(runner);

    TestMakeConnFactory(runner);

    return runner.Summary();
}
