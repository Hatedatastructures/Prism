/**
 * @file PipelinePrimitives.cpp
 * @brief 管道原语单元测试
 * @details 验证 psm::pipeline::primitives 命名空间下的核心功能，包括：
 * 1. is_mux_target() 对 mux 标记地址的检测逻辑
 * 2. preview 预读回放包装器的构造与基本属性
 * 3. probe_result 探测结果辅助方法的正确性
 */

#include <prism/memory.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/recognition/probe/probe.hpp>
#include <prism/trace/spdlog.hpp>

#include "common/TestRunner.hpp"

#include <array>
#include <cstddef>
#include <memory>
#include <string_view>

#include <boost/asio.hpp>

namespace net = boost::asio;

namespace
{
    psm::testing::TestRunner runner("PipelinePrimitives");
} // namespace

// ============================================================================
// is_mux_target 测试
// ============================================================================

/**
 * @brief 测试 is_mux_target() 对 mux 标记地址的检测
 * @details 覆盖以下场景：
 * - mux 启用 + 匹配的 .mux.sing-box.arpa 后缀 -> true
 * - mux 启用 + 非匹配主机名 -> false
 * - mux 禁用 -> false（无论主机名如何）
 * - 边界情况：空主机名、恰好等于后缀、后缀前多一个字符
 */
void TestIsMuxTarget()
{
    runner.LogInfo("=== TestIsMuxTarget ===");

    using psm::pipeline::primitives::is_mux_target;

    // mux 启用 + 匹配的 mux 标记地址 -> true
    runner.Check(
        is_mux_target("example.mux.sing-box.arpa", true) == true,
        "mux enabled + matching host -> true");

    // mux 启用 + 嵌套子域名 -> true
    runner.Check(
        is_mux_target("foo.bar.mux.sing-box.arpa", true) == true,
        "mux enabled + nested subdomain -> true");

    // mux 启用 + 恰好等于后缀 -> true
    runner.Check(
        is_mux_target(".mux.sing-box.arpa", true) == true,
        "mux enabled + exactly suffix -> true");

    // mux 启用 + 非匹配主机名 -> false
    runner.Check(
        is_mux_target("example.com", true) == false,
        "mux enabled + non-matching host -> false");

    // mux 启用 + 类似但不匹配的后缀 -> false
    runner.Check(
        is_mux_target("mux.sing-box.arpa", true) == false,
        "mux enabled + missing leading dot -> false");

    // mux 启用 + 拼写错误的后缀 -> false
    runner.Check(
        is_mux_target("example.mux.singbox.arpa", true) == false,
        "mux enabled + misspelled suffix -> false");

    // mux 启用 + 空主机名 -> false
    runner.Check(
        is_mux_target("", true) == false,
        "mux enabled + empty host -> false");

    // mux 启用 + 后缀的前缀（比后缀短） -> false
    runner.Check(
        is_mux_target("sing-box.arpa", true) == false,
        "mux enabled + partial suffix -> false");

    // mux 禁用 + 匹配的 mux 标记地址 -> false
    runner.Check(
        is_mux_target("example.mux.sing-box.arpa", false) == false,
        "mux disabled + matching host -> false");

    // mux 禁用 + 任意主机名 -> false
    runner.Check(
        is_mux_target("anything", false) == false,
        "mux disabled + any host -> false");

    runner.LogPass("TestIsMuxTarget");
}

// ============================================================================
// preview 构造测试
// ============================================================================

/**
 * @brief 简易 mock transmission，用于 preview 构造测试
 * @details 提供最小的 transmission 实现，仅返回一个 valid executor，
 * 不涉及任何网络 I/O。
 */
class mock_transmission final : public psm::channel::transport::transmission
{
public:
    explicit mock_transmission(net::io_context &ioc)
        : ioc_(ioc)
    {
    }

    [[nodiscard]] bool is_reliable() const noexcept override { return true; }

    [[nodiscard]] executor_type executor() const override
    {
        return ioc_.get_executor();
    }

    auto async_read_some(std::span<std::byte>, std::error_code &ec)
        -> net::awaitable<std::size_t> override
    {
        ec = std::make_error_code(std::errc::operation_not_supported);
        co_return 0;
    }

    auto async_write_some(std::span<const std::byte>, std::error_code &ec)
        -> net::awaitable<std::size_t> override
    {
        ec = std::make_error_code(std::errc::operation_not_supported);
        co_return 0;
    }

    void close() override {}
    void cancel() override {}

private:
    net::io_context &ioc_;
};

/**
 * @brief 测试 preview 包装器的构造与非协程基本属性
 * @details 验证 preview 可正确构造，is_reliable() 和 executor()
 * 正确委托给内部传输对象。
 */
void TestPreviewConstruction()
{
    runner.LogInfo("=== TestPreviewConstruction ===");

    namespace pp = psm::pipeline::primitives;

    net::io_context ioc;

    // 构造内部 mock 传输
    auto inner = std::make_shared<mock_transmission>(ioc);

    // 构造预读数据
    constexpr std::string_view sample_data = "GET / HTTP/1.1\r\n";
    const auto byte_span = std::span<const std::byte>(
        reinterpret_cast<const std::byte *>(sample_data.data()),
        sample_data.size());

    // 构造 preview
    auto preview = std::make_shared<pp::preview>(inner, byte_span);

    // 验证 is_reliable 委托给内部传输
    runner.Check(
        preview->is_reliable() == true,
        "preview::is_reliable() delegates to inner");

    // 验证 executor 委托给内部传输
    runner.Check(
        preview->executor() == inner->executor(),
        "preview::executor() delegates to inner");

    // 测试空预读数据的 preview 构造
    auto inner2 = std::make_shared<mock_transmission>(ioc);
    const auto empty_span = std::span<const std::byte>();
    auto preview2 = std::make_shared<pp::preview>(inner2, empty_span);

    runner.Check(
        preview2->is_reliable() == true,
        "preview with empty preread is_reliable()");

    runner.Check(
        preview2->executor() == inner2->executor(),
        "preview with empty preread executor()");

    // 测试使用默认内存资源的构造
    auto inner3 = std::make_shared<mock_transmission>(ioc);
    const std::array<std::byte, 8> data = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
                                            std::byte{0x04}, std::byte{0x05}, std::byte{0x06},
                                            std::byte{0x07}, std::byte{0x08}};
    auto preview3 = std::make_shared<pp::preview>(inner3, data);

    runner.Check(
        preview3->is_reliable() == true,
        "preview with array data is_reliable()");

    runner.LogPass("TestPreviewConstruction");
}

// ============================================================================
// probe_result 辅助方法测试
// ============================================================================

/**
 * @brief 测试 probe_result 结构体的辅助方法
 * @details 验证 success(), preload_view(), preload_bytes() 等
 * 非协程辅助方法的正确性。
 */
void TestProbeResultHelpers()
{
    runner.LogInfo("=== TestProbeResultHelpers ===");

    using psm::recognition::probe::probe_result;
    using psm::protocol::protocol_type;
    using psm::fault::code;

    // 测试默认构造状态
    {
        probe_result result;
        runner.Check(
            result.success() == false,
            "default constructed probe_result::success() == false");
        runner.Check(
            result.pre_read_size == 0,
            "default constructed pre_read_size == 0");
        runner.Check(
            result.preload_view().empty() == true,
            "default constructed preload_view() is empty");
        runner.Check(
            result.preload_bytes().empty() == true,
            "default constructed preload_bytes() is empty");
    }

    // 测试成功状态
    {
        probe_result result;
        result.type = protocol_type::http;
        result.ec = code::success;
        runner.Check(
            result.success() == true,
            "probe_result::success() == true when type != unknown and ec == success");
    }

    // 测试未知类型时 success() 返回 false
    {
        probe_result result;
        result.type = protocol_type::unknown;
        result.ec = code::success;
        runner.Check(
            result.success() == false,
            "success() == false when type == unknown even if ec == success");
    }

    // 测试错误码非 success 时 success() 返回 false
    {
        probe_result result;
        result.type = protocol_type::tls;
        result.ec = code::eof;
        runner.Check(
            result.success() == false,
            "success() == false when ec != success even if type != unknown");
    }

    // 测试 preload_view() 返回正确的字符串视图
    {
        probe_result result;
        constexpr const char *sample = "GET /";
        const auto bytes = reinterpret_cast<const std::byte *>(sample);
        constexpr std::size_t len = 5;

        std::memcpy(result.pre_read_data.data(), bytes, len);
        result.pre_read_size = len;
        result.type = protocol_type::http;
        result.ec = code::success;

        const auto view = result.preload_view();
        runner.Check(
            view.size() == len,
            "preload_view() returns correct size");
        runner.Check(
            view == std::string_view("GET /"),
            "preload_view() returns correct content");
    }

    // 测试 preload_bytes() 返回正确的字节跨度
    {
        probe_result result;
        const std::array<std::byte, 6> expected = {
            std::byte{0x16}, // TLS record type
            std::byte{0x03}, // TLS version major
            std::byte{0x01}, // TLS version minor
            std::byte{0x00}, // length high
            std::byte{0x7E}, // length low
            std::byte{0x01}, // ClientHello type
        };

        std::memcpy(result.pre_read_data.data(), expected.data(), expected.size());
        result.pre_read_size = expected.size();
        result.type = protocol_type::tls;
        result.ec = code::success;

        const auto span = result.preload_bytes();
        runner.Check(
            span.size() == expected.size(),
            "preload_bytes() returns correct size");

        bool match = true;
        for (std::size_t i = 0; i < expected.size(); ++i)
        {
            if (span[i] != expected[i])
            {
                match = false;
                break;
            }
        }
        runner.Check(match, "preload_bytes() returns correct byte content");
    }

    runner.LogPass("TestProbeResultHelpers");
}

// ============================================================================
// shut_close 测试
// ============================================================================

/**
 * @brief 测试 shut_close 对裸指针的安全处理
 */
void TestShutCloseNullptr()
{
    runner.LogInfo("=== TestShutCloseNullptr ===");

    // 对空指针调用 shut_close 不应崩溃
    psm::pipeline::primitives::shut_close(nullptr);
    runner.LogPass("shut_close(nullptr) is safe");
}

// ============================================================================
// 入口
// ============================================================================

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，依次运行 mux 目标检测、preview 构造、
 * probe_result 辅助方法以及 shut_close 空指针安全测试，输出结果。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    runner.LogInfo("Starting PipelinePrimitives tests...");

    TestIsMuxTarget();
    TestPreviewConstruction();
    TestProbeResultHelpers();
    TestShutCloseNullptr();

    runner.LogInfo("PipelinePrimitives tests completed.");

    return runner.Summary();
}
