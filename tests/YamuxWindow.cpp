/**
 * @file YamuxWindow.cpp
 * @brief yamux 窗口流控单元测试
 * @details 验证 yamux 多路复用协议的窗口流量控制机制，覆盖以下场景：
 * 1. 窗口耗尽后写入阻塞（发送超过初始窗口大小的数据，验证写入挂起）
 * 2. 窗口恢复后写入继续（发送 WindowUpdate，验证写入恢复）
 * 3. delta clamping（WindowUpdate delta 值的溢出钳制到 uint32_max）
 * 4. recv_consumed 自动 WindowUpdate（读取数据后自动发送窗口更新）
 * 5. 窗口信号定时器的阻塞与唤醒（io_context 协程验证）
 * 6. WindowUpdate 帧通过 TCP socket pair 的实际传输与解析
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/multiplex/yamux/craft.hpp>

#include "common/TestRunner.hpp"

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>

namespace
{
    psm::testing::TestRunner runner("YamuxWindow");

    namespace yamux = psm::multiplex::yamux;
    namespace net = boost::asio;

    // ---------- helpers ----------

    /**
     * @brief 模拟 craft::send_data 中的窗口扣减 CAS 循环
     * @details 复现 craft::send_data 的原子扣减逻辑：尝试从 send_window 扣减 payload_size，
     * 成功返回 true，窗口不足返回 false。
     */
    [[nodiscard]] auto try_acquire_window(yamux::stream_window &window, std::uint32_t payload_size) -> bool
    {
        auto old_val = window.send_window.load(std::memory_order_acquire);
        while (old_val >= payload_size)
        {
            if (window.send_window.compare_exchange_weak(old_val, old_val - payload_size, std::memory_order_acq_rel))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief 模拟 craft::handle_window_update 中的窗口增量 CAS 循环（含溢出钳制）
     * @details 复现 craft::handle_window_update 的原子累加逻辑：
     * delta 累加后溢出时钳制到 uint32_max 而非回绕。
     */
    void apply_window_update(yamux::stream_window &window, std::uint32_t delta)
    {
        auto old_val = window.send_window.load(std::memory_order_acquire);
        std::uint32_t new_val;
        do
        {
            new_val = old_val + delta;
            if (new_val < old_val)
            {
                new_val = std::numeric_limits<std::uint32_t>::max();
            }
        } while (!window.send_window.compare_exchange_weak(old_val, new_val, std::memory_order_acq_rel));
    }

    /**
     * @brief 模拟 craft::update_recv_win 的阈值判定逻辑
     * @details 累加 consumed 到 recv_consumed，达到 initial_window/2 时返回 true
     * （应发送 WindowUpdate）并重置计数器，否则返回 false。
     */
    [[nodiscard]] auto check_recv_window_threshold(yamux::stream_window &window,
                                                    std::uint32_t consumed,
                                                    std::uint32_t initial_window) -> bool
    {
        const auto total = window.recv_consumed.fetch_add(consumed, std::memory_order_acq_rel) + consumed;
        if (total >= initial_window / 2)
        {
            window.recv_consumed.store(0, std::memory_order_release);
            return true;
        }
        return false;
    }
} // namespace

// ---------- Test 1: Window exhaustion blocks write ----------

/**
 * @brief 测试窗口耗尽后写入阻塞
 * @details 设置较小窗口后连续扣减，验证窗口为 0 时 try_acquire_window 返回 false
 * （对应 craft::send_data 中协程挂起等待窗口更新）。
 * 同时验证初始窗口大小 (256KB) 下恰好耗尽的场景。
 */
void TestWindowExhaustionBlocksWrite()
{
    runner.LogInfo("=== TestWindowExhaustionBlocksWrite ===");

    net::io_context ioc;

    // 小窗口耗尽测试
    {
        yamux::stream_window window(ioc.get_executor());
        window.send_window.store(100, std::memory_order_release);

        runner.Check(try_acquire_window(window, 60),
            "WindowExhaustion: acquire 60/100 bytes succeeds");
        runner.Check(window.send_window.load() == 40,
            "WindowExhaustion: remaining window is 40");

        runner.Check(try_acquire_window(window, 40),
            "WindowExhaustion: acquire 40/40 bytes succeeds (full drain)");
        runner.Check(window.send_window.load() == 0,
            "WindowExhaustion: window is 0 (exhausted)");

        runner.Check(!try_acquire_window(window, 1),
            "WindowExhaustion: acquire 1 byte fails when window is 0");
    }

    // 初始窗口 (256KB) 恰好耗尽
    {
        yamux::stream_window window(ioc.get_executor());
        constexpr auto initial = yamux::default_window; // 262144

        // 扣减恰好等于初始窗口的数据量
        runner.Check(try_acquire_window(window, initial),
            "WindowExhaustion: acquire full 256KB initial window succeeds");
        runner.Check(window.send_window.load() == 0,
            "WindowExhaustion: window is 0 after full 256KB drain");

        // 超出 1 字节应失败
        runner.Check(!try_acquire_window(window, 1),
            "WindowExhaustion: cannot acquire 1 more byte after full drain");
    }

    // 超过初始窗口的请求应立即失败
    {
        yamux::stream_window window(ioc.get_executor());
        constexpr auto initial = yamux::default_window;

        runner.Check(!try_acquire_window(window, initial + 1),
            "WindowExhaustion: request exceeding initial window fails immediately");
    }
}

// ---------- Test 2: Window recovery resumes write ----------

/**
 * @brief 测试窗口恢复后写入继续
 * @details 窗口耗尽后通过 apply_window_update 恢复，验证 try_acquire_window 恢复成功。
 * 覆盖单次恢复、多次累加恢复、耗尽→恢复→耗尽→恢复循环等场景。
 */
void TestWindowRecoveryResumesWrite()
{
    runner.LogInfo("=== TestWindowRecoveryResumesWrite ===");

    net::io_context ioc;
    yamux::stream_window window(ioc.get_executor());

    // 窗口设为 0（模拟耗尽）
    window.send_window.store(0, std::memory_order_release);
    runner.Check(!try_acquire_window(window, 100),
        "WindowRecovery: acquire fails when window is 0");

    // 发送 WindowUpdate 恢复 1024 字节
    apply_window_update(window, 1024);
    runner.Check(window.send_window.load() == 1024,
        "WindowRecovery: window restored to 1024");

    // 恢复后写入成功
    runner.Check(try_acquire_window(window, 512),
        "WindowRecovery: acquire 512 bytes succeeds after recovery");
    runner.Check(window.send_window.load() == 512,
        "WindowRecovery: remaining window is 512");

    // 多次 WindowUpdate 累加
    apply_window_update(window, 100);
    apply_window_update(window, 200);
    runner.Check(window.send_window.load() == 812,
        "WindowRecovery: multiple updates accumulate (512+100+200=812)");

    // 耗尽→恢复→耗尽→恢复循环
    window.send_window.store(0, std::memory_order_release);
    runner.Check(!try_acquire_window(window, 1), "WindowRecovery: cycle - exhausted again");

    apply_window_update(window, 256 * 1024);
    runner.Check(window.send_window.load() == 256 * 1024,
        "WindowRecovery: cycle - restored to 256KB");
    runner.Check(try_acquire_window(window, 256 * 1024),
        "WindowRecovery: cycle - can acquire full 256KB after recovery");
}

// ---------- Test 3: Delta clamping ----------

/**
 * @brief 测试 WindowUpdate delta 值的溢出钳制
 * @details 验证 send_window + delta 溢出 uint32_t 时钳制到 uint32_max，
 * 正常加法不受影响，delta=0 不改变窗口。
 * 同时验证 WindowUpdate 帧在 delta 边界值 (0, uint32_max) 下的编解码正确性。
 */
void TestDeltaClamping()
{
    runner.LogInfo("=== TestDeltaClamping ===");

    net::io_context ioc;
    yamux::stream_window window(ioc.get_executor());

    // 溢出钳制：(uint32_max - 100) + 200 -> uint32_max
    window.send_window.store(std::numeric_limits<std::uint32_t>::max() - 100, std::memory_order_release);
    apply_window_update(window, 200);
    runner.Check(window.send_window.load() == std::numeric_limits<std::uint32_t>::max(),
        "DeltaClamping: (uint32_max - 100) + 200 clamped to uint32_max");

    // 恰好不溢出：(uint32_max - 1) + 1 -> uint32_max
    window.send_window.store(std::numeric_limits<std::uint32_t>::max() - 1, std::memory_order_release);
    apply_window_update(window, 1);
    runner.Check(window.send_window.load() == std::numeric_limits<std::uint32_t>::max(),
        "DeltaClamping: (uint32_max - 1) + 1 == uint32_max (exact)");

    // 已是最大值再加：uint32_max + 1 -> uint32_max
    window.send_window.store(std::numeric_limits<std::uint32_t>::max(), std::memory_order_release);
    apply_window_update(window, 1);
    runner.Check(window.send_window.load() == std::numeric_limits<std::uint32_t>::max(),
        "DeltaClamping: uint32_max + 1 clamped to uint32_max");

    // 极端溢出：uint32_max + uint32_max -> uint32_max
    window.send_window.store(std::numeric_limits<std::uint32_t>::max(), std::memory_order_release);
    apply_window_update(window, std::numeric_limits<std::uint32_t>::max());
    runner.Check(window.send_window.load() == std::numeric_limits<std::uint32_t>::max(),
        "DeltaClamping: uint32_max + uint32_max clamped to uint32_max");

    // 正常加法不受影响
    window.send_window.store(1000, std::memory_order_release);
    apply_window_update(window, 500);
    runner.Check(window.send_window.load() == 1500,
        "DeltaClamping: 1000 + 500 = 1500 (no clamping)");

    // delta = 0 不改变窗口
    window.send_window.store(1000, std::memory_order_release);
    apply_window_update(window, 0);
    runner.Check(window.send_window.load() == 1000,
        "DeltaClamping: delta=0 leaves window unchanged");

    // WindowUpdate 帧编解码：delta 边界值
    {
        auto frame_zero = yamux::build_winupd(yamux::flags::none, 1, 0);
        auto parsed_zero = yamux::parse_header(frame_zero);
        runner.Check(parsed_zero.has_value() && parsed_zero->length == 0,
            "DeltaClamping: WindowUpdate delta=0 round-trip correct");

        auto frame_max = yamux::build_winupd(
            yamux::flags::none, 1, std::numeric_limits<std::uint32_t>::max());
        auto parsed_max = yamux::parse_header(frame_max);
        runner.Check(parsed_max.has_value() &&
            parsed_max->length == std::numeric_limits<std::uint32_t>::max(),
            "DeltaClamping: WindowUpdate delta=uint32_max round-trip correct");
    }
}

// ---------- Test 4: recv_consumed auto WindowUpdate ----------

/**
 * @brief 测试 recv_consumed 自动 WindowUpdate 阈值触发
 * @details 模拟 craft::update_recv_win 逻辑：累积消费量达到 initial_window/2 时
 * 触发 WindowUpdate 发送并重置计数器。覆盖小量不触发、精确阈值、
 * 单次大量、多轮触发等场景。
 */
void TestRecvConsumedAutoWindowUpdate()
{
    runner.LogInfo("=== TestRecvConsumedAutoWindowUpdate ===");

    net::io_context ioc;
    constexpr auto initial = yamux::default_window; // 262144
    constexpr auto threshold = initial / 2;                 // 131072

    // 小量消费不触发
    {
        yamux::stream_window window(ioc.get_executor());
        runner.Check(!check_recv_window_threshold(window, 1024, initial),
            "RecvAuto: 1024 bytes does not trigger (below threshold)");
        runner.Check(window.recv_consumed.load() == 1024,
            "RecvAuto: recv_consumed accumulated to 1024");
    }

    // 累积到阈值触发
    {
        yamux::stream_window window(ioc.get_executor());

        // 消费 130000 字节（13 * 10000），低于阈值 131072
        bool triggered = false;
        for (int i = 0; i < 13; ++i)
        {
            triggered = check_recv_window_threshold(window, 10000, initial);
        }
        runner.Check(!triggered, "RecvAuto: 130000 bytes does not trigger");

        // 再消费 1072 字节，总计 131072 = 阈值，触发
        triggered = check_recv_window_threshold(window, 1072, initial);
        runner.Check(triggered, "RecvAuto: 131072 bytes (exact threshold) triggers");
        runner.Check(window.recv_consumed.load() == 0,
            "RecvAuto: recv_consumed reset to 0 after trigger");
    }

    // 单次大量消费直接触发
    {
        yamux::stream_window window(ioc.get_executor());
        runner.Check(check_recv_window_threshold(window, initial, initial),
            "RecvAuto: single 256KB consumption triggers immediately");
        runner.Check(window.recv_consumed.load() == 0,
            "RecvAuto: recv_consumed reset after large trigger");
    }

    // 多轮触发
    {
        yamux::stream_window window(ioc.get_executor());
        int trigger_count = 0;
        for (int round = 0; round < 4; ++round)
        {
            if (check_recv_window_threshold(window, threshold + 1, initial))
            {
                ++trigger_count;
            }
        }
        runner.Check(trigger_count == 4,
            "RecvAuto: 4 rounds of (threshold+1) triggers 4 WindowUpdates");
    }

    // 精确阈值边界：threshold - 1 不触发，再加 1 触发
    {
        yamux::stream_window window(ioc.get_executor());
        runner.Check(!check_recv_window_threshold(window, threshold - 1, initial),
            "RecvAuto: threshold - 1 does not trigger");
        runner.Check(check_recv_window_threshold(window, 1, initial),
            "RecvAuto: threshold exactly triggers WindowUpdate");
    }
}

// ---------- Test 5: Window signal block and wake ----------

/**
 * @brief 测试窗口信号定时器的阻塞与唤醒
 * @details 模拟 craft::send_data 中 window_signal 的阻塞/唤醒模式：
 * 协程挂起等待信号，WindowUpdate 到达后 cancel 唤醒协程。
 */
void TestWindowSignalBlockAndWake()
{
    runner.LogInfo("=== TestWindowSignalBlockAndWake ===");

    net::io_context ioc;
    yamux::stream_window window(ioc.get_executor());
    auto signal = window.window_signal;

    std::atomic<bool> woke_up{false};

    // 启动协程等待窗口信号
    net::co_spawn(ioc.get_executor(),
        [signal, &woke_up]() -> net::awaitable<void>
        {
            boost::system::error_code ec;
            co_await signal->async_wait(net::redirect_error(net::use_awaitable, ec));
            woke_up.store(true, std::memory_order_release);
        },
        net::detached);

    // poll 让协程启动并挂起
    ioc.poll();
    runner.Check(!woke_up.load(std::memory_order_acquire),
        "WindowSignal: coroutine suspended on window_signal");

    // 模拟 WindowUpdate 到达：cancel 唤醒
    signal->cancel();
    ioc.run();
    runner.Check(woke_up.load(std::memory_order_acquire),
        "WindowSignal: coroutine woke up after cancel");
}

/**
 * @brief 测试窗口信号无虚假唤醒
 * @details 验证 window_signal 在未被 cancel 时不会无故唤醒挂起的协程。
 */
void TestWindowSignalNoSpuriousWake()
{
    runner.LogInfo("=== TestWindowSignalNoSpuriousWake ===");

    net::io_context ioc;
    yamux::stream_window window(ioc.get_executor());

    std::atomic<bool> woke_up{false};

    net::co_spawn(ioc.get_executor(),
        [signal = window.window_signal, &woke_up]() -> net::awaitable<void>
        {
            boost::system::error_code ec;
            co_await signal->async_wait(net::redirect_error(net::use_awaitable, ec));
            woke_up.store(true, std::memory_order_release);
        },
        net::detached);

    ioc.poll();
    runner.Check(!woke_up.load(std::memory_order_acquire),
        "WindowSignalNoSpurious: no wake without cancel");
}

// ---------- Test 6: WindowUpdate frame over TCP socket pair ----------

/**
 * @brief 测试 WindowUpdate 帧通过 TCP socket pair 的传输与解析
 * @details 创建 TCP loopback 连接对，一端编码发送 WindowUpdate 帧，
 * 另一端接收并解析验证帧内容。覆盖普通 WindowUpdate 和 SYN 打开流两种帧类型。
 */
void TestWindowUpdateFrameOverSocketPair()
{
    runner.LogInfo("=== TestWindowUpdateFrameOverSocketPair ===");

    net::io_context ioc;

    // 创建 TCP socket pair（loopback accept/connect）
    // 使用显式 127.0.0.1 避免 IPv6/IPv4 混淆导致的连接失败
    boost::system::error_code ec;
    net::ip::tcp::acceptor acceptor(ioc,
        net::ip::tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 0));
    auto ep = acceptor.local_endpoint();

    net::ip::tcp::socket client_sock(ioc);
    client_sock.connect(net::ip::tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), ep.port()), ec);
    if (ec)
    {
        runner.LogFail(std::format("SocketPair: client connect failed: {}", ec.message()).c_str());
        return;
    }

    auto server_sock = acceptor.accept(ec);
    if (ec)
    {
        runner.LogFail(std::format("SocketPair: server accept failed: {}", ec.message()).c_str());
        return;
    }
    acceptor.close();

    // --- 场景 1: 普通 WindowUpdate(none, stream_id=42, delta=65536) ---
    {
        constexpr std::uint32_t test_stream_id = 42;
        constexpr std::uint32_t test_delta = 65536;

        auto frame = yamux::build_winupd(yamux::flags::none, test_stream_id, test_delta);

        boost::system::error_code write_ec;
        net::write(client_sock, net::buffer(frame.data(), frame.size()), write_ec);
        runner.Check(!write_ec, "SocketPair: write WindowUpdate frame succeeded");
        if (write_ec)
        {
            return;
        }

        std::array<std::byte, yamux::frame_hdrsize> recv_buf{};
        boost::system::error_code read_ec;
        const auto n = net::read(server_sock, net::buffer(recv_buf.data(), recv_buf.size()), read_ec);
        runner.Check(!read_ec, "SocketPair: read WindowUpdate frame succeeded");
        runner.Check(n == yamux::frame_hdrsize, "SocketPair: received exactly 12 bytes");

        auto parsed = yamux::parse_header(recv_buf);
        runner.Check(parsed.has_value(), "SocketPair: WindowUpdate header parse succeeded");
        if (parsed)
        {
            runner.Check(parsed->type == yamux::message_type::window_update,
                "SocketPair: WindowUpdate type == window_update");
            runner.Check(parsed->flag == yamux::flags::none,
                "SocketPair: WindowUpdate flag == none");
            runner.Check(parsed->stream_id == test_stream_id,
                "SocketPair: WindowUpdate stream_id == 42");
            runner.Check(parsed->length == test_delta,
                "SocketPair: WindowUpdate delta == 65536");
        }
    }

    // --- 场景 2: WindowUpdate(SYN, stream_id=1, delta=256KB) 模拟流打开 ---
    {
        auto syn_frame = yamux::build_winupd(
            yamux::flags::syn, 1, yamux::default_window);

        boost::system::error_code write_ec;
        net::write(client_sock, net::buffer(syn_frame.data(), syn_frame.size()), write_ec);
        runner.Check(!write_ec, "SocketPair: write SYN frame succeeded");
        if (write_ec)
        {
            return;
        }

        std::array<std::byte, yamux::frame_hdrsize> syn_recv{};
        boost::system::error_code read_ec;
        net::read(server_sock, net::buffer(syn_recv.data(), syn_recv.size()), read_ec);
        runner.Check(!read_ec, "SocketPair: read SYN frame succeeded");

        auto syn_parsed = yamux::parse_header(syn_recv);
        runner.Check(syn_parsed.has_value(), "SocketPair: SYN header parse succeeded");
        if (syn_parsed)
        {
            runner.Check(syn_parsed->type == yamux::message_type::window_update,
                "SocketPair: SYN type == window_update");
            runner.Check(yamux::has_flag(syn_parsed->flag, yamux::flags::syn),
                "SocketPair: SYN frame has SYN flag");
            runner.Check(syn_parsed->stream_id == 1,
                "SocketPair: SYN frame stream_id == 1");
            runner.Check(syn_parsed->length == yamux::default_window,
                "SocketPair: SYN frame delta == 256KB (initial window)");
        }
    }

    // --- 场景 3: WindowUpdate(ACK, stream_id=1, delta=512KB) 模拟服务端确认 ---
    {
        constexpr std::uint32_t server_window = 512 * 1024;
        auto ack_frame = yamux::build_winupd(yamux::flags::ack, 1, server_window);

        boost::system::error_code write_ec;
        net::write(server_sock, net::buffer(ack_frame.data(), ack_frame.size()), write_ec);
        runner.Check(!write_ec, "SocketPair: write ACK frame succeeded");
        if (write_ec)
        {
            return;
        }

        std::array<std::byte, yamux::frame_hdrsize> ack_recv{};
        boost::system::error_code read_ec;
        net::read(client_sock, net::buffer(ack_recv.data(), ack_recv.size()), read_ec);
        runner.Check(!read_ec, "SocketPair: read ACK frame succeeded");

        auto ack_parsed = yamux::parse_header(ack_recv);
        runner.Check(ack_parsed.has_value(), "SocketPair: ACK header parse succeeded");
        if (ack_parsed)
        {
            runner.Check(ack_parsed->type == yamux::message_type::window_update,
                "SocketPair: ACK type == window_update");
            runner.Check(yamux::has_flag(ack_parsed->flag, yamux::flags::ack),
                "SocketPair: ACK frame has ACK flag");
            runner.Check(ack_parsed->stream_id == 1,
                "SocketPair: ACK frame stream_id == 1");
            runner.Check(ack_parsed->length == server_window,
                "SocketPair: ACK frame delta == 512KB (server window)");
        }
    }
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，运行 yamux 窗口流控全部测试用例。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    runner.LogInfo("========== Yamux Window Flow Control Tests ==========");

    TestWindowExhaustionBlocksWrite();
    TestWindowRecoveryResumesWrite();
    TestDeltaClamping();
    TestRecvConsumedAutoWindowUpdate();
    TestWindowSignalBlockAndWake();
    TestWindowSignalNoSpuriousWake();
    TestWindowUpdateFrameOverSocketPair();

    return runner.Summary();
}
