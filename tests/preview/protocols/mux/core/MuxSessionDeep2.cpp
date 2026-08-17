/**
 * @file MuxSessionDeep2.cpp
 * @brief 共享会话框架（session<C>）剩余分支深度测试
 * @details 直接驱动 session<smux::codec> 引擎，手工注入帧序列覆盖
 *          dispatch 全部事件分支：open（含 id==0 / 重复流 / 带负载）、
 *          data（已知流 / 隐式开流 / id==0）、fin / rst（含未知流）、
 *          控制帧忽略；以及 stream_handle 的 shutdown / cancel /
 *          set_timeout / set_peer_eof / on_rst / is_open 等剩余方法，
 *          会话关闭后 send_fin / send_rst 的空通道分支，流 ID 环绕。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include <common/core/transport/memory_stream.hpp>
#include <common/protocols/mux/h2mux/h2mux.hpp>
#include <common/protocols/mux/smux/smux.hpp>
#include <common/protocols/mux/yamux/yamux.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace preview;
    using namespace preview::mux;
    namespace net = boost::asio;

    /**
     * @brief 驱动协程运行
     */
    template <typename A>
    auto run_coro(net::io_context &ioc, A coro) -> void
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          ioc.stop();
                      });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    /**
     * @brief 构造 SYN + 负载帧（覆盖 open 分支带负载路径）
     */
    auto make_syn_with_payload(std::uint32_t id, std::string_view payload) -> std::vector<std::uint8_t>
    {
        smux::frame_header hdr{};
        hdr.cmd = smux::command::syn;
        hdr.length = static_cast<std::uint16_t>(payload.size());
        hdr.stream_id = id;
        return smux::build(hdr, as_u8_span(payload));
    }

    TEST(MuxSessionDeep2, DispatchAllEvents)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto peer = std::make_shared<memory_stream>(std::move(b));
        session_options opt{};
        opt.role = preview::role::server;
        auto session = mux::session<smux::codec>::create(std::make_shared<memory_stream>(std::move(a)), opt);

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // open（带负载）→ accept 得到流并读到负载
                     const auto w1 = co_await peer->write_all(make_syn_with_payload(1, "open-payload"));
                     EXPECT_FALSE(w1);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     auto handle = co_await session->accept_stream();
                     std::array<std::uint8_t, 64> buf{};
                     const auto n = co_await handle->read_some(std::span<std::uint8_t>(buf));
                     EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(buf.data()), n), "open-payload");
                     EXPECT_EQ(session->stream_count(), 1u);

                     // 重复 SYN（同 id）→ 忽略
                     const auto w2 = co_await peer->write_all(smux::build_syn(1));
                     EXPECT_FALSE(w2);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     EXPECT_EQ(session->stream_count(), 1u);

                     // SYN id==0 → 忽略
                     const auto w3 = co_await peer->write_all(smux::build_syn(0));
                     EXPECT_FALSE(w3);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     EXPECT_EQ(session->stream_count(), 1u);

                     // data 已知流
                     const auto w4 = co_await peer->write_all(smux::build_push(1, as_u8_span(std::string_view{"data1"})));
                     EXPECT_FALSE(w4);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     const auto n1 = co_await handle->read_some(std::span<std::uint8_t>(buf));
                     EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(buf.data()), n1), "data1");

                     // data 隐式开流（无 SYN）
                     const auto w5 = co_await peer->write_all(smux::build_push(3, as_u8_span(std::string_view{"implicit"})));
                     EXPECT_FALSE(w5);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     auto implicit = co_await session->accept_stream();
                     if (!implicit)
                     {
                         EXPECT_TRUE(false) << "implicit stream accept failed";
                         co_return;
                     }
                     const auto n2 = co_await implicit->read_some(std::span<std::uint8_t>(buf));
                     EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(buf.data()), n2), "implicit");
                     EXPECT_EQ(session->stream_count(), 2u);

                     // data id==0 → 忽略
                     const auto w6 = co_await peer->write_all(smux::build_push(0, as_u8_span(std::string_view{"x"})));
                     EXPECT_FALSE(w6);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     EXPECT_EQ(session->stream_count(), 2u);

                     // fin 已知流 → 对端半关
                     const auto w7 = co_await peer->write_all(smux::build_fin(1));
                     EXPECT_FALSE(w7);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     EXPECT_TRUE(handle->is_peer_eof());

                     // fin 未知流 → 忽略
                     const auto w8 = co_await peer->write_all(smux::build_fin(99));
                     EXPECT_FALSE(w8);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);

                     // 控制帧（NOP）→ 忽略
                     smux::frame_header nop_hdr{};
                     nop_hdr.cmd = smux::command::nop;
                     const auto w9 = co_await peer->write_all(smux::build(nop_hdr));
                     EXPECT_FALSE(w9);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     EXPECT_EQ(session->stream_count(), 2u);

                     // smux 无独立 RST 帧：FIN 帧即半关（stream_event::fin）
                     const auto w10 = co_await peer->write_all(smux::build_fin(3));
                     EXPECT_FALSE(w10);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     EXPECT_TRUE(implicit->is_peer_eof());
                     EXPECT_EQ(session->stream_count(), 2u);

                     // fin 未知流 → 无副作用
                     const auto w11 = co_await peer->write_all(smux::build_fin(98));
                     EXPECT_FALSE(w11);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     EXPECT_EQ(session->stream_count(), 2u);

                     co_await session->close();
                 });
    }

    TEST(MuxSessionDeep2, YamuxRstEvent)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto peer = std::make_shared<memory_stream>(std::move(b));
        auto session = mux::session<yamux::codec>::create(std::make_shared<memory_stream>(std::move(a)), session_options{});

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     (void)session->executor();
                     // 开流（Data + SYN + 负载）→ open 分支带负载路径
                     const auto w1 = co_await peer->write_all(
                         yamux::build_data(yamux::flags::syn, 1, as_u8_span(std::string_view{"open-payload"})));
                     EXPECT_FALSE(w1);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     auto handle = co_await session->accept_stream();
                     if (!handle)
                     {
                         EXPECT_TRUE(false) << "accept_stream failed";
                         co_return;
                     }
                     std::array<std::uint8_t, 64> buf{};
                     const auto n = co_await handle->read_some(std::span<std::uint8_t>(buf));
                     EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(buf.data()), n), "open-payload");
                     EXPECT_EQ(session->stream_count(), 1u);

                     // FIN（Data + FIN 标志）→ fin 分支
                     const auto w2 = co_await peer->write_all(yamux::build_data(yamux::flags::fin, 1, {}));
                     EXPECT_FALSE(w2);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     EXPECT_TRUE(handle->is_peer_eof());
                     EXPECT_EQ(session->stream_count(), 1u);

                     // FIN 未知流 → 无副作用
                     const auto w3 = co_await peer->write_all(yamux::build_data(yamux::flags::fin, 99, {}));
                     EXPECT_FALSE(w3);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     EXPECT_EQ(session->stream_count(), 1u);

                     // RST 已知流 → 流关闭并移除
                     const auto w4 = co_await peer->write_all(yamux::build_data(yamux::flags::rst, 1, {}));
                     EXPECT_FALSE(w4);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     EXPECT_TRUE(handle->is_closed());
                     EXPECT_EQ(session->stream_count(), 0u);

                     // RST 未知流 → 无副作用
                     const auto w5 = co_await peer->write_all(yamux::build_data(yamux::flags::rst, 98, {}));
                     EXPECT_FALSE(w5);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     EXPECT_EQ(session->stream_count(), 0u);

                     // 本端 shutdown / reset（send_fin / send_rst 实例路径）
                     co_await handle->shutdown();
                     co_await handle->reset();
                     co_await session->close();
                 });
    }

    TEST(MuxSessionDeep2, H2muxFinAndImplicitOpen)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto peer = std::make_shared<memory_stream>(std::move(b));
        auto session = mux::session<h2mux::codec>::create(std::make_shared<memory_stream>(std::move(a)), session_options{});

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     (void)session->executor();
                     // data 隐式开流（无 SYN 帧）+ 负载 → 717 路径
                     const auto w1 = co_await peer->write_all(
                         h2mux::build_data(1, as_u8_span(std::string_view{"implicit"})));
                     EXPECT_FALSE(w1);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     auto handle = co_await session->accept_stream();
                     if (!handle)
                     {
                         EXPECT_TRUE(false) << "accept_stream failed";
                         co_return;
                     }
                     std::array<std::uint8_t, 64> buf{};
                     const auto n = co_await handle->read_some(std::span<std::uint8_t>(buf));
                     EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(buf.data()), n), "implicit");
                     EXPECT_EQ(session->stream_count(), 1u);

                     // CLOSE 帧 → fin 分支
                     const auto w2 = co_await peer->write_all(h2mux::build_close(1));
                     EXPECT_FALSE(w2);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     EXPECT_TRUE(handle->is_peer_eof());

                     // CLOSE 未知流 → 无副作用
                     const auto w3 = co_await peer->write_all(h2mux::build_close(77));
                     EXPECT_FALSE(w3);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);

                     // 本端 shutdown / reset（send_fin / send_rst 实例路径）
                     co_await handle->shutdown();
                     co_await handle->reset();
                     co_await session->close();
                 });
    }

    TEST(MuxSessionDeep2, StreamHandleMethods)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto peer = std::make_shared<memory_stream>(std::move(b));
        auto session = mux::session<smux::codec>::create(std::make_shared<memory_stream>(std::move(a)), session_options{});

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     (void)session->executor();
                     auto handle = co_await session->open_stream();
                     if (!handle)
                     {
                         EXPECT_TRUE(false) << "open_stream failed";
                         co_return;
                     }
                     EXPECT_TRUE(handle->is_open());
                     EXPECT_EQ(handle->id(), 1u);

                     // shutdown：置 fin_sent + 发 FIN
                     co_await handle->shutdown();
                     EXPECT_TRUE(handle->is_fin_sent());
                     EXPECT_TRUE(handle->is_open());

                     // set_peer_eof：对端 FIN 到达
                     handle->set_peer_eof();
                     EXPECT_TRUE(handle->is_peer_eof());

                     // on_rst：流被对端重置
                     handle->on_rst();
                     EXPECT_TRUE(handle->is_closed());
                     EXPECT_FALSE(handle->is_open());

                     // cancel：唤醒挂起读返回 0
                     auto handle2 = co_await session->open_stream();
                     if (!handle2)
                     {
                         EXPECT_TRUE(false) << "open_stream failed";
                         co_return;
                     }
                     handle2->cancel();
                     std::array<std::uint8_t, 8> buf{};
                     const auto n = co_await handle2->read_some(std::span<std::uint8_t>(buf));
                     EXPECT_EQ(n, 0u);

                     // set_timeout：读超时返回 0
                     handle2->set_timeout(std::chrono::milliseconds(20));
                     const auto n2 = co_await handle2->read_some(std::span<std::uint8_t>(buf));
                     EXPECT_EQ(n2, 0u);

                     // 挂起读超时路径（队列空 + 超时启用）
                     auto handle3 = co_await session->open_stream();
                     if (!handle3)
                     {
                         EXPECT_TRUE(false) << "open_stream failed";
                         co_return;
                     }
                     handle3->set_timeout(std::chrono::milliseconds(20));
                     const auto n3 = co_await handle3->read_some(std::span<std::uint8_t>(buf));
                     EXPECT_EQ(n3, 0u);

                     // 会话关闭前 shutdown / reset：send_fin / send_rst 实例路径
                     co_await handle2->shutdown();
                     co_await handle2->reset();
                     // 会话关闭后：send_fin / send_rst 空通道分支
                     co_await session->close();
                     co_await handle2->close();
                 });
    }

    TEST(MuxSessionDeep2, SessionClosedPaths)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto session = mux::session<smux::codec>::create(std::make_shared<memory_stream>(std::move(a)), session_options{});

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto handle = co_await session->open_stream();
                     if (!handle)
                     {
                         EXPECT_TRUE(false) << "open_stream failed";
                         co_return;
                     }
                     EXPECT_TRUE(session->is_open());
                     co_await session->close();
                     EXPECT_FALSE(session->is_open());

                     // 会话关闭后：open / accept / push_data 失败路径
                     const auto null_stream = co_await session->open_stream();
                     EXPECT_EQ(null_stream, nullptr);
                     auto accepted = co_await session->accept_stream();
                     EXPECT_EQ(accepted, nullptr);
                     const auto perr = co_await handle->write_all(as_u8_span(std::string_view{"x"}));
                     EXPECT_TRUE(perr);
                     EXPECT_EQ(perr, make_error_code(error::broken_pipe));
                 });
    }

    TEST(MuxSessionDeep2, StreamIdWrapAround)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        session_options opt{};
        opt.role = preview::role::client;
        opt.max_streams = 40000;
        auto session = mux::session<smux::codec>::create(std::make_shared<memory_stream>(std::move(a)), opt);

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 32768 个奇数流 ID（1..65535）分配成功
                     for (std::size_t i = 0; i < 32768; ++i)
                     {
                         auto handle = co_await session->open_stream();
                         if (!handle)
                         {
                             EXPECT_TRUE(false) << "open_stream failed at " << i;
                             co_return;
                         }
                     }
                     EXPECT_EQ(session->stream_count(), 32768u);
                     // 下一次分配：next_id 环绕（65537 > 65535），全表已占 → nullptr
                     const auto null_stream = co_await session->open_stream();
                     EXPECT_EQ(null_stream, nullptr);
                     co_await session->close();
                 });
    }

} // namespace
