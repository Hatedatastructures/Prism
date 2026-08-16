/**
 * @file udp_relay.hpp
 * @brief UDP 双向中继（T3-4 D5 完整版）
 * @details 关联生命周期模型（bind → 会话表 → 超时回收）：
 *          - 动态关联：A 侧首包学习来源 → 与 B 侧来源配对成会话
 *          - 会话表：{A 端点 ↔ B 端点} 双向映射，配对后双向转发
 *          - 超时回收：会话空闲超时后从表移除（后续包重新学习/丢弃）
 *          - 端口不匹配：未配对来源的包丢弃
 *          - 单侧关闭：任一端 socket 关闭 → 隧道结束
 * @note 真实语义（SOCKS5 UDP ASSOCIATE 动态客户端端口）：
 *       两端外部端点动态学习，无需预置 set_remote
 */

#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <map>
#include <memory>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/core/transport/unreliable.hpp>

namespace psmtest::net_udp
{

    namespace net = boost::asio;

    /**
     * @struct relay_options
     * @brief UDP 中继选项
     */
    struct relay_options
    {
        std::chrono::milliseconds idle_timeout{std::chrono::seconds(60)}; ///< 会话空闲超时（0=禁用）
    };

    /**
     * @class udp_relay
     * @brief UDP 双向中继器（关联生命周期）
     * @details 并发转发两个方向；来源动态配对成会话；
     *          会话超时回收；单侧关闭终止。
     */
    class udp_relay
    {
    public:
        /**
         * @brief 构造
         * @param a 端 A（unreliable 包装）
         * @param b 端 B（unreliable 包装）
         * @param opts 中继选项
         */
        udp_relay(std::shared_ptr<psmtest::transport::unreliable> a,
                  std::shared_ptr<psmtest::transport::unreliable> b, relay_options opts = {})
            : a_(std::move(a)), b_(std::move(b)), opts_(opts)
        {
        }

        /**
         * @brief 运行双向中继
         * @return 隧道结束后完成
         */
        [[nodiscard]] auto run() -> net::awaitable<void>
        {
            using boost::asio::experimental::awaitable_operators::operator||;

            auto assoc = std::make_shared<assoc_table>();

            // 单向转发：from 收 → 按会话表配对目标发 to
            auto relay_one = [&](psmtest::transport::unreliable &from,
                                 psmtest::transport::unreliable &to,
                                 std::shared_ptr<assoc_table> table,
                                 bool from_is_a) -> net::awaitable<void>
            {
                std::array<std::byte, 65535> buf{};
                while (true)
                {
                    net::ip::udp::endpoint src;
                    boost::system::error_code r_ec;
                    const auto n = co_await from.native_socket().async_receive_from(
                        net::buffer(buf.data(), buf.size()), src,
                        net::redirect_error(net::use_awaitable, r_ec));
                    if (r_ec || n == 0)
                    {
                        co_return;
                    }
                    // 先学习/配对，再查转发目标（首包即配对）
                    table->touch(src, from_is_a, opts_.idle_timeout);
                    const auto peer = table->peer_of(src, from_is_a);
                    if (!peer)
                    {
                        continue; // 未配对/已回收：丢弃
                    }
                    boost::system::error_code w_ec;
                    co_await to.native_socket().async_send_to(
                        net::buffer(buf.data(), n), *peer,
                        net::redirect_error(net::use_awaitable, w_ec));
                    if (w_ec)
                    {
                        co_return;
                    }
                    table->touch(src, from_is_a, opts_.idle_timeout);
                }
            };

            co_await (relay_one(*a_, *b_, assoc, true) ||
                      relay_one(*b_, *a_, assoc, false) || recycle_loop(assoc));
            a_->close();
            b_->close();
            co_return;
        }

    private:
        /**
         * @struct assoc_table
         * @brief 会话关联表（A 端点 ↔ B 端点配对 + 超时时间）
         */
        struct assoc_table
        {
            /// 单侧条目：配对端点 + 最后活动时刻
            struct entry
            {
                net::ip::udp::endpoint peer{}; ///< 对端（配对端点）
                std::uint64_t last_seen{0};    ///< 最后活动（毫秒）
            };

            /**
             * @brief 查询来源配对目标
             * @param src 来源端点
             * @param from_a 来源是否 A 侧
             * @return 配对目标（未配对返回 nullopt）
             */
            [[nodiscard]] auto peer_of(const net::ip::udp::endpoint &src, bool from_a) const
                -> std::optional<net::ip::udp::endpoint>
            {
                const auto &table = from_a ? a_to_b_ : b_to_a_;
                const auto it = table.find(src);
                if (it == table.end() || it->second.peer == net::ip::udp::endpoint{})
                {
                    return std::nullopt; // 未学习或未配对
                }
                return it->second.peer;
            }

            /**
             * @brief 关联/配对：记录来源，与对侧未配对来源配对，刷新活动时间
             * @param src 来源端点（本侧）
             * @param from_a 来源是否 A 侧
             * @param timeout 空闲超时（0 = 不回收）
             */
            void touch(const net::ip::udp::endpoint &src, bool from_a,
                       std::chrono::milliseconds timeout)
            {
                (void)timeout;
                auto &self = from_a ? a_to_b_ : b_to_a_;
                auto &other = from_a ? b_to_a_ : a_to_b_;
                const auto now = now_ms();
                auto it = self.find(src);
                if (it == self.end())
                {
                    // 新来源：移除本侧旧的未配对条目（单活跃会话简化）
                    for (auto i = self.begin(); i != self.end();)
                    {
                        if (i->second.peer == net::ip::udp::endpoint{})
                        {
                            i = self.erase(i);
                        }
                        else
                        {
                            ++i;
                        }
                    }
                    it = self.emplace(src, entry{{}, now}).first;
                }
                else
                {
                    it->second.last_seen = now;
                }
                if (it->second.peer != net::ip::udp::endpoint{})
                {
                    return; // 已配对
                }
                // 与对侧未配对来源配对（先到者等后到者）
                for (auto &[other_src, oe] : other)
                {
                    if (oe.peer == net::ip::udp::endpoint{})
                    {
                        it->second.peer = other_src;
                        oe.peer = src;
                        return;
                    }
                }
            }

            /**
             * @brief 配对：将对侧来源与来源配对
             * @param a_ep A 侧端点
             * @param b_ep B 侧端点
             */
            void pair(const net::ip::udp::endpoint &a_ep, const net::ip::udp::endpoint &b_ep)
            {
                a_to_b_[a_ep].peer = b_ep;
                b_to_a_[b_ep].peer = a_ep;
            }

            /**
             * @brief 回收超时会话
             * @param timeout 超时（0 = 禁用）
             * @return 回收数
             */
            auto reap(std::chrono::milliseconds timeout) -> std::size_t
            {
                if (timeout.count() <= 0)
                {
                    return 0;
                }
                const auto now = now_ms();
                std::size_t removed = 0;
                for (auto it = a_to_b_.begin(); it != a_to_b_.end();)
                {
                    if (now - it->second.last_seen >
                        static_cast<std::uint64_t>(timeout.count()))
                    {
                        b_to_a_.erase(it->second.peer);
                        it = a_to_b_.erase(it);
                        ++removed;
                    }
                    else
                    {
                        ++it;
                    }
                }
                return removed;
            }

            [[nodiscard]] static auto now_ms() -> std::uint64_t
            {
                return static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch())
                        .count());
            }

            std::map<net::ip::udp::endpoint, entry> a_to_b_; ///< A 来源 → 配对
            std::map<net::ip::udp::endpoint, entry> b_to_a_; ///< B 来源 → 配对
        };

        /**
         * @brief 会话回收循环：周期扫描超时会话
         * @param table 关联表
         */
        [[nodiscard]] auto recycle_loop(std::shared_ptr<assoc_table> table) -> net::awaitable<void>
        {
            if (opts_.idle_timeout.count() <= 0)
            {
                // 禁用回收：超长 timer 挂起（不占 socket 读，避免与转发竞争）
                net::steady_timer t(co_await net::this_coro::executor);
                t.expires_after(std::chrono::hours(24));
                boost::system::error_code ec;
                co_await t.async_wait(net::redirect_error(net::use_awaitable, ec));
                co_return;
            }
            while (true)
            {
                net::steady_timer t(co_await net::this_coro::executor);
                t.expires_after(opts_.idle_timeout);
                boost::system::error_code ec;
                co_await t.async_wait(net::redirect_error(net::use_awaitable, ec));
                if (ec == net::error::operation_aborted)
                {
                    continue;
                }
                table->reap(opts_.idle_timeout);
            }
        }

        std::shared_ptr<psmtest::transport::unreliable> a_; ///< 端 A
        std::shared_ptr<psmtest::transport::unreliable> b_; ///< 端 B
        relay_options opts_;                               ///< 中继选项
    };

} // namespace psmtest::net_udp
