/**
 * @file UdpRelay.hpp
 * @brief UDP 双向中继（T3-4 D5 完整版）
 * @details 关联生命周期模型（Bind → 会话表 → 超时回收）：
 *          - 动态关联：A 侧首包学习来源 → 与 B 侧来源配对成会话
 *          - 会话表：{A 端点 ↔ B 端点} 双向映射，配对后双向转发
 *          - 超时回收：会话空闲超时后从表移除（后续包重新学习/丢弃）
 *          - 端口不匹配：未配对来源的包丢弃
 *          - 单侧关闭：任一端 socket 关闭 → 隧道结束
 * @note 真实语义（SOCKS5 UDP ASSOCIATE 动态客户端端口）：
 *       两端外部端点动态学习，无需预置 SetRemote
 */

#pragma once

#include <array>
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Transport/Unreliable.hpp>

namespace Preview::Network::Udp
{

    namespace Net = boost::asio;

    /**
     * @struct RelayOptions
     * @brief UDP 中继选项
     */
    struct RelayOptions
    {
        std::chrono::milliseconds IdleTimeout{std::chrono::seconds(60)}; ///< 会话空闲超时（0=禁用）
        std::size_t MaxAssociations{256}; ///< 最大并发关联数（0=不限）
    };

    /**
     * @class UdpRelay
     * @brief UDP 双向中继器（关联生命周期）
     * @details 并发转发两个方向；来源动态配对成会话；
     *          会话超时回收；单侧关闭终止。
     */
    class UdpRelay
    {
    public:
        /**
         * @brief 构造
         * @param a 端 A（Unreliable 包装）
         * @param b 端 B（Unreliable 包装）
         * @param opts 中继选项
         */
        UdpRelay(std::shared_ptr<Preview::Transport::Unreliable> EndpointA,
                  std::shared_ptr<Preview::Transport::Unreliable> EndpointB,
                  RelayOptions Options = {})
            : A_(std::move(EndpointA)), B_(std::move(EndpointB)), Opts_(Options)
        {
        }

        /**
         * @brief 运行双向中继
         * @return 隧道结束后完成
         */
        [[nodiscard]] auto Run() -> Net::awaitable<void>
        {
            using Net::experimental::awaitable_operators::operator||;

            auto Assoc = std::make_shared<AssocTable>(Opts_.IdleTimeout, Opts_.MaxAssociations);

            // 单向转发：from 收 → 按会话表配对目标发 to
            auto RelayOne = [&](Preview::Transport::Unreliable &Source,
                                 Preview::Transport::Unreliable &Destination,
                                 std::shared_ptr<AssocTable> Table,
                                 bool FromIsA) -> Net::awaitable<void>
            {
                // 64KB 缓冲堆分配：协程帧只留 8 字节 shared_ptr（两方向各持独立缓冲，避免读写竞争）
                auto Buf = std::make_shared<std::array<std::byte, 65535>>();
                while (true)
                {
                    Net::ip::udp::endpoint SourceEndpoint;
                    boost::system::error_code REc;
                    const auto N = co_await Source.NativeSocket().async_receive_from(
                        Net::buffer(Buf->data(), Buf->size()), SourceEndpoint,
                        Net::redirect_error(Net::use_awaitable, REc));
                    if (REc || N == 0)
                    {
                        co_return;
                    }
                    // 先学习/配对，再查转发目标（首包即配对）
                    Table->Touch(SourceEndpoint, FromIsA);
                    const auto Peer = Table->PeerOf(SourceEndpoint, FromIsA);
                    if (!Peer)
                    {
                        continue; // 未配对/已回收：丢弃
                    }
                    boost::system::error_code WEc;
                    co_await Destination.NativeSocket().async_send_to(
                        Net::buffer(Buf->data(), N), *Peer,
                        Net::redirect_error(Net::use_awaitable, WEc));
                    if (WEc)
                    {
                        co_return;
                    }
                    Table->Touch(SourceEndpoint, FromIsA);
                }
            };

            co_await (RelayOne(*A_, *B_, Assoc, true) ||
                      RelayOne(*B_, *A_, Assoc, false) || RecycleLoop(Assoc));
            A_->Close();
            B_->Close();
            co_return;
        }

    private:
        /**
         * @struct AssocTable
         * @brief 会话关联表（A 端点 ↔ B 端点配对 + 超时时间）
         */
        struct AssocTable
        {
            AssocTable(std::chrono::milliseconds IdleTimeout, std::size_t MaxAssociations)
                : Timeout_(IdleTimeout), MaxAssociations_(MaxAssociations)
            {
            }

            /// 单侧条目：配对端点 + 最后活动时刻
            struct Entry
            {
                Net::ip::udp::endpoint Peer{}; ///< 对端（配对端点）
                std::uint64_t LastSeen{0};    ///< 最后活动（毫秒）
            };

            /**
             * @brief 查询来源配对目标
             * @param src 来源端点
             * @param FromA 来源是否 A 侧
             * @return 配对目标（未配对返回 nullopt）
             */
            [[nodiscard]] auto PeerOf(const Net::ip::udp::endpoint &SourceEndpoint, bool FromA) const
                -> std::optional<Net::ip::udp::endpoint>
            {
                const auto &Table = [&]() -> const decltype(AToB_) & {
                    if (FromA)
                    {
                        return AToB_;
                    }
                    return BToA_;
                }();
                const auto It = Table.find(SourceEndpoint);
                if (It == Table.end() || It->second.Peer == Net::ip::udp::endpoint{})
                {
                    return std::nullopt; // 未学习或未配对
                }
                return It->second.Peer;
            }

            /**
             * @brief 关联/配对：记录来源，与对侧未配对来源配对，刷新活动时间
             * @param src 来源端点（本侧）
             * @param FromA 来源是否 A 侧
             */
            void Touch(const Net::ip::udp::endpoint &SourceEndpoint, bool FromA)
            {
                auto &Self = [&]() -> decltype(AToB_) & {
                    if (FromA)
                    {
                        return AToB_;
                    }
                    return BToA_;
                }();
                auto &Other = [&]() -> decltype(AToB_) & {
                    if (FromA)
                    {
                        return BToA_;
                    }
                    return AToB_;
                }();
                const auto Now = NowMs();
                auto It = Self.find(SourceEndpoint);
                if (It == Self.end())
                {
                    // 新来源：移除本侧旧的未配对条目（单活跃会话简化）
                    for (auto I = Self.begin(); I != Self.end();)
                    {
                        if (I->second.Peer == Net::ip::udp::endpoint{})
                        {
                            I = Self.erase(I);
                        }
                        else
                        {
                            ++I;
                        }
                    }
                    It = Self.emplace(SourceEndpoint, Entry{{}, Now}).first;
                }
                else
                {
                    It->second.LastSeen = Now;
                }
                if (It->second.Peer != Net::ip::udp::endpoint{})
                {
                    return; // 已配对
                }
                // 与对侧最新的未配对来源配对；过期候选直接回收，避免新来源
                // 与陈旧端点配对造成跨会话流量混淆。
                std::optional<Net::ip::udp::endpoint> Best;
                std::uint64_t BestSeen = 0;
                for (auto I = Other.begin(); I != Other.end();)
                {
                    if (I->second.Peer != Net::ip::udp::endpoint{})
                    {
                        ++I;
                        continue;
                    }
                    if (Timeout_.count() > 0 &&
                        Now - I->second.LastSeen > static_cast<std::uint64_t>(Timeout_.count()))
                    {
                        I = Other.erase(I);
                        continue;
                    }
                    if (!Best || I->second.LastSeen > BestSeen)
                    {
                        Best = I->first;
                        BestSeen = I->second.LastSeen;
                    }
                    ++I;
                }
                if (!Best)
                {
                    return; // 无可用候选：等对侧来源
                }
                if (MaxAssociations_ != 0 && PairedCount_ >= MaxAssociations_)
                {
                    // 达到关联上限：拒绝新会话，丢弃两侧未配对占位
                    Other.erase(*Best);
                    Self.erase(It);
                    return;
                }
                It->second.Peer = *Best;
                Other[*Best].Peer = SourceEndpoint;
                ++PairedCount_;
            }

            /**
             * @brief 对称回收超时条目
             * @return 回收条目数
             * @details 未配对条目按自身时间回收；配对条目按两侧最后活动的
             *          较大值判定空闲，并同时移除两侧映射。仅扫描单侧会
             *          让先到且长期未配对的另一侧条目永久残留。
             */
            auto Reap() -> std::size_t
            {
                if (Timeout_.count() <= 0)
                {
                    return 0;
                }
                const auto Now = NowMs();
                const auto Limit = static_cast<std::uint64_t>(Timeout_.count());
                const auto Idle = [&](const std::uint64_t Last) { return Now - Last > Limit; };
                std::size_t Removed = 0;
                // A 侧：未配对按自身时间；配对按两侧最大值
                for (auto It = AToB_.begin(); It != AToB_.end();)
                {
                    auto &Slot = It->second;
                    if (Slot.Peer == Net::ip::udp::endpoint{})
                    {
                        if (Idle(Slot.LastSeen))
                        {
                            It = AToB_.erase(It);
                            ++Removed;
                        }
                        else
                        {
                            ++It;
                        }
                        continue;
                    }
                    const auto PeerIt = BToA_.find(Slot.Peer);
                    if (PeerIt == BToA_.end() || Idle(std::max(Slot.LastSeen, PeerIt->second.LastSeen)))
                    {
                        if (PeerIt != BToA_.end())
                        {
                            BToA_.erase(PeerIt);
                        }
                        It = AToB_.erase(It);
                        if (PairedCount_ > 0)
                        {
                            --PairedCount_;
                        }
                        ++Removed;
                        continue;
                    }
                    ++It;
                }
                // B 侧：未配对同样回收；配对残项（A 侧缺失/已超时）清理
                for (auto It = BToA_.begin(); It != BToA_.end();)
                {
                    auto &Slot = It->second;
                    if (Slot.Peer == Net::ip::udp::endpoint{})
                    {
                        if (Idle(Slot.LastSeen))
                        {
                            It = BToA_.erase(It);
                            ++Removed;
                        }
                        else
                        {
                            ++It;
                        }
                        continue;
                    }
                    const auto PeerIt = AToB_.find(Slot.Peer);
                    if (PeerIt == AToB_.end() || Idle(std::max(Slot.LastSeen, PeerIt->second.LastSeen)))
                    {
                        if (PeerIt != AToB_.end())
                        {
                            AToB_.erase(PeerIt);
                        }
                        It = BToA_.erase(It);
                        if (PairedCount_ > 0)
                        {
                            --PairedCount_;
                        }
                        ++Removed;
                        continue;
                    }
                    ++It;
                }
                return Removed;
            }

            [[nodiscard]] static auto NowMs() -> std::uint64_t
            {
                return static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch())
                        .count());
            }

            std::chrono::milliseconds Timeout_{std::chrono::seconds(60)}; ///< 空闲超时（0 = 禁用）
            std::size_t MaxAssociations_{256};                            ///< 最大并发关联（0 = 不限）
            std::size_t PairedCount_{0};                                  ///< 当前已配对关联数
            std::map<Net::ip::udp::endpoint, Entry> AToB_; ///< A 来源 → 配对
            std::map<Net::ip::udp::endpoint, Entry> BToA_; ///< B 来源 → 配对
        };

        /**
         * @brief 会话回收循环：周期扫描超时会话
         * @param Table 关联表
         */
        [[nodiscard]] auto RecycleLoop(std::shared_ptr<AssocTable> Table) -> Net::awaitable<void>
        {
            if (Opts_.IdleTimeout.count() <= 0)
            {
                // 禁用回收：超长 timer 挂起（不占 socket 读，避免与转发竞争）
                Net::steady_timer Timer(co_await Net::this_coro::executor);
                Timer.expires_after(std::chrono::hours(24));
                boost::system::error_code ErrorCode;
                co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, ErrorCode));
                co_return;
            }
            while (true)
            {
                Net::steady_timer Timer(co_await Net::this_coro::executor);
                Timer.expires_after(Opts_.IdleTimeout);
                boost::system::error_code ErrorCode;
                co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, ErrorCode));
                if (ErrorCode == Net::error::operation_aborted)
                {
                    // 组取消是一次性的：吞掉取消将使 || 组永不完成并泄漏 socket
                    co_return;
                }
                Table->Reap();
            }
        }

        std::shared_ptr<Preview::Transport::Unreliable> A_; ///< 端 A
        std::shared_ptr<Preview::Transport::Unreliable> B_; ///< 端 B
        RelayOptions Opts_;                               ///< 中继选项
    };

} // namespace Preview::Network::Udp
