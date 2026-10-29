/** @file Association.hpp @brief 每 id 独立的 DNS/send/receive 全阶段期限和真实 drain。 */
#pragma once
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <system_error>
#include <utility>
#include <vector>
#include <Prism/Protocols/Vless/Xudp/Detail/State.hpp>
#include <Prism/Protocols/Common/Datagram/Deadline.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/udp.hpp>

namespace Prism::Vless::Xudp
{
    [[nodiscard]] auto MakeTrafficObservation(
        const std::shared_ptr<State> &Root,
        const std::shared_ptr<Association> &Value) -> Prism::Foundation::TrafficObservation;

    [[nodiscard]] auto AssociationPhysicallyRetired(
        const std::shared_ptr<Association>& Value) noexcept -> bool;

    auto FinishAssociation(
        const std::shared_ptr<State>& Root,
        const std::shared_ptr<Association>& Value) -> void;

    auto UnlinkRetiringAssociation(
        const std::shared_ptr<State>& Root,
        const std::shared_ptr<Association>& Value) -> void;

    auto DrainAssociation(const std::shared_ptr<State>& Root,
        const std::shared_ptr<Association>& Value) -> Net::awaitable<bool>;

    /** @brief 重试 active 与 End 后关联；只在 socket/子任务真实退休后释放 lease。 */
    auto RetireAssociationOwners(const std::shared_ptr<State>& Root)
        -> Net::awaitable<bool>;

    /** @brief 当前 association executor 更新真实活动期限；计时 owner 只关闭本 id。 */
    auto Touch(const std::shared_ptr<State>& Root, const std::shared_ptr<Association>& Value) -> void;
    auto OpenSocket(const std::shared_ptr<State>& Root,
        const std::shared_ptr<Association>& Value, Net::ip::udp::endpoint Target) -> bool;
    /** @brief 一次发送拥有 Packet，DNS/send 全阶段期限由 sender await；回包由独立 receiver。 */
    auto Send(std::shared_ptr<State> Root, std::shared_ptr<Association> Value, Frame Packet)
        -> Net::awaitable<Prism::Fault::Code>;
    auto Work(std::shared_ptr<State> Root, std::shared_ptr<Association> Value) -> Net::awaitable<void>;
    /** @brief 持私有 socket 连续接收全部回包；地址族切换的旧 receive 先退栈再进入新 epoch。 */
    auto Receive(std::shared_ptr<State> Root, std::shared_ptr<Association> Value) -> Net::awaitable<void>;
    /** @brief 独立 idle owner；真实 DNS、发送、收包或 writer 挂起都会被本 id 的 deadline 取消并 join。 */
    auto Idle(std::shared_ptr<State> Root, std::shared_ptr<Association> Value) -> Net::awaitable<void>;
    auto RunWorker(std::shared_ptr<State> Root, std::shared_ptr<Association> Value) -> Net::awaitable<void>;
    /** @brief 外部 owning task 等 association 自己的 scope，scope 内没有等待自身的 runner。 */
    auto RunAssociation(std::shared_ptr<State> Root, std::shared_ptr<Association> Value) -> Net::awaitable<void>;
    auto RejectAssociation(std::shared_ptr<State> Root, std::uint16_t Id) -> Net::awaitable<void>;
    auto StartAssociation(std::shared_ptr<State> Root, Frame Packet) -> bool;
}
