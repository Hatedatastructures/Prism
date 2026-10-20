/**
 * @file UdpAssocBindGate.hpp
 * @brief SOCKS5 UDP_ASSOCIATE bind 与 BND wire 的唯一准入 owner。
 * @details 单次 bind/reply 与并发 Run 共用 typed 结果；每个等待调用保留独立取消和操作预约。
 */
#pragma once

#include <Prism/Protocols/Socks5/UdpAssocRetirement.hpp>
#include <Prism/Protocols/Socks5/AddressCodec.hpp>
#include <Prism/Protocols/Socks5/MessageCodec.hpp>
#include <Prism/Protocols/Socks5/TransportCodec.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/system/error_code.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <vector>

namespace Prism::Socks5
{
    namespace Net = boost::asio;

    /**
     * @class UdpAssocBindGate
     * @brief 拥有一次性 UDP bind、BND 回复和并发等待结果。
     * @details 状态只在关联 strand 上访问；退休 owner 持有本操作 reservation 与失败回执。
     */
    class UdpAssocBindGate final : public std::enable_shared_from_this<UdpAssocBindGate>
    {
    public:
        using Endpoint = Net::ip::udp::endpoint;
        using Result = ReplyResult<std::size_t>;

        /** @brief 在关联 executor 上创建并绑定唯一退休 owner。 */
        UdpAssocBindGate(Net::any_io_executor Executor,
                         std::shared_ptr<UdpAssocRetirement> Retirement);

        /**
         * @brief 执行或等待唯一的 bind 与 BND 回复。
         * @return 完整 wire 字节数或保留协议码、Native 与 partial progress 的失败。
         * @note 首个调用启动底层操作；取消等待者只结束自己的等待，不取消共享操作。
         */
        [[nodiscard]] auto Run() -> Net::awaitable<Result>;

        /** @brief 返回 bind 成功后的本地 BND 端点。 */
        [[nodiscard]] auto LocalEndpoint() const -> Endpoint;

        /** @brief 返回已绑定时用于 SOCKS5 peer 检查的控制端点快照。 */
        [[nodiscard]] auto ControlPeer() const -> std::optional<Endpoint>
        {
            return ControlPeer_;
        }

    private:
        enum class Action
        {
            Start,
            Wait,
            Completed,
        };

        /** @brief 只由 strand 调用，选择唯一执行者或共享等待者。 */
        [[nodiscard]] auto Enter() noexcept -> Action;

        /** @brief 等待首个调用发布结果；本 timer 仅属于当前 waiter。 */
        [[nodiscard]] auto Wait() -> Net::awaitable<Result>;

        /** @brief 绑定并记录 socket/native 失败；不发送第二份 BND wire。 */
        [[nodiscard]] auto BindSockets(const UdpAssocRetirement::ControlEndpointSnapshot &Control)
            -> ReplyResult<Endpoint>;

        /** @brief 把原生 socket 失败同时投递到 public Drain 与当前 bind 结果。 */
        [[nodiscard]] auto SocketFailure(const boost::system::error_code ErrorCode)
            -> ReplyFailure;

        /** @brief setup 失败后尽力提交 GeneralFailure，并保留原始 typed/native cause。 */
        [[nodiscard]] auto SendGeneralFailure(
            const std::shared_ptr<Conn<>> &Tcp,
            ReplyFailure Failure) -> Net::awaitable<Result>;

        /** @brief 在唯一调用者中绑定并提交完整 BND 应答。 */
        [[nodiscard]] auto BindAndReplyCore() -> Net::awaitable<Result>;

        /** @brief 发布唯一结果后再唤醒全部等待者。 */
        auto Complete(Result Value) -> void;

        /** @brief 构造单一 typed 协议/传输失败结果。 */
        [[nodiscard]] static auto FailureResult(
            const Error Protocol,
            const Prism::Fault::Failure Transport,
            const std::size_t Bytes) -> Result
        {
            return std::unexpected(ReplyFailure{Protocol, Transport, Bytes});
        }

        Net::any_io_executor Executor_;
        std::shared_ptr<UdpAssocRetirement> Retirement_;
        std::vector<std::weak_ptr<Net::steady_timer>> Waiters_;
        std::optional<Result> Result_;
        std::optional<Endpoint> BoundEndpoint_;
        std::optional<Endpoint> ControlPeer_;
        bool Running_{false};
    };
}
