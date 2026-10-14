/** @file StreamEgress.hpp @brief Contract::StreamEgress 端口：把 TCP 拨号全部委托给唯一 Dialer engine。 */

#pragma once

#include <Preview/Contract/Services/Stream.hpp>
#include <Preview/Net/Dialer/Dialer.hpp>

#include <chrono>
#include <memory>
#include <system_error>
#include <utility>

namespace Preview::Network
{
    /** @brief 冷路径注入 executor、DNS owner 与拨号总 deadline；不含协议选择。 */
    struct StreamEgressOptions final
    {
        boost::asio::any_io_executor Executor;
        std::shared_ptr<Preview::Network::Dns::Resolver> Resolver;
        std::chrono::milliseconds Timeout;
    };

    /**
     * @class StreamEgress
     * @brief 拥有唯一拨号 engine 的 StreamEgress 实现。
     * @details 目标按值交给 engine；取消随 await 传播，失败不留下活跃候选或 socket。
     *          成功传输的半关闭与最终关闭由返回 owner 负责。
     */
    class StreamEgress final : public Preview::Contract::StreamEgress
    {
    public:
        explicit StreamEgress(StreamEgressOptions Options)
            : Dialer_(Options.Executor,
                  Preview::Network::Dialer::DialOptions{Options.Timeout, true, std::move(Options.Resolver)})
        {
        }

        /** @brief 一次拨号：直接转发唯一 engine 的唯一结果形状，失败保留原生 cause。 */
        [[nodiscard]] auto Connect(Preview::Network::Target Target)
            -> boost::asio::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>> override
        {
            co_return co_await Dialer_.Connect(std::move(Target));
        }

    private:
        Preview::Network::Dialer::Dialer Dialer_;
    };
} // namespace Preview::Network
