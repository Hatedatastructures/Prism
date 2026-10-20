/** @file Relay.hpp @brief Runtime 与协议共用的有界可靠中继契约。 */
#pragma once

#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <memory>

namespace Prism::Contract::Services
{
    class FirstTransferObserver;
}

namespace Prism::Network::Relay
{
    namespace Net = boost::asio;

    /**
     * @brief 移交两端、共享 worker 字节池和冻结策略。
     * @details Inbound、Outbound 与 Bytes 由中继 owner 共享持有至两方向及退休 Drain 完成；每方向
     *          借用一个独占池块至 pump 返回。FirstTransfer 是可选观察 owner，每个方向首次成功写出后
     *          至多通知一次。IdleTimeout 为零时不创建监视任务。请求不拥有 executor context。
     */
    struct Request final
    {
        SharedTransmission Inbound;
        SharedTransmission Outbound;
        std::size_t BufferSize{16 * 1024};
        std::chrono::milliseconds IdleTimeout{0};
        Foundation::TrafficObservation Observation{};
        std::shared_ptr<Memory::BytePool> Bytes;
        std::shared_ptr<Prism::Contract::Services::FirstTransferObserver> FirstTransfer;
    };

    /** @brief 成功写出字节、首因与每个方向的失败事实；EOF 半关闭不记为业务失败。 */
    struct Result final
    {
        Fault::Failure Failure;
        std::array<std::size_t, 2> Total{};
        std::array<Fault::Failure, 2> DirectionFailure{};
    };

    /**
     * @brief 接管两端并执行有界双向中继。
     * @param Input 按值移交两个传输、worker 字节池与观察 owner。
     * @return 每个方向实际成功的字节数与领域/原生首因；普通取消作为 Canceled 值返回。
     * @details 准入失败时仍关闭并 Drain 已移交载体；正常运行时在入站原 executor 的串行域推进。
     *          EOF 只半关闭对应目标的写方向，保留反向读取；错误或取消停止两端。最终 Close 由该 owner
     *          发起，返回前等待两侧 activity 的真实 Drain；调用方保持 executor context 运行至完成。
     */
    [[nodiscard]] auto Run(Request Input) -> Net::awaitable<Result>;
}
