/** @file Stream.hpp @brief 通用拨号与双向流转发的独立 owning 能力端口。 */
#pragma once
#include <Preview/Net/Target.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Account/Lease.hpp>
#include <Preview/Contract/Ingress/RequestMetadata.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Foundation/Utility/TrafficSink.hpp>
#include <cstddef>
#include <chrono>
#include <expected>
namespace Preview::Contract
{
    class StreamEgress
    {
    public:
        virtual ~StreamEgress()=default;
        /** @brief 接管目标，取消随 coroutine 传播；成功返回 owning transport，caller 负责半关闭与最终关闭。
         *         失败返回 `Failure{Code, Native}` 且不携带传输，失败侧 socket 已由拨号 owner 关闭。 */
        [[nodiscard]] virtual auto Connect(Preview::Network::Target Target)
            -> boost::asio::awaitable<std::expected<Preview::SharedTransmission,Preview::Fault::Failure>> = 0;
    };
    /** @brief child 的 owning 拨号、idle/buffer 和观察快照；无 Runtime/worker/registry 查找。 */
    struct StreamServices final
    {
        std::shared_ptr<StreamEgress> Egress;
        std::shared_ptr<Preview::Foundation::TrafficSink> Traffic;
        std::chrono::milliseconds IdleTimeout{0};
        std::size_t BufferSize{16 * 1024};
        /** @brief 同一实际网络 owner 的共享块池，供子流分段缓冲；不查全局服务。 */
        std::shared_ptr<Preview::Memory::BytePool> Bytes;
    };
    struct StreamRelayRequest final
    {
        Preview::SharedTransmission Inbound,Outbound;
        Preview::Network::Target Target;
        Preview::AccountId AccountId;
        std::string Identity;
        Preview::Account::StreamLease Lease;
        /** @brief 真实 admission 元数据；取消和最终关闭仍由 owning relay/lease 负责。 */
        Preview::Contract::RequestMetadata Metadata{};
        /** @brief 前置写入且已成功的字节，避免协议准备阶段被 relay 统计遗漏。 */
        std::size_t InitialUploadBytes{0};
    };
    class StreamRelay
    {
    public:
        virtual ~StreamRelay()=default;
        /** @brief 接管两端与已获得的唯一 stream lease，保留半关闭；最终关闭并在退栈后归还租约。 */
        [[nodiscard]] virtual auto Run(StreamRelayRequest Request)
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> = 0;
    };
}
