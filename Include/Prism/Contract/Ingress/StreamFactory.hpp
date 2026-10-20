/** @file StreamFactory.hpp @brief 唯一协议接入工厂与请求元数据。 */
#pragma once

#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <Prism/Contract/Ingress/RequestMetadata.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <boost/asio/awaitable.hpp>

#include <memory>
#include <string_view>

namespace Prism::Contract
{
    /**
     * @struct StreamAcceptInput
     * @brief 协议接入的唯一 owning 输入。
     * @details Inbound、Metadata、Bytes 与同代状态按值移交给 Accept；Inbound 是共享传输
     *          owner，Metadata 拥有身份与 trace 快照，Bytes 是真实有界字节池 owner。
     *          字节池不隐藏在 Metadata 中，也不存在拆开的旧参数入口或 fallback。
     */
    struct StreamAcceptInput final
    {
        Prism::SharedTransmission Inbound{};
        RequestMetadata Metadata{};
        std::shared_ptr<Prism::Memory::BytePool> Bytes{};
        std::shared_ptr<Prism::Foundation::GenerationUseState> GenerationUseState;
    };

    /**
     * @brief 工厂持有认证及协议服务，Accept 接管入站共享所有权。
     * @details 在入站 executor 运行，协程取消传播到握手 I/O；失败时协议关闭
     *          已取得的流并释放租约。成功值唯一拥有认证结果；stream 支持半关闭，
     *          最终关闭交给数据面执行者，datagram 最终关闭始终归协议 session。
     *          输入的 Inbound、Metadata 和 Bytes 只能由这个单一 typed 参数进入，
     *          调用者交付后不再保留其移交副本。
     */
    class StreamFactory
    {
    public:
        virtual ~StreamFactory() = default;
        [[nodiscard]] virtual auto Accept(StreamAcceptInput Input)
            -> boost::asio::awaitable<AcceptOutcome> = 0;
        [[nodiscard]] virtual auto Name() const -> std::string_view = 0;
    };
}
