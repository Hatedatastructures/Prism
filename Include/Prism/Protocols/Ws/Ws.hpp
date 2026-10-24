/**
 * @file Ws.hpp
 * @brief WebSocket 的类型化建连与接收接口。
 * @details factory 接管流传输与 byte pool；成功时返回唯一 StreamTransport owner。
 */
#pragma once

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace Prism::Ws
{
    namespace Net = boost::asio;

    struct ClientOptions final
    {
        std::string Host;
        std::string Key{"dGhlIHNhbXBsZSBub25jZQ=="};
    };

    struct ServerOptions final
    {
        std::string Path{"/"};
        std::string Host;
    };

    struct ConnectOptions final
    {
        SharedTransmission Transport;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
        ClientOptions Client;
    };

    struct AcceptOptions final
    {
        SharedTransmission Transport;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
        ServerOptions Server;
    };

    class StreamTransport;

    struct ConnectResult final
    {
        std::string Accept;
        std::shared_ptr<StreamTransport> Connection;
    };

    struct AcceptResult final
    {
        std::string Key;
        std::shared_ptr<StreamTransport> Connection;
    };

    /**
     * @brief 已完成 Upgrade 的 WebSocket 流传输 owner。
     * @details executor 固定继承自底层传输；ReadSome/WriteSome 通过 Transmission 返回 IoResult。
     *          Cancel 只取消挂起操作，WriteShutdown 只半关闭本地写向；Close 交付底层关闭，
     *          实际退休由 Activity()->Drain() 等待。Release 仅在活动排空后移交底层 owner。
     */
    class StreamTransport final : public Prism::Transmission
    {
    public:
        /** @brief 销毁已退役的 WebSocket facade 和其私有协议 owner。 */
        ~StreamTransport() override;

        /** @brief 返回继承自底层传输的固定 executor。 */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override;

        /** @brief 返回 facade、私有 WebSocket owner 与底层载体的组合活动回执。 */
        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override;

        /** @brief 返回下一层实际传输。 */
        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission * override;

        /** @brief 返回下一层实际传输的常量视图。 */
        [[nodiscard]] auto NextLayer() const noexcept
            -> const Prism::Transmission * override;

        /** @brief 活动排空后移交已退休的底层传输。 */
        [[nodiscard]] auto Release() -> SharedTransmission override;

    private:
        /** @brief 只在编译单元内持有 WebSocket 状态机与模板组件。 */
        struct Impl;

        /** @brief 接管底层传输与 byte pool，初始化本连接的 WebSocket owner。 */
        explicit StreamTransport(
            SharedTransmission Transport,
            std::shared_ptr<Prism::Memory::BytePool> Bytes,
            bool Client);

        /** @brief 在客户端 Upgrade 握手中发送请求并校验服务端响应。 */
        [[nodiscard]] auto WriteHandshake(std::string_view Key, std::string_view Host)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /** @brief 在服务端 Upgrade 握手中读取请求并发送响应。 */
        [[nodiscard]] auto ReadHandshake(
            std::string &Key,
            std::string_view ExpectedPath,
            std::string_view ExpectedHost)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /** @brief 返回本连接握手生成的 Sec-WebSocket-Accept。 */
        [[nodiscard]] auto Accept() const noexcept -> const std::string &;

        /** @brief 启动基类已预约的消息读取操作。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override;

        /** @brief 启动基类已预约的 binary 帧写入操作。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override;

        /** @brief 将半关闭操作交给本连接的写 owner。 */
        auto StartWriteShutdown(Completion Handler) -> void override;

        /** @brief 将最终关闭交给本连接的底层 owner。 */
        [[nodiscard]] auto OnClose() -> ControlResult override;

        /** @brief 将取消交给本连接的底层 owner。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override;

        /** @brief 持有不暴露到公共头的 WebSocket 内部实现。 */
        std::unique_ptr<Impl> Impl_;
        friend auto Connect(ConnectOptions Options)
            -> Net::awaitable<std::expected<ConnectResult, Prism::Fault::Failure>>;
        friend auto Accept(AcceptOptions Options)
            -> Net::awaitable<std::expected<AcceptResult, Prism::Fault::Failure>>;
    };

    /**
     * @brief 接管底层传输与 byte pool，执行客户端 Upgrade 握手。
     * @param Options 含被接管的底层传输、连接 byte pool 和客户端握手字段。
     * @return 成功时返回 Accept 值与活动中的 WebSocket owner；失败返回握手或退休结果。
     * @details 失败时沿准备好的 admission ticket 关闭并排空已接管的传输；成功后调用方负责
     *          关闭连接并等待其 Activity 排空。
     */
    [[nodiscard]] auto Connect(ConnectOptions Options)
        -> Net::awaitable<std::expected<ConnectResult, Prism::Fault::Failure>>;

    /**
     * @brief 接管底层传输与 byte pool，读取并校验服务端 Upgrade 请求。
     * @param Options 含被接管的底层传输、连接 byte pool 和服务端路径/主机约束。
     * @return 成功时返回客户端 key 与活动中的 WebSocket owner；失败返回握手或退休结果。
     * @details 失败时沿准备好的 admission ticket 关闭并排空已接管的传输；成功后调用方负责
     *          关闭连接并等待其 Activity 排空。
     */
    [[nodiscard]] auto Accept(AcceptOptions Options)
        -> Net::awaitable<std::expected<AcceptResult, Prism::Fault::Failure>>;
}
