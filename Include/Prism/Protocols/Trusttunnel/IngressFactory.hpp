/**
 * @file IngressFactory.hpp
 * @brief TrustTunnel wire-proof 与 typed protocol Accept owner。
 * @details HTTP/2 carrier 先由 Http2Accept 完成 TLS、settings、CONNECT 和
 *          Basic wire proof，再由本 owner 进行账户 Authenticate、目标解析、
 *          lease 移交和唯一 ProtocolDataPlane 发布。底层 HTTP/2 transport 与
 *          wire-proof owner 均为模块私有实现，调用方只能接收认证后的 handoff。
 */

#pragma once

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Contract/Ingress/StreamFactory.hpp>
#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Protocols/Trusttunnel/Types.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace Prism::Trusttunnel
{

    namespace Net = boost::asio;

    class AuthenticatedTransport;

    namespace Detail
    {
        class Http2Accept;
        class CarrierOwner;
    }

    struct WireAuthBinding;

    [[nodiscard]] auto MakeWireAuthBinding(
        ServerConfig Configuration,
        Prism::SharedAuthenticator Authenticator)
        -> std::shared_ptr<const WireAuthBinding>;

    using SharedWireAuthBinding = std::shared_ptr<const WireAuthBinding>;

    /**
     * @class AuthenticatedTransport
     * @brief Http2Accept 完成 wire 认证后发布的不可伪造 carrier handoff。
     * @details 构造函数和发布入口只对 Detail::Http2Accept 开放，普通调用方不能伪造
     *          carrier handoff。该对象只保存 carrier owner 与 authority，
 *          不保存账户身份或 lease。不可变
     *          binding pin 由 carrier owner 保留至完整物理退休后释放。
     */
    class AuthenticatedTransport final : public Prism::Transmission
    {
    public:
        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto RequiresExternalCloseReceipt() const noexcept -> bool override
        {
            return true;
        }

        /** @brief 部分读取；结果与借用沿正式前门交付一次。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override;

        /** @brief 部分写入；保留 carrier 侧短写语义。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override;

        /** @brief 真实写半关闭：只提交 END_STREAM，保留反向读取能力。 */
        auto StartWriteShutdown(Completion Handler) -> void override;

        /** @brief 交付 carrier 关闭；实际退出由 carrier driver 生命周期另行等待。 */
        [[nodiscard]] auto OnClose() -> ControlResult override;

        /** @brief 可重复取消 carrier 挂起操作；成功只表示命令已接管。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override;

        auto SetTimeout(const std::chrono::milliseconds Timeout) -> void override;

        [[nodiscard]] auto IsOpen() const -> bool override;

        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission * override;

        [[nodiscard]] auto NextLayer() const noexcept
            -> const Prism::Transmission * override;

        [[nodiscard]] auto Authority() const noexcept -> std::string_view
        {
            return Authority_;
        }

    private:
        friend class Detail::Http2Accept;
        friend class IngressFactory;

        AuthenticatedTransport(std::shared_ptr<Detail::CarrierOwner> Owner,
                               std::string Authority);

        [[nodiscard]] static auto CreateForHandshake(
            std::shared_ptr<Detail::CarrierOwner> Owner,
            std::string Authority)
            -> std::shared_ptr<AuthenticatedTransport>;

        /** @brief 读取当前 owner 的 generation pin；物理退休后返回空绑定。 */
        [[nodiscard]] auto Binding() const noexcept
            -> const SharedWireAuthBinding &;

        ExecutorType Executor_;
        std::shared_ptr<Detail::CarrierOwner> Owner_;
        std::string Authority_;
        std::shared_ptr<Prism::Contract::CarrierActivity> Activity_;
    };

    /**
     * @struct IngressOptions
     * @brief TrustTunnel 的 wire 配置与 typed 账户认证器。
     * @details ServerConfig 只用于核对 carrier 已完成的 wire 认证材料；账户
     *          AccountId/AccountLease 必须由 Authenticator 在本 owner 中取得。
     */
    struct IngressOptions final
    {
        SharedWireAuthBinding Binding{};
    };

    /**
     * @class IngressFactory
     * @brief TrustTunnel 的唯一 protocol Accept owner。
     * @details Accept 只接受 AuthenticatedTransport。成功时将 authority、typed
     *          identity、AccountId、AccountLease 和 stream carrier 一起交给 Admit；
     *          失败或异常由 InboundAdmission 负责取消与关闭，支持 carrier EOF、
     *          half-close 和最终 close 的既有 Transport 合同。
     */
    class IngressFactory final : public Prism::Contract::StreamFactory
    {
        using Failure = Prism::Fault::Failure;

    public:
        explicit IngressFactory(IngressOptions Options)
            : Options_(std::move(Options))
        {
        }

        auto Accept(Prism::Contract::StreamAcceptInput Input)
            -> Net::awaitable<std::expected<
                Prism::Contract::ProtocolDataPlane, Prism::Fault::Failure>> override;

        [[nodiscard]] auto Name() const -> std::string_view override
        {
            return "trusttunnel";
        }

    private:
        /** @brief 在旧 TrustTunnel wire 错误边界映射正式 typed Failure 分类。 */
        [[nodiscard]] static auto ToAdmissionFailure(const Prism::Error Error) noexcept -> Failure;

        struct Authority final
        {
            std::string Host;
            std::uint16_t Port{0};
        };

        [[nodiscard]] static auto ParseAuthority(const std::string_view Value)
            -> std::optional<Authority>;

        IngressOptions Options_;
    };

} // namespace Prism::Trusttunnel
