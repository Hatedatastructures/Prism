/**
 * @file QuicConnection.hpp
 * @brief QUIC 首包接入、owner 身份与关闭的中立契约。
 * @details 本文件不声明或包含具体 QUIC 实现。协议模块实现 owner 与冷路径 factory，
 *          Boundary 只通过该契约处理 CID、peer、UDP 入站、关闭请求和真实 drain。
 */
#pragma once

#include <Preview/Contract/Ingress/ProviderFailure.hpp>
#include <Preview/Contract/Ingress/RequestMetadata.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <cstddef>

namespace Preview::Contract
{
    /** @brief Boundary 分流和关闭决策所需的稳定状态快照。 */
    struct QuicConnectionState final
    {
        bool HandshakeReady{false};
        bool Closed{false};
    };

    /**
     * @brief 单条协议 QUIC 连接的真实 owner 端口。
     * @details 实现者必须固定一个串行 executor。ReceivePacket 只在该 executor 同步借用
     *          payload 与 peer；Start 和 RequestClose 在同一 executor 上完成状态交接。
     *          RequestClose 成功表示同一 owner 已接受或已接受该请求；拒绝返回 typed
     *          Failure，owner 保持可重试。成功请求也不代表协程、stream/datagram child 已退出；
     *          Drain 继续等待真实退出并返回首个 Fault。最终 UDP socket 仍归 Boundary 关闭。
     */
    class QuicConnectionOwner
    {
    public:
        virtual ~QuicConnectionOwner() = default;

        /**
         * @brief 在 owner executor 上启动已构造连接。
         * @note 输入在 factory 创建时已接管；该方法不取得 packet 或额外资源所有权。
         */
        virtual auto Start() -> void = 0;

        /**
         * @brief 同步借用 UDP payload 与 peer，并报告协议 Native 是否接受该包。
         * @param Payload 仅在本次调用期间有效的包视图。
         * @param Peer 按值稳定保存的远端 UDP peer。
         * @return 接受返回 true；无效状态或协议拒绝返回 false。
         */
        [[nodiscard]] virtual auto ReceivePacket(
            std::span<const std::byte> Payload,
            const boost::asio::ip::udp::endpoint& Peer) -> bool = 0;

        /** @brief 原子读取握手与关闭快照，不泄露协议实现类型。 */
        [[nodiscard]] virtual auto State() const noexcept -> QuicConnectionState = 0;

        /**
         * @brief 请求 owner 在固定 executor 上取消并关闭协议连接。
         * @return 成功表示命令已接受或先前已接受；失败表示尚未接受，可用同一 owner 重试。
         * @note 该调用不等待退栈；随后仍须 await Drain 确认真实完成。
         */
        [[nodiscard]] virtual auto RequestClose() noexcept
            -> std::expected<void, Preview::Fault::Failure> = 0;

        /**
         * @brief 请求关闭并等待 Native 与协议 child 真实退栈。
         * @return 成功表示 owner 已完成 drain；失败保留首个 Fault::Failure。
         * @details awaitable 必须自行保活 owner，并在 owner executor 上完成；超时/取消
         *          不能冒充完成，最终 socket close 仍由 Boundary listener 执行。
         */
        [[nodiscard]] virtual auto Drain()
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> = 0;
    };

    class QuicIngressBindingSnapshot;

    /** @brief 一条 QUIC connection 唯一拥有的代次使用预约；不可复制，真实 Drain 后释放。 */
    class QuicConnectionGenerationLease final
    {
    public:
        QuicConnectionGenerationLease() noexcept = default;
        QuicConnectionGenerationLease(const QuicConnectionGenerationLease&) = delete;
        auto operator=(const QuicConnectionGenerationLease&) -> QuicConnectionGenerationLease& = delete;
        QuicConnectionGenerationLease(QuicConnectionGenerationLease&&) noexcept = default;
        auto operator=(QuicConnectionGenerationLease&&) noexcept -> QuicConnectionGenerationLease& = default;

        [[nodiscard]] auto Generation() const noexcept -> Preview::GenerationId { return Generation_; }
        [[nodiscard]] auto BindingId() const noexcept -> std::string_view { return BindingId_; }
        [[nodiscard]] explicit operator bool() const noexcept
        { return static_cast<bool>(Generation_) && !BindingId_.empty() && static_cast<bool>(Use_); }

    private:
        friend class QuicIngressBindingSnapshot;
        QuicConnectionGenerationLease(
            const Preview::GenerationId Generation,
            std::string BindingId,
            Preview::Foundation::GenerationUseLease Use) noexcept
            : Generation_(Generation), BindingId_(std::move(BindingId)), Use_(std::move(Use))
        {
        }

        Preview::GenerationId Generation_{};
        std::string BindingId_;
        Preview::Foundation::GenerationUseLease Use_;
    };

    /** @brief 接管首包 CID、peer、完成观察者、请求元数据与唯一代次预约。 */
    struct QuicAcceptRequest final
    {
        /** @brief 值拥有的首包目标 CID。 */
        std::vector<std::byte> ConnectionId;
        /** @brief 值拥有的远端 UDP peer。 */
        boost::asio::ip::udp::endpoint Peer;
        /** @brief owner 完成后通知 Boundary 清除全部关联 alias。 */
        std::function<void()> OnClosed;
        /** @brief 借用调用方已拥有的值身份；缺失字段保持空值。 */
        Preview::Contract::RequestMetadata Metadata{};
        /** @brief 当前编译绑定的唯一代次预约；创建后移入 Native owner，CID alias 不复制。 */
        QuicConnectionGenerationLease GenerationUse;
    };

    /**
     * @brief move-only QUIC owner 租约。
     * @details 身份在租约存续期间稳定，用于 CID alias 判等。Boundary 持有 lease；Protocol
     *          catalog 也可在冷装配时持有同一 owner 并调用 Drain。显式调用者须检查关闭回执；析构只尽力请求关闭，不等待。
     */
    class QuicConnectionLease final
    {
    public:
        explicit QuicConnectionLease(std::shared_ptr<QuicConnectionOwner> Owner)
            : Owner_(std::move(Owner))
        {
        }

        QuicConnectionLease(QuicConnectionLease&& Other) noexcept
            : Owner_(std::move(Other.Owner_))
        {
        }

        auto operator=(QuicConnectionLease&& Other) noexcept -> QuicConnectionLease&
        {
            if (this != &Other)
            {
                (void)RequestClose();
                Owner_ = std::move(Other.Owner_);
            }
            return *this;
        }

        QuicConnectionLease(const QuicConnectionLease&) = delete;
        auto operator=(const QuicConnectionLease&) -> QuicConnectionLease& = delete;
        ~QuicConnectionLease() { (void)RequestClose(); }

        /** @brief 返回仅用于 alias 判等的稳定 owner 身份，不转移所有权。 */
        [[nodiscard]] auto Identity() const noexcept -> const QuicConnectionOwner*
        {
            return Owner_.get();
        }

        /** @brief 复制中立 owner 句柄，供已接管的外部 lease pin 保活。 */
        [[nodiscard]] auto SharedOwner() const noexcept -> std::shared_ptr<QuicConnectionOwner>
        {
            return Owner_;
        }

        /** @brief 启动协议 owner；空租约无操作。 */
        auto Start() -> void
        {
            if (Owner_)
            {
                Owner_->Start();
            }
        }

        /** @brief 将本次借用包交给协议 owner；空租约拒绝。 */
        [[nodiscard]] auto ReceivePacket(
            std::span<const std::byte> Payload,
            const boost::asio::ip::udp::endpoint& Peer) const -> bool
        {
            return Owner_ && Owner_->ReceivePacket(Payload, Peer);
        }

        /** @brief 读取中立状态；空租约视为已关闭。 */
        [[nodiscard]] auto State() const noexcept -> QuicConnectionState
        {
            if (!Owner_)
            {
                return {false, true};
            }
            return Owner_->State();
        }

        /**
         * @brief 请求同一 owner 接受关闭；空租约成功。
         * @return 未接受时保留 Failure，调用者仍可在 lease 存续期间重试。
         */
        [[nodiscard]] auto RequestClose() noexcept
            -> std::expected<void, Preview::Fault::Failure>
        {
            return Owner_ ? Owner_->RequestClose()
                          : std::expected<void, Preview::Fault::Failure>{};
        }

        /** @brief 请求关闭并等待 owner 真实 drain；空租约成功完成。 */
        [[nodiscard]] auto Drain()
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            return DrainOwned(Owner_);
        }

    private:
        /** @brief 创建 awaitable 时即接管 owner，允许原租约在首次调度前释放。 */
        [[nodiscard]] static auto DrainOwned(std::shared_ptr<QuicConnectionOwner> Owner)
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            if (!Owner)
            {
                co_return std::expected<void, Preview::Fault::Failure>{};
            }
            co_return co_await Owner->Drain();
        }

        std::shared_ptr<QuicConnectionOwner> Owner_;
    };

    /** @brief 每个已编译 listener 的冷路径工厂；热路径不按名称查找。 */
    class QuicConnectionFactory
    {
    public:
        virtual ~QuicConnectionFactory() = default;

        /** @brief 接管首包请求并返回完整 owner lease 或配置/资源失败。 */
        [[nodiscard]] virtual auto Create(QuicAcceptRequest Request)
            -> std::expected<QuicConnectionLease, ProviderFailure> = 0;

        /** @brief 只在 Close 后、Native/control/协议 child 全部真实退栈时返回 true。 */
        [[nodiscard]] virtual auto IsRetired() const noexcept -> bool = 0;
    };

    /** @brief 单一代次预编译 QUIC listener binding 与新 CID admission 的 typed factory snapshot。 */
    class QuicIngressBindingSnapshot final
    {
    public:
        struct Binding final
        {
            std::string Id;
            std::shared_ptr<QuicConnectionFactory> Factory;
        };

        struct Options final
        {
            Preview::Foundation::GenerationPin Generation;
            std::shared_ptr<Preview::Foundation::GenerationUseState> UseState;
            Preview::Contract::RequestMetadata Metadata{};
            std::optional<Binding> Listener;
        };

        explicit QuicIngressBindingSnapshot(Options Value)
            : Generation_(std::move(Value.Generation)), UseState_(std::move(Value.UseState)),
              Metadata_(std::move(Value.Metadata)), Listener_(std::move(Value.Listener))
        {
        }

        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            if (!Generation_ || !UseState_ || !Metadata_.TaskIdentity.Generation ||
                Metadata_.TaskIdentity.Generation != Generation_->Id())
            {
                return false;
            }
            return !Listener_ || (!Listener_->Id.empty() && static_cast<bool>(Listener_->Factory));
        }

        [[nodiscard]] auto GenerationOwner() const noexcept
            -> const Preview::Foundation::GenerationPin& { return Generation_; }
        [[nodiscard]] auto Generation() const noexcept -> Preview::GenerationId
        { return Generation_ ? Generation_->Id() : Preview::GenerationId{}; }
        [[nodiscard]] auto UseState() const noexcept
            -> const std::shared_ptr<Preview::Foundation::GenerationUseState>& { return UseState_; }
        [[nodiscard]] auto Metadata() const -> Preview::Contract::RequestMetadata { return Metadata_; }
        [[nodiscard]] auto HasListener() const noexcept -> bool
        { return Listener_.has_value() && static_cast<bool>(Listener_->Factory); }
        [[nodiscard]] auto ListenerBindingId() const noexcept -> std::string_view
        { return Listener_ ? std::string_view(Listener_->Id) : std::string_view{}; }
        [[nodiscard]] auto Factory() const noexcept -> std::shared_ptr<QuicConnectionFactory>
        { return Listener_ ? Listener_->Factory : std::shared_ptr<QuicConnectionFactory>{}; }

        /** @brief 新 CID 唯一预约一次；已知 CID 与别名不得调用。 */
        [[nodiscard]] auto AcquireUse() const
            -> std::expected<QuicConnectionGenerationLease, Preview::Fault::Failure>
        {
            if (!IsValid() || !HasListener())
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::NotSupported});
            }
            auto Use = UseState_->Acquire();
            if (!Use)
            {
                return std::unexpected(Use.error());
            }
            return QuicConnectionGenerationLease{
                Generation(), Listener_->Id, std::move(*Use)};
        }

    private:
        const Preview::Foundation::GenerationPin Generation_;
        const std::shared_ptr<Preview::Foundation::GenerationUseState> UseState_;
        const Preview::Contract::RequestMetadata Metadata_;
        const std::optional<Binding> Listener_;
    };
}
