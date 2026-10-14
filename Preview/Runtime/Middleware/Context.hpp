/**
 * @file Context.hpp
 * @brief 中间件管线上下文
 * @details DataPlane 是协议接入后的唯一目标、身份、租约和根传输来源。
 *          Context 另外持有出站传输及会话运行服务，中间件原地装饰根传输。
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <utility>

#include <boost/asio/awaitable.hpp>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Lifecycle/TaskState.hpp>
#include <Preview/Net/Target.hpp>
#include <Preview/Contract/Ingress/DataPlane.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Transport/PadPolicy.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Foundation/Utility/TrafficSink.hpp>

namespace Preview::Runtime
{

    class SessionControl;

} // namespace Preview::Runtime

namespace Preview::Middleware
{

    /**
     * @class Context
     * @brief 管线执行上下文
     * @details 协议工厂结果移入 DataPlane；具名访问器直接引用该唯一事实。
     *          Dial 产出的 Outbound 按运行阶段存活，最终关闭由 Session relay 拥有。
     */
    class Context
    {
    public:
        /// 协议握手后的 typed 数据面；Session 只消费该字段进行分派。
        Preview::Contract::ProtocolDataPlane DataPlane{};
        /// listener 提交的稳定任务身份（值语义，不持有 registry）。
        Preview::Lifecycle::TaskIdentity TaskIdentity{};
        std::shared_ptr<Preview::Runtime::SessionControl> Control{};
        /// 上游传输（Dial 中间件产出，relay 中间件消费）
        Preview::SharedTransmission Outbound;
        /// 入站 peer IP；按会话拥有，不放入共享服务配置。
        std::string SourceIp;
        /// 协议专用接入回调的受控名称，供识别结果为 Unknown 时记录 Accept 失败。
        std::string ProtocolNameForLog{};
        /// 拨号函数签名：成功交出 owning 传输（非空），失败保留领域码与原生 cause。
        using DialFn = std::function<boost::asio::awaitable<
            std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>(
                const Preview::Network::Target &)>;

        /// 流量统计 owner；relay 与 detached 数据面只消费这一份 shared sink。
        std::shared_ptr<Preview::Foundation::TrafficSink> Traffic{};
        /// 真正worker块池，装饰器只共享现有容量，不创建会话局部最大池。
        std::shared_ptr<Preview::Memory::BytePool> Bytes{};
        /// 当前 Session 的 worker-owned 出站拨号函数；mux 子流必须继承该 owner。
        DialFn Dial{};
        /// 填充配置（可选，pad 中间件消费）
        struct PadConfig
        {
            bool Enabled{false};
            std::shared_ptr<const Preview::Transport::PadConfig> Policy{}; ///< 冷编译且不可变的数值范围。
        };
        const PadConfig *Pad{nullptr};
        /// 缓冲区大小（relay 中间件消费）
        std::size_t BufferSize{16384};
        /// 管线空闲超时（>0 时 relay 优先使用；0 = 用 relay 构造参数）
        std::chrono::milliseconds Timeout{0};

        /** @brief 移入唯一握手结果；不复制认证或目标事实。 */
        auto SetDataPlane(Preview::Contract::ProtocolDataPlane Value) -> void
        {
            DataPlane = std::move(Value);
        }

        [[nodiscard]] auto Inbound() noexcept -> Preview::SharedTransmission&
        {
            return std::visit([](auto& Root) -> Preview::SharedTransmission&
                { return Root.Transport; }, DataPlane.Root);
        }
        [[nodiscard]] auto Inbound() const noexcept -> const Preview::SharedTransmission&
        {
            return std::visit([](const auto& Root) -> const Preview::SharedTransmission&
                { return Root.Transport; }, DataPlane.Root);
        }
        [[nodiscard]] auto Target() noexcept -> Preview::Network::Target& { return DataPlane.Target; }
        [[nodiscard]] auto Target() const noexcept -> const Preview::Network::Target& { return DataPlane.Target; }
        [[nodiscard]] auto Identity() noexcept -> std::string& { return DataPlane.Identity; }
        [[nodiscard]] auto Identity() const noexcept -> const std::string& { return DataPlane.Identity; }
        [[nodiscard]] auto DisplayIdentity() noexcept -> std::string& { return DataPlane.DisplayIdentity; }
        [[nodiscard]] auto DisplayIdentity() const noexcept -> const std::string& { return DataPlane.DisplayIdentity; }
        [[nodiscard]] auto AccountId() noexcept -> Preview::AccountId& { return DataPlane.AccountId; }
        [[nodiscard]] auto AccountId() const noexcept -> const Preview::AccountId& { return DataPlane.AccountId; }
        [[nodiscard]] auto AccountLease() noexcept -> Preview::Account::AccountLease& { return DataPlane.AccountLease; }
        [[nodiscard]] auto AccountLease() const noexcept -> const Preview::Account::AccountLease& { return DataPlane.AccountLease; }
        [[nodiscard]] auto ProtocolAuthenticated() noexcept -> bool& { return DataPlane.ProtocolAuthenticated; }
        [[nodiscard]] auto ProtocolAuthenticated() const noexcept -> const bool& { return DataPlane.ProtocolAuthenticated; }
        [[nodiscard]] auto PostDial() noexcept -> decltype(DataPlane.PostDial)& { return DataPlane.PostDial; }
        [[nodiscard]] auto IsDatagram() const noexcept -> bool { return DataPlane.IsDatagram(); }

        [[nodiscard]] auto UserForLog() const -> std::string
        {
            if (!DataPlane.DisplayIdentity.empty())
            {
                return DataPlane.DisplayIdentity;
            }
            if (DataPlane.AccountId)
            {
                return std::to_string(DataPlane.AccountId.Value());
            }
            return {};
        }


    };

} // namespace Preview::Middleware
