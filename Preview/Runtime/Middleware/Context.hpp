/**
 * @file Context.hpp
 * @brief 中间件管线上下文
 * @details 在中间件链中传递的共享状态：目标地址、流量统计、
 * 传输所有权、检测结果、填充配置等。对应生产库 forward_pipeline
 * 的 pipeline_options 职责。
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

#include <boost/asio/awaitable.hpp>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Account/Credential.hpp>
#include <Preview/Account/Lease.hpp>
#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Lifecycle/TaskState.hpp>
#include <Preview/Net/Target.hpp>
#include <Preview/Runtime/Contract/DataPlane.hpp>
#include <Preview/Transport/Transmission.hpp>
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
     * @details 持有管线内共享的数据：入站传输（可被中间件替换）、
     * 目标地址、协议检测结果、流量统计指针。中间件通过修改
     * Inbound 实现"包装"语义（如 pad/mux 装饰）。
     */
    class Context
    {
    public:
        /// 协议握手后的 typed 数据面；Session 只消费该字段进行分派。
        Preview::Runtime::ProtocolDataPlane DataPlane{};
        /// listener 提交的稳定任务身份（值语义，不持有 registry）。
        Preview::Lifecycle::TaskIdentity TaskIdentity{};
        std::shared_ptr<Preview::Runtime::SessionControl> Control{};
        /// 认证后的 typed 账户身份；租约仍由 DataPlane owner 持有。
        Preview::AccountId AccountId{};
        /// 入站传输（中间件可替换包装）
        Preview::SharedTransmission Inbound;
        /// 上游传输（Dial 中间件产出，relay 中间件消费）
        Preview::SharedTransmission Outbound;
        /// 目标地址（拨号中间件消费）
        Preview::Network::Target Target;
        /// 检测到的协议类型
        std::uint16_t detected{0};
        /// Dgram 会话标记（AcceptProtocol 设置；Session 转走 udp_service）
        bool IsDgram{false};
        /**
         * @brief 流量统计接口兼容别名
         * @details 具体接口位于 Foundation，保留该别名以兼容
         *          运行时调用方并阻止协议层依赖完整 Context。
         */
        using TrafficSink = Preview::Foundation::TrafficSink;

        /// 流量统计回调（relay 中间件消费）
        TrafficSink *traffic{nullptr};
        /// 认证通过后的用户标识（Auth 中间件写入，relay 统计按此聚合）
        std::string identity{};
        /// 协议接入器已完成凭据认证时，跳过通用 Auth 中间件
        bool ProtocolAuthenticated{false};
        /// 认证通过后的账户租约，持有期间计入并发连接配额
        Preview::Account::AccountLease AccountLease{};
        /// 通用认证输入的 secure 所有权；不保存原始 secret 字符串。
        std::shared_ptr<const Preview::Account::Credential> Credential{};
        /// 非敏感身份标签（例如 SOCKS5 用户名或远端标识）。
        std::string RawIdentity{};
        /// 填充配置（可选，pad 中间件消费）
        struct PadConfig
        {
            bool Enabled{false};
            std::size_t MinSize{64};
            std::size_t MaxSize{1024};
        };
        const PadConfig *pad{nullptr};
        /// 缓冲区大小（relay 中间件消费）
        std::size_t BufferSize{16384};
        /// 管线空闲超时（>0 时 relay 优先使用；0 = 用 relay 构造参数）
        std::chrono::milliseconds timeout{0};
        /// 拨号完成回调（协议注入：拨号成功/失败后发送协议级应答）
        std::function<boost::asio::awaitable<void>(Preview::Fault::Code)> PostDial{};

        /**
         * @brief 安装 secure 认证凭据
         * @param Value 凭据所有权移交
         */
        auto SetCredential(Preview::Account::Credential Value) -> void
        {
            Credential = std::make_shared<const Preview::Account::Credential>(std::move(Value));
        }

        /**
         * @brief 安装协议数据面并同步 Session 需要的值语义元数据
         * @param Value 协议数据面（所有权移交）
         */
        auto SetDataPlane(Preview::Runtime::ProtocolDataPlane Value) -> void
        {
            DataPlane = std::move(Value);
            Target = DataPlane.Target;
            identity = DataPlane.Identity;
            AccountId = DataPlane.AccountId;
            ProtocolAuthenticated = DataPlane.ProtocolAuthenticated;
            PostDial = DataPlane.PostDial;
            if (DataPlane.AccountLease)
            {
                AccountLease = std::move(*DataPlane.AccountLease);
            }
            if (const auto Transport = DataPlane.Transport())
            {
                Inbound = Transport;
            }
        }

        /**
         * @brief 将中间件替换后的 Inbound 回写到 typed 流数据面
         */
        auto SynchronizeDataPlane() noexcept -> void
        {
            if (auto *Stream = DataPlane.Stream())
            {
                Stream->Transport = Inbound;
            }
            else if (auto *Datagram = DataPlane.Datagram())
            {
                Datagram->Transport = Inbound;
            }
            else if (auto *Mux = DataPlane.Mux())
            {
                Mux->Transport = Inbound;
            }
        }

        /**
         * @brief 将旧入口输入物化为 typed 根数据面
         * @param DatagramService 旧会话服务的值语义回调
         * @details 该适配只位于 Context 边界，Session 不读取旧标志。
         */
        auto MaterializeDataPlane(Preview::Runtime::DatagramDataPlane::ServiceFn DatagramService)
            -> void
        {
            if (DataPlane.HasTransport())
            {
                if (auto *Datagram = DataPlane.Datagram(); Datagram && !Datagram->Service)
                {
                    Datagram->Service = std::move(DatagramService);
                }
                return;
            }
            if (IsDgram)
            {
                DataPlane.Root = Preview::Runtime::DatagramDataPlane{Inbound,
                                                                       std::move(DatagramService)};
            }
            else
            {
                DataPlane.Root = Preview::Runtime::StreamDataPlane{Inbound};
            }
        }
    };

} // namespace Preview::Middleware
