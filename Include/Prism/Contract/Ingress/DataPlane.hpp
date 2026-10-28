/**
 * @file DataPlane.hpp
 * @brief 会话根数据面契约
 * @details 数据面以值语义 variant 区分可靠流与数据报服务。协议层只
 *          负责构造 ProtocolDataPlane，Session 只消费 RootDataPlane，
 *          不再通过布尔标志或 RTTI 猜测数据面形态。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <expected>
#include <functional>
#include <Prism/Contract/Ingress/Datagram/Session.hpp>
#include <Prism/Contract/Ingress/MuxSession.hpp>
#include <Prism/Contract/Ingress/Protocol.hpp>
#include <memory>
#include <optional>
#include <string>
#include <variant>

#include <Prism/Account/Lease.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Contract
{

    namespace Net = boost::asio;

    namespace Ingress
    {

        /**
         * @brief 为 root 数据面之外的 provider 接入资源提供 session 级最终关闭和 drain。
         * @details Runtime 在 root Run 结束并释放数据面 view 后调用 Drain，再退休共享 inbound。
         *          Drain 请求关闭并等待额外 carrier 的真实 Activity 退休；未完成时实现保留 owner
         *          与原 executor，并返回 typed failure。调用方持有对象直到 drain 结束。
         */
        class SessionRetirementOwner
        {
        public:
            virtual ~SessionRetirementOwner() = default;

            /** @brief 请求关闭并 drain 此 session 独占的额外接入资源。 */
            [[nodiscard]] virtual auto Drain()
                -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> = 0;
        };

    } // namespace Ingress

    /**
     * @struct StreamDataPlane
     * @brief 可靠、可半关闭的流数据面
     * @details 握手成功后由工厂移交；在 Transport executor 运行，取消传播到流 I/O。
     *          Session relay 持有根传输直到双向转发退出并负责最终关闭。
     */
    struct StreamDataPlane final
    {
        /// 拨号成功后一次性包装出站流；输入共享所有权，空结果表示装饰失败。
        using OutboundDecoratorFn = std::function<Prism::SharedTransmission(
            Prism::SharedTransmission)>;

        Prism::SharedTransmission Transport{};
        /// 冷路径装饰器；Session 在 Active outbound 发布前调用，Relay 负责最终关闭。
        OutboundDecoratorFn OutboundDecorator{};
    };

    /**
     * @struct DatagramDataPlane
     * @brief 协议数据报数据面
     * @details Session 是协议拥有的运行、取消、drain 和最终关闭者。
     *          Transport 仅保活握手后的控制载体，执行者通过 Session 关闭，
     *          不单独关闭该观察句柄；Run 完成表示该关联全部异步操作已退栈。
     */
    struct DatagramDataPlane final
    {
        Prism::SharedTransmission Transport{};
        std::shared_ptr<DatagramSession> Session{};
    };

    /**
     * @brief 多路复用根的正式协议 owner 与传输观察句柄。
     * @details 工厂移交共享传输；运行在该流 executor，Mux owner 负责子流取消、
     *          drain 和根传输最终关闭，子流半关闭按各自流合同执行。
     */
    struct MuxRootDataPlane final
    {
        Prism::SharedTransmission Transport{};
        std::shared_ptr<MuxSession> Session{};
    };

    /// Session 使用的根数据面；variant 类型本身表达数据面形态。
    using RootDataPlane = std::variant<StreamDataPlane, DatagramDataPlane, MuxRootDataPlane>;

    /**
     * @struct ProtocolDataPlane
     * @brief 协议握手结果及其根数据面
     * @details 账户租约随该对象移动到 Session 所有权边界；AccountId 是
     *          值语义身份，即使租约之后被释放也不会产生悬空引用。
     */
    struct ProtocolDataPlane final
    {
        ProtocolDataPlane() = default;
        ProtocolDataPlane(const ProtocolDataPlane&) = delete;
        auto operator=(const ProtocolDataPlane&) -> ProtocolDataPlane& = delete;
        ProtocolDataPlane(ProtocolDataPlane&&) noexcept = default;
        auto operator=(ProtocolDataPlane&&) noexcept -> ProtocolDataPlane& = default;

        ProtocolType Protocol{ProtocolType::Unknown};
        RootDataPlane Root{};
        /// Provider 握手期间创建的额外 carrier owner；Runtime 在 root Run 后、inbound 退休前 drain。
        std::shared_ptr<Ingress::SessionRetirementOwner> AdmissionOwner{};
        Prism::Network::Target Target{};
        std::string Identity{};
        std::string DisplayIdentity{};
        Prism::AccountId AccountId{};
        Prism::Account::AccountLease AccountLease{};
        bool ProtocolAuthenticated{false};
        /// 上游拨号完成后的协议应答回调；输入会话状态，返回应答写入状态。
        /** @brief 拨号后只调用一次的协议回复；按值借用失败事实，完整返回回复 I/O 失败。
         * @details 输入保留拨号 Code/Native，Runtime 仍拥有其首因；输出只表示回复操作结果。
         *          callback 持有自身传输 owner 至 await 完成，沿传输 executor 取消、半关闭和最终关闭。
         */
        std::function<Net::awaitable<Prism::Fault::Failure>(Prism::Fault::Failure)> PostDial{};

        [[nodiscard]] auto IsStream() const noexcept -> bool
        {
            return std::holds_alternative<StreamDataPlane>(Root);
        }

        [[nodiscard]] auto IsDatagram() const noexcept -> bool
        {
            return std::holds_alternative<DatagramDataPlane>(Root);
        }

        [[nodiscard]] auto IsMux() const noexcept -> bool
        {
            return std::holds_alternative<MuxRootDataPlane>(Root);
        }

        [[nodiscard]] auto Stream() noexcept -> StreamDataPlane *
        {
            return std::get_if<StreamDataPlane>(&Root);
        }

        [[nodiscard]] auto Stream() const noexcept -> const StreamDataPlane *
        {
            return std::get_if<StreamDataPlane>(&Root);
        }

        [[nodiscard]] auto Datagram() noexcept -> DatagramDataPlane *
        {
            return std::get_if<DatagramDataPlane>(&Root);
        }

        [[nodiscard]] auto Datagram() const noexcept -> const DatagramDataPlane *
        {
            return std::get_if<DatagramDataPlane>(&Root);
        }

        [[nodiscard]] auto Mux() noexcept -> MuxRootDataPlane *
        {
            return std::get_if<MuxRootDataPlane>(&Root);
        }

        [[nodiscard]] auto Mux() const noexcept -> const MuxRootDataPlane *
        {
            return std::get_if<MuxRootDataPlane>(&Root);
        }

        [[nodiscard]] auto HasTransport() const noexcept -> bool
        {
            const auto *StreamValue = Stream();
            if (StreamValue)
            {
                return static_cast<bool>(StreamValue->Transport);
            }
            const auto *DatagramValue = Datagram();
            if (DatagramValue)
            {
                return static_cast<bool>(DatagramValue->Transport);
            }
            const auto *MuxValue = Mux();
            return MuxValue && static_cast<bool>(MuxValue->Transport);
        }

        [[nodiscard]] auto Transport() const noexcept -> Prism::SharedTransmission
        {
            if (const auto *StreamValue = Stream())
            {
                return StreamValue->Transport;
            }
            if (const auto *DatagramValue = Datagram())
            {
                return DatagramValue->Transport;
            }
            if (const auto *MuxValue = Mux())
            {
                return MuxValue->Transport;
            }
            return {};
        }
    };

    /// 拒绝结果只含 typed cause，不允许携带可转发的成功值。
    using AcceptOutcome = std::expected<ProtocolDataPlane, Prism::Fault::Failure>;

    /**
     * @brief 校验正式数据面不变量；关闭与退休由预预约 admission owner 执行。
     * @details 本函数不取得资源、不关闭、不释放 lease；失败值随后交给
     *          InboundAdmission::Admit，以便关闭和真实 drain 完成前保留完整 owner。
     *          静态凭据允许无账户；账户身份存在时必须与有效租约属于同一记录。
     */
    [[nodiscard]] inline auto Validate(const ProtocolDataPlane& Plane) noexcept
        -> Prism::Fault::Failure
    {
        if (!Plane.HasTransport())
            return {Prism::Fault::Code::IoError};
        else if (static_cast<bool>(Plane.AccountId) != static_cast<bool>(Plane.AccountLease))
            return {Prism::Fault::Code::AuthFailed};
        else if (Plane.AccountLease && Plane.AccountLease.AccountId() != Plane.AccountId)
            return {Prism::Fault::Code::AuthFailed};
        else if (const auto* Datagram = Plane.Datagram(); Datagram && !Datagram->Session)
            return {Prism::Fault::Code::NotSupported};
        else if (const auto* Mux = Plane.Mux(); Mux && !Mux->Session)
            return {Prism::Fault::Code::NotSupported};
        return {};
    }

    /**
     * @brief 将协议私有 wire error 在唯一 ingress 边界显式转换为正式 Failure。
     * @param Error 协议状态机产生的 code；不携带也不伪造 Native cause。
     * @return 领域码保持 Fault 映射，Native 为空。
     */
    [[nodiscard]] inline auto FailureFromProtocolError(Prism::Error Error) noexcept
        -> Prism::Fault::Failure
    {
        return {Prism::Fault::ToCode(Prism::make_error_code(Error))};
    }

} // namespace Prism::Contract
