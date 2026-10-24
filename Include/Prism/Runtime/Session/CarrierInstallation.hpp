/** @file CarrierInstallation.hpp @brief 实际传输字段的原域验证和唯一pin-view移交。 */
#pragma once

#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Runtime/CarrierDomain.hpp>
#include <Prism/Runtime/ActiveTransports.hpp>

#include <expected>
#include <memory>

namespace Prism::Runtime
{
    /** @brief 验证阶段不移交输入；成功安装后用同一字段消费实际pin alias，不遗留原生副本。 */
    class SessionCarrierInstallation final
    {
    public:
        /** @brief 在接受阶段一次性安装数据面唯一 root owner，覆盖进入 relay 前的失败路径。 */
        [[nodiscard]] static auto AcceptedDataPlane(
            ActiveTransports& Active,
            Prism::Contract::ProtocolDataPlane& DataPlane)
            -> std::expected<void, Prism::Fault::Failure>;

        /**
         * @brief 在会话真实owner接管入站操作能力。
         * @details Carrier 引用只借用至返回；Activity 执行器是物理执行域事实。
         * 报告执行器不一致仍交给 Active 的拒绝 owner 保留。成功替换为实际资源/context
         * view，必须持有到 completion 退出。
         * 原executor、取消和最终关闭属于Carrier实际owner，本操作不实现半关闭。
         */
        [[nodiscard]] static auto Inbound(ActiveTransports& Active, Prism::SharedTransmission& Carrier)
            -> std::expected<void, Prism::Fault::Failure>;

        /** @brief 出站移交与入站遵守同一原域和操作 view 合同，失败不在调用线程回收实物。 */
        [[nodiscard]] static auto Outbound(ActiveTransports& Active, Prism::SharedTransmission& Carrier)
            -> std::expected<void, Prism::Fault::Failure>;

    private:
        /** @brief 按协议会话 Activity 固定 owner 域；Activity 无效时用载体域保留拒绝输入。 */
        [[nodiscard]] static auto CreateProtocolDomain(
            std::shared_ptr<Prism::Contract::CarrierActivity> Activity,
            const Prism::SharedTransmission& Carrier)
            -> std::expected<CarrierDomain, Prism::Fault::Failure>;

        /** @brief Datagram root session 是唯一关闭 owner，Transport 仅随数据面保活。 */
        [[nodiscard]] static auto InstallDatagram(
            ActiveTransports& Active,
            Prism::Contract::DatagramDataPlane& Datagram)
            -> std::expected<void, Prism::Fault::Failure>;

        /** @brief Mux root session 是唯一关闭 owner，Transport 仅随数据面保活。 */
        [[nodiscard]] static auto InstallMux(
            ActiveTransports& Active,
            Prism::Contract::MuxRootDataPlane& Mux)
            -> std::expected<void, Prism::Fault::Failure>;

        /** @brief 优先使用 Activity 执行器；只在保留拒绝载体时退回报告执行器。 */
        [[nodiscard]] static auto CreateDomain(const Prism::SharedTransmission& Carrier)
            -> std::expected<CarrierDomain, Prism::Fault::Failure>;
    };
}
