/** @file CarrierInstallation.hpp @brief 实际传输字段的原域验证和唯一pin-view移交。 */
#pragma once

#include <Preview/Runtime/ActiveTransports.hpp>

namespace Preview::Runtime
{
    /** @brief 验证阶段不移交输入；成功安装后用同一字段消费实际pin alias，不遗留原生副本。 */
    class SessionCarrierInstallation final
    {
    public:
        /**
         * @brief 在会话真实owner接管入站操作能力。
         * @details Carrier 引用只借用至返回；Activity 执行器是物理执行域事实。
         * 报告执行器不一致仍交给 Active 的拒绝 owner 保留。成功替换为实际资源/context
         * view，必须持有到 completion 退出。
         * 原executor、取消和最终关闭属于Carrier实际owner，本操作不实现半关闭。
         */
        [[nodiscard]] static auto Inbound(ActiveTransports& Active, Preview::SharedTransmission& Carrier)
            -> std::expected<void, Preview::Fault::Failure>
        {
            if (!Carrier) return {};
            auto Domain = CreateDomain(Carrier);
            if (!Domain) return std::unexpected(Domain.error());
            auto Installed = Active.StoreInbound(std::move(Carrier), *Domain);
            if (!Installed) return std::unexpected(Installed.error());
            Carrier = std::move(*Installed);
            return {};
        }

        /** @brief 出站移交与入站遵守同一原域和操作 view 合同，失败不在调用线程回收实物。 */
        [[nodiscard]] static auto Outbound(ActiveTransports& Active, Preview::SharedTransmission& Carrier)
            -> std::expected<void, Preview::Fault::Failure>
        {
            if (!Carrier) return {};
            auto Domain = CreateDomain(Carrier);
            if (!Domain) return std::unexpected(Domain.error());
            auto Installed = Active.StoreOutbound(std::move(Carrier), *Domain);
            if (!Installed) return std::unexpected(Installed.error());
            Carrier = std::move(*Installed);
            return {};
        }

    private:
        /** @brief 优先使用 Activity 执行器；只在保留拒绝载体时退回报告执行器。 */
        [[nodiscard]] static auto CreateDomain(const Preview::SharedTransmission& Carrier)
            -> std::expected<CarrierDomain, Preview::Fault::Failure>
        {
            const auto Activity = Carrier->Activity();
            auto Domain = CarrierDomain::Create(
                Activity ? Activity->Executor() : Carrier->Executor(), Activity);
            if (Domain) return Domain;
            auto HoldingDomain = CarrierDomain::Create(Carrier->Executor(), {});
            if (HoldingDomain) return HoldingDomain;
            return std::unexpected(Domain.error());
        }
    };
}
