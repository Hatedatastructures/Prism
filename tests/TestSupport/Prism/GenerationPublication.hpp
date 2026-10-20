/** @file GenerationPublication.hpp @brief 配置阶段账户在集成测试中的真实发布。 */
#pragma once

#include <Prism/Application/AccountCatalog.hpp>
#include <Prism/Runtime/GenerationPublication.hpp>

#include <expected>
#include <memory>

namespace Prism::Testing
{
    /** @brief 按生产启动顺序发布配置阶段账户，并返回必须保活的 authority owner。 */
    [[nodiscard]] inline auto PublishConfiguredAccountCatalog(
        Prism::Application::AccountCatalog& Catalog,
        const Prism::Foundation::GenerationPin& Generation)
        -> std::expected<std::shared_ptr<Prism::Runtime::GenerationPublication>,
            Prism::Fault::Failure>
    {
        if (!Catalog.Store || !Catalog.Identities || !Catalog.IdentityPreparation || !Generation)
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }

        auto Publication = std::make_shared<Prism::Runtime::GenerationPublication>();
        const auto Attached = Catalog.Identities->RuntimeRegistry()->AttachAdmissionAuthority(Publication);
        if (!Attached) return std::unexpected(Attached.error());

        const auto Staged = Catalog.IdentityPreparation->StageCommit();
        if (!Staged) return std::unexpected(Staged.error());

        auto Prepared = Publication->Prepare({}, Generation, Catalog.Store->AccountIds());
        if (!Prepared)
        {
            if (Catalog.RuntimeTransaction)
            {
                Catalog.RuntimeTransaction->Rollback();
            }
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        if (Catalog.RuntimeTransaction)
        {
            const auto RuntimePublished = Catalog.RuntimeTransaction->Publish();
            if (!RuntimePublished)
            {
                return std::unexpected(RuntimePublished.error());
            }
        }
        const auto Published = Publication->Publish(*Prepared);
        if (!Published)
        {
            if (Catalog.RuntimeTransaction)
            {
                Catalog.RuntimeTransaction->Rollback();
            }
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }

        const auto Committed = Catalog.IdentityPreparation->Commit();
        if (!Committed) return std::unexpected(Committed.error());
        if (Catalog.RuntimeTransaction)
        {
            Catalog.RuntimeTransaction->Finalize();
        }
        return Publication;
    }
}
