/** @file Reload.cpp @brief Operations 配置 reload 持久化实现。 */
#include <Prism/Application/Operations/Reload/Detail/Reload.hpp>

#include <cstddef>
#include <string>

namespace Prism::Application::OperationsReload
{

    namespace
    {

        class SensitiveJsonWiper final
        {
        public:
            explicit SensitiveJsonWiper(std::string &Value) noexcept : Value_(&Value)
            {
            }

            ~SensitiveJsonWiper()
            {
                if (Value_)
                {
                    volatile char *Bytes = Value_->data();
                    for (std::size_t Index = 0; Index < Value_->size(); ++Index)
                    {
                        Bytes[Index] = '\0';
                    }
                    Value_->clear();
                }
            }

            SensitiveJsonWiper(const SensitiveJsonWiper &) = delete;
            auto operator=(const SensitiveJsonWiper &) -> SensitiveJsonWiper & = delete;

        private:
            std::string *Value_;
        };

    } // namespace

    auto RunPersistedReload(PersistedReloadRequest Request) -> Net::awaitable<Outcome>
    {
        (void)Request.PersistenceLease;
        const auto Prepared = co_await Prism::Application::Reload::PrepareGenerationReload(
            Request.State, Request.Work);
        if (!Prepared)
            co_return co_await Prism::Application::Reload::PublicationTransaction::Abort(
                Request.State, std::move(Request.Work.Candidate), Prepared.error());
        auto Json = Configuration::ConfigurationParser::SerializeJson(
            Request.Work.Candidate->Generation->Configuration());
        if (!Json)
            co_return co_await Prism::Application::Reload::PublicationTransaction::Abort(
                Request.State, std::move(Request.Work.Candidate),
                Failure{Prism::Fault::Code::InvalidArgument});
        SensitiveJsonWiper JsonWiper(*Json);
        auto File = Prism::Application::OperationsConfigurationPersistence::FileTransaction::Replace(
            Request.State->ConfigurationPath, *Json, Request.Operation);
        if (!File)
            co_return co_await Prism::Application::Reload::PublicationTransaction::Abort(
                Request.State, std::move(Request.Work.Candidate), File.error());
        const auto Published = co_await Prism::Application::Reload::PublicationTransaction::PublishPreparedReload(
            Request.State, std::move(*Prepared));
        if (!Published)
        {
            const auto Restored = File->Rollback();
            if (!Restored) co_return std::unexpected(Restored.error());
            co_return Published;
        }
        File->Commit();
        co_return Published;
    }

} // namespace Prism::Application::OperationsReload
