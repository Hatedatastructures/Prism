/** @file Outcome.cpp @brief 稳定映射配置错误结果。 */

#include <Prism/Application/Configuration/Command/Detail/Outcome.hpp>

#include <string>

namespace Prism::Application::ConfigurationCommandOutcome
{

    auto CodeName(const Configuration::ConfigurationErrorCode Code) noexcept
        -> std::string_view
    {
        using Value = Configuration::ConfigurationErrorCode;
        switch (Code)
        {
        case Value::Parse: return "parse";
        case Value::UnknownField: return "unknown_field";
        case Value::MissingField: return "missing_field";
        case Value::InvalidType: return "invalid_type";
        case Value::FileOpen: return "file_open";
        case Value::UnsupportedSchemaVersion: return "unsupported_schema_version";
        case Value::InvalidValue: return "invalid_value";
        case Value::DuplicateId: return "duplicate_id";
        case Value::MissingReference: return "missing_reference";
        case Value::UnknownMuxMode: return "unknown_mux_mode";
        case Value::InvalidCarrierOptions: return "invalid_carrier_options";
        case Value::UnresolvedSecret: return "unresolved_secret";
        case Value::MissingCapability: return "missing_capability";
        case Value::InvalidConfiguration: return "invalid_configuration";
        case Value::InvalidGeneration: return "invalid_generation";
        case Value::HotReloadDisabled: return "hot_reload_disabled";
        case Value::MissingAcknowledgement: return "missing_acknowledgement";
        case Value::WorkerRejected: return "worker_rejected";
        case Value::PublishConflict: return "publish_conflict";
        }
        return "invalid_configuration";
    }

    auto Invalid(const Prism::RequestId Correlation,
        const Configuration::ConfigurationError &Error) -> Prism::Operations::CommandResult
    {
        auto Result = Prism::Operations::CommandResult::Invalid(Correlation);
        Result.Message = "configuration_invalid";
        Result.Failure = {Prism::Fault::Code::ConfigErr};
        Result.ConfigurationIssues.push_back({std::string(CodeName(Error.Code)), Error.Path,
            "配置字段未通过当前服务端校验"});
        return Result;
    }

} // namespace Prism::Application::ConfigurationCommandOutcome
