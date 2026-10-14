/** @file ConfigurationCommandOutcome.hpp @brief 把真实配置首因转换为安全公开校验结果。 */
#pragma once
#include <Preview/Application/Configuration/ConfigurationError.hpp>
#include <Preview/Operations/Models.hpp>
#include <string_view>
namespace Preview::Application::ConfigurationCommandOutcome
{
    /** @brief 配置错误枚举一次映射为稳定值；不回显输入、secret或解析器正文。 */
    [[nodiscard]] inline auto CodeName(Configuration::ConfigurationErrorCode Code) noexcept -> std::string_view
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
    /** @brief 校验拒绝尚未发布配置，保留真实字段与类别；没有网络关闭或半关闭行为。 */
    [[nodiscard]] inline auto Invalid(const Preview::RequestId Correlation,
        const Configuration::ConfigurationError& Error) -> Preview::Operations::CommandResult
    {
        auto Result = Preview::Operations::CommandResult::Invalid(Correlation);
        Result.Message = "configuration_invalid";
        Result.Failure = {Preview::Fault::Code::ConfigErr};
        Result.ConfigurationIssues.push_back({std::string(CodeName(Error.Code)), Error.Path,
            "配置字段未通过当前服务端校验"});
        return Result;
    }
}
