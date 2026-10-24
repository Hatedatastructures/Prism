/**
 * @file ValidationCompareCase.hpp
 * @brief 配置校验对照工具的固定场景和 Parser 语义入口。
 */
#pragma once

#include "ValidationCompare.hpp"

#include <Prism/Application/Configuration/Configuration.hpp>
#include <Prism/Composition/Builtin/Snapshot.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

namespace Prism::Application::Configuration::Perf::Scenario
{

    using ConfigurationErrorCode =
        Prism::Application::Configuration::ConfigurationErrorCode;
    using ConfigurationParser = Prism::Application::Configuration::ConfigurationParser;
    using ConfigurationValidator = Prism::Application::Configuration::ConfigurationValidator;
    using PreviewConfiguration =
        Prism::Application::Configuration::PreviewConfiguration;
    using ValidationOptions =
        Prism::Application::Configuration::ValidationOptions;
    using ValidationRequest =
        Prism::Application::Configuration::ValidationRequest;
    using BuiltinSnapshot = Prism::Composition::Builtin::BuiltinSnapshot;
    using SnapshotPointer = std::shared_ptr<const BuiltinSnapshot>;

    inline constexpr std::uint64_t FnvOffset = 14695981039346656037ull;

    struct ExpectedError final
    {
        bool Invalid{false};
        ConfigurationErrorCode Code{ConfigurationErrorCode::InvalidConfiguration};
        std::string_view Path{};
    };

    struct ScenarioSpec final
    {
        std::size_t Nodes{64};
        std::uint64_t Seed{0};
        ScenarioKind Kind{ScenarioKind::Valid};
    };

    struct Scenario final
    {
        PreviewConfiguration Configuration{};
        std::string Json;
        std::size_t Nodes{0};
        std::uint64_t TraceHash{FnvOffset};
        ScenarioKind Kind{ScenarioKind::Valid};
        ExpectedError Expected{};
    };

    struct ErrorView final
    {
        bool Present{false};
        ConfigurationErrorCode Code{ConfigurationErrorCode::InvalidConfiguration};
        std::string Path;
    };

    /** @brief 按场景类型返回 parser/validator 的唯一预期错误。 */
    [[nodiscard]] auto MakeExpectedError(ScenarioKind Kind) -> ExpectedError;

    /** @brief 返回固定场景的 CLI/report 名称。 */
    [[nodiscard]] auto ScenarioName(ScenarioKind Kind) -> const char *;

    /** @brief 构造固定节点数的可序列化场景。 */
    [[nodiscard]] auto MakeScenario(const ScenarioSpec &Spec) -> Scenario;

    /** @brief 从外部 JSON 输入加载并按选定场景校验预期错误。 */
    [[nodiscard]] auto LoadScenario(const Options &Settings,
                                    const SnapshotPointer &Builtins) -> Scenario;

    /** @brief 创建共享 parser/validator 选项。 */
    [[nodiscard]] auto MakeValidationOptions(const SnapshotPointer &Builtins)
        -> ValidationOptions;

    /** @brief 创建静态 builtin 快照。 */
    [[nodiscard]] auto MakeStaticBuiltinSnapshot() -> SnapshotPointer;

    /** @brief 将场景 JSON 写入指定路径。 */
    auto WriteFile(const std::filesystem::path &Path, std::string_view Contents) -> void;

    /** @brief 验证 parser 与 validator 对同一场景给出一致结果。 */
    [[nodiscard]] auto ValidateScenario(const Scenario &ScenarioValue,
                                        const SnapshotPointer &Builtins) -> bool;

    template <typename ResultType>
    auto CaptureError(const ResultType &Result) -> ErrorView
    {
        if (Result.has_value())
        {
            return {};
        }
        return {true, Result.error().Code, Result.error().Path};
    }

    inline auto MatchesExpected(const ErrorView &Actual,
                                const ExpectedError &Expected) -> bool
    {
        return Actual.Present == Expected.Invalid &&
               (!Expected.Invalid ||
                (Actual.Code == Expected.Code && Actual.Path == Expected.Path));
    }

    inline auto SameError(const ErrorView &Left, const ErrorView &Right) -> bool
    {
        return Left.Present == Right.Present &&
               (!Left.Present || (Left.Code == Right.Code && Left.Path == Right.Path));
    }

} // namespace Prism::Application::Configuration::Perf::Scenario
