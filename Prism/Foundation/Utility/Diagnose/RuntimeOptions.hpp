/**
 * @file RuntimeOptions.hpp
 * @brief Diagnose backend 的公开启动参数。
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <Prism/Foundation/Utility/Text/Case.hpp>
#include <Prism/Foundation/Utility/Diagnose/FormattingLimits.hpp>

namespace Prism::Diagnose
{

    /**
     * @brief Diagnose facade 支持的日志级别。
     * @details Trace 到 Critical 按严重程度递增；Access 是独立通道，Off 表示关闭普通级别筛选。
     */
    enum class LogLevel : std::uint8_t
    {
        Trace, ///< 细粒度诊断信息。
        Debug, ///< 调试过程和非关键生命周期信息。
        Info, ///< 正常运行和请求活动信息。
        Access, ///< 独立的访问或审计通道。
        Warn, ///< 可恢复异常或需要关注的情况。
        Error, ///< 操作失败，但进程仍可继续运行。
        Critical, ///< 关键失败；facade 不因普通级别阈值过滤此级别。
        Off, ///< 不接受普通日志级别。
    };

    /**
     * @brief 返回日志输出中使用的大驼峰等级名称。
     * @param Level Diagnose 日志等级。
     * @return 与等级对应的稳定输出名称；未知值回退为 "Off"。
     */
    [[nodiscard]] constexpr auto LogLevelName(const LogLevel Level) noexcept -> std::string_view
    {
        switch (Level)
        {
        case LogLevel::Trace:
            return "Trace";
        case LogLevel::Debug:
            return "Debug";
        case LogLevel::Info:
            return "Info";
        case LogLevel::Access:
            return "Access";
        case LogLevel::Warn:
            return "Warn";
        case LogLevel::Error:
            return "Error";
        case LogLevel::Critical:
            return "Critical";
        case LogLevel::Off:
            return "Off";
        }
        return "Off";
    }

    /**
     * @brief 将受控 snake_case 标识转换为 PascalCase。
     * @param Value 程序生成的枚举或事件标识。
     * @return 去除下划线和连字符并大写各单词首字母后的文本。
     * @note 仅用于受控标识；不得用于用户名、网络地址或原生错误文本。
     */
    [[nodiscard]] inline auto PascalCaseToken(const std::string_view Value) -> std::string
    {
        std::string Result;
        Result.reserve(Value.size());
        Prism::Text::TransformPascalCase(Value, [&Result](const char Character) { Result.push_back(Character); });
        return Result;
    }

    /**
     * @brief 创建 Diagnose backend 时使用的公开配置。
     * @details 配置目录、文件、控制台输出、队列容量和轮转策略；队列满时的处理由 backend 决定。
     */
    struct RuntimeOptions final
    {
        LogLevel Level{LogLevel::Info}; ///< 普通 facade 日志的级别阈值；Access/Audit 和 Critical 有专门规则。
        std::filesystem::path Directory{"logs"}; ///< 日志目录；应用 owner 在初始化时创建。
        std::string FileName{"prism.log"}; ///< 当前日志文件名，不含目录分隔符。
        bool Console{false}; ///< 是否额外启用 stdout sink。
        std::size_t QueueCapacity{4096U}; ///< 固定快照队列容量；并发提交或队列满时调用立即返回 Dropped。
        std::size_t QueueBytes{64U * 1024U * 1024U}; ///< 冷构造队列槽的累计实际容量上限。
        FormattingLimits Formatting{}; ///< 冷校验/冻结的 width、precision 及累计工作额度。
        std::uint64_t RotateBytes{64ULL * 1024ULL * 1024ULL}; ///< 单个日志文件达到此字节数时轮转。
        std::uint32_t RotateFiles{8U}; ///< 轮转时保留的历史文件数。
    };

    /**
     * @brief 判断请求级别是否通过配置阈值。
     * @param Configured 当前配置的级别阈值。
     * @param Requested 本条记录请求的级别。
     * @return Off 配置或请求级别时返回 false；阈值为 Access 时仅放行 Access；
     * 请求为 Access 时，Trace、Debug、Info 阈值放行；其他级别按严重程度比较。
     */
    [[nodiscard]] constexpr auto IsLevelEnabled(const LogLevel Configured, const LogLevel Requested) noexcept
        -> bool
    {
        if (Configured == LogLevel::Off || Requested == LogLevel::Off)
        {
            return false;
        }
        if (Configured == LogLevel::Access)
        {
            return Requested == LogLevel::Access;
        }
        if (Requested == LogLevel::Access)
        {
            return static_cast<std::uint8_t>(Configured) <= static_cast<std::uint8_t>(LogLevel::Info);
        }
        return static_cast<std::uint8_t>(Requested) >= static_cast<std::uint8_t>(Configured);
    }
} // namespace Prism::Diagnose
