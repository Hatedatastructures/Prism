/**
 * @file FieldKey.hpp
 * @brief Diagnose 编译期字段定义和类型化 key。
 */
#pragma once

#include <Preview/Foundation/Identifier/Id.hpp>

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace Preview::Diagnose
{

    /**
     * @brief Diagnose 日志字段的稳定数字标识。
     * @details 字段 ID 用于在上下文、冻结目录和异步日志记录之间标识同一字段；
     * 修改既有枚举值的顺序或含义会改变其数值编码。
     */
    enum class FieldId : std::uint8_t
    {
        Worker, ///< Worker 身份 ID，并参与固定人类前缀。
        Session, ///< Session 身份 ID，并参与固定人类前缀。
        Correlation, ///< 关联同一请求或操作的 ID。
        Process, ///< 进程身份 ID。
        Generation, ///< 当前配置 generation ID。
        Task, ///< 生命周期任务 ID。
        Operation, ///< 管理面操作 ID。
        Protocol, ///< 识别出的协议名称。
        Route, ///< 选中的路由标识。
        Stream, ///< 多路复用子流 ID。
        Carrier, ///< 承载协议或传输方式名称。
        Sni, ///< TLS ClientHello 中的服务器名称。
        Alpn, ///< TLS 协商协议名称。
        TlsVersion, ///< TLS 协议版本名称。
        Stage, ///< 当前处理阶段名称。
        Status, ///< 当前阶段的结果或状态名称。
        FaultCode, ///< Preview 内部错误码名称。
        NativeError, ///< 系统或底层库错误文本。
        ElapsedMs, ///< 阶段或操作耗时，单位为毫秒。
    };

    /**
     * @brief 字段值写入日志快照时采用的编码类别。
     * @details 数值和枚举编码为无符号整数，布尔值单独保存；文本类别使用有界 UTF-8 字符串。
     */
    enum class FieldValueKind : std::uint8_t
    {
        Unsigned, ///< 无符号整数或强类型 ID 的数值表示。
        Enumeration, ///< 枚举底层值的无符号表示。
        Boolean, ///< 独立存储的布尔值。
        ShortText, ///< 按字段 MaxLength 限制的短 UTF-8 文本。
        BoundedText, ///< 允许较大配置上限、仍需限长的 UTF-8 文本。
    };

    /**
     * @brief 判断字段值类别是否为文本。
     * @param Kind 待检查的值类别。
     * @return 类别为 ShortText 或 BoundedText 时返回 true。
     */
    [[nodiscard]] constexpr auto IsTextFieldKind(const FieldValueKind Kind) noexcept -> bool
    {
        return Kind == FieldValueKind::ShortText || Kind == FieldValueKind::BoundedText;
    }

    /**
     * @brief 指定字段在人类可读日志中的可见性。
     * @details HumanVisible 字段可出现在带字段的人类可读输出中；StructuredOnly 字段仅供结构化输出使用。
     */
    enum class FieldVisibility : std::uint8_t
    {
        HumanVisible, ///< 可出现在 HumanWithFields 输出中。
        StructuredOnly, ///< 只出现在 Structured 输出中。
    };

    /**
     * @brief 获取字段 ID 对应的稳定名称。
     * @param Id 要查询的字段 ID。
     * @return 已知 ID 对应的名称；若传入未定义的枚举值，则返回空字符串视图。
     */
    [[nodiscard]] constexpr auto FieldName(const FieldId Id) noexcept -> std::string_view
    {
        switch (Id)
        {
        case FieldId::Worker:
            return "Worker";
        case FieldId::Session:
            return "Session";
        case FieldId::Correlation:
            return "Correlation";
        case FieldId::Process:
            return "Process";
        case FieldId::Generation:
            return "Generation";
        case FieldId::Task:
            return "Task";
        case FieldId::Operation:
            return "Operation";
        case FieldId::Protocol:
            return "Protocol";
        case FieldId::Route:
            return "Route";
        case FieldId::Stream:
            return "Stream";
        case FieldId::Carrier:
            return "Carrier";
        case FieldId::Sni:
            return "Sni";
        case FieldId::Alpn:
            return "Alpn";
        case FieldId::TlsVersion:
            return "TlsVersion";
        case FieldId::Stage:
            return "Stage";
        case FieldId::Status:
            return "Status";
        case FieldId::FaultCode:
            return "FaultCode";
        case FieldId::NativeError:
            return "NativeError";
        case FieldId::ElapsedMs:
            return "ElapsedMs";
        }
        return {};
    }

    /**
     * @brief 描述一个字段的编译期元数据。
     * @details 这些属性供类型化上下文、字段编解码和运行时字段目录共同使用。
     * 通过字段编解码接口写入时，文本值须属于正式无分配 Text::ViewInput 类型；
     * 不接收任意用户转换，领域类型先显式取得稳定 View。其他类别要求值类型与 Value 完全匹配。
     * @tparam IdValue 字段在日志记录中的稳定 ID。
     * @tparam Value 字段的声明值类型，也是非文本字段要求的精确类型。
     * @tparam KindValue 字段的编码类别，决定快照保存数值、布尔值还是文本。
     * @tparam VisibilityValue 字段在人类可读输出中的可见性策略。
     * @tparam MaxLengthValue 文本字段允许的最大 UTF-8 字节数；非文本字段不使用此值。
     * @tparam SensitiveValue 是否在字段进入异步提交记录前执行敏感文本脱敏。
     * @tparam ContextIdentityValue 是否将该字段作为上下文身份的一部分处理。
     */
    template <FieldId IdValue, typename Value, FieldValueKind KindValue,
        FieldVisibility VisibilityValue = FieldVisibility::StructuredOnly, std::size_t MaxLengthValue = 0U,
        bool SensitiveValue = false, bool ContextIdentityValue = false>
    struct FieldDefinition final
    {
        using ValueType = Value;
        static constexpr FieldId Id = IdValue;
        static constexpr FieldValueKind Kind = KindValue;
        static constexpr FieldVisibility Visibility = VisibilityValue;
        static constexpr std::size_t MaxLength = MaxLengthValue;
        static constexpr bool Sensitive = SensitiveValue;
        static constexpr bool ContextIdentity = ContextIdentityValue;
        static constexpr std::string_view Name = FieldName(IdValue);
    };

    /**
     * @brief 将字段定义包装为可用于上下文读写的类型化 key。
     * @details key 暴露字段定义和值类型，使上下文操作能够在编译期检查字段和值的对应关系。
     * @tparam Definition 提供 ValueType 和 Id 成员的字段定义类型，通常为 FieldDefinition 实例化。
     */
    template <typename Definition>
    struct FieldKey final
    {
        using DefinitionType = Definition;
        using ValueType = typename Definition::ValueType;

        static constexpr FieldId Id = Definition::Id;
    };

    /**
     * @brief Preview 各模块共享的内置字段定义和类型化 key。
     * @details 每个定义集中声明字段 ID、值类型、编码类别、可见性及文本安全策略，
     * 对应的 key 可直接用于 ContextState 的类型化接口。
     */
    namespace Fields
    {
        using WorkerDefinition = FieldDefinition<FieldId::Worker, Preview::WorkerId, FieldValueKind::Unsigned,
            FieldVisibility::HumanVisible, 0U, false, true>;
        using SessionDefinition = FieldDefinition<FieldId::Session, Preview::SessionId,
            FieldValueKind::Unsigned, FieldVisibility::HumanVisible, 0U, false, true>;
        using CorrelationDefinition =
            FieldDefinition<FieldId::Correlation, Preview::RequestId, FieldValueKind::Unsigned>;
        using ProcessDefinition =
            FieldDefinition<FieldId::Process, Preview::ProcessId, FieldValueKind::Unsigned>;
        using GenerationDefinition =
            FieldDefinition<FieldId::Generation, Preview::GenerationId, FieldValueKind::Unsigned>;
        using TaskDefinition = FieldDefinition<FieldId::Task, Preview::TaskId, FieldValueKind::Unsigned>;
        using OperationDefinition =
            FieldDefinition<FieldId::Operation, Preview::OperationId, FieldValueKind::Unsigned>;
        using ProtocolDefinition = FieldDefinition<FieldId::Protocol, std::string_view,
            FieldValueKind::ShortText, FieldVisibility::StructuredOnly, 64U>;
        using RouteDefinition = FieldDefinition<FieldId::Route, std::string_view, FieldValueKind::ShortText,
            FieldVisibility::StructuredOnly, 64U>;
        using StreamDefinition =
            FieldDefinition<FieldId::Stream, Preview::StreamId, FieldValueKind::Unsigned>;
        using CarrierDefinition = FieldDefinition<FieldId::Carrier, std::string_view,
            FieldValueKind::ShortText, FieldVisibility::HumanVisible, 64U>;
        using SniDefinition = FieldDefinition<FieldId::Sni, std::string_view, FieldValueKind::ShortText,
            FieldVisibility::HumanVisible, 64U>;
        using AlpnDefinition = FieldDefinition<FieldId::Alpn, std::string_view, FieldValueKind::ShortText,
            FieldVisibility::StructuredOnly, 64U>;
        using TlsVersionDefinition = FieldDefinition<FieldId::TlsVersion, std::string_view,
            FieldValueKind::ShortText, FieldVisibility::HumanVisible, 64U>;
        using StageDefinition = FieldDefinition<FieldId::Stage, std::string_view, FieldValueKind::ShortText,
            FieldVisibility::StructuredOnly, 64U>;
        using StatusDefinition = FieldDefinition<FieldId::Status, std::string_view, FieldValueKind::ShortText,
            FieldVisibility::StructuredOnly, 64U>;
        using FaultCodeDefinition = FieldDefinition<FieldId::FaultCode, std::string_view,
            FieldValueKind::ShortText, FieldVisibility::StructuredOnly, 64U>;
        using NativeErrorDefinition = FieldDefinition<FieldId::NativeError, std::string_view,
            FieldValueKind::BoundedText, FieldVisibility::StructuredOnly, 256U, true>;
        using ElapsedMsDefinition =
            FieldDefinition<FieldId::ElapsedMs, std::uint64_t, FieldValueKind::Unsigned>;

        inline constexpr FieldKey<WorkerDefinition> Worker{};
        inline constexpr FieldKey<SessionDefinition> Session{};
        inline constexpr FieldKey<CorrelationDefinition> Correlation{};
        inline constexpr FieldKey<ProcessDefinition> Process{};
        inline constexpr FieldKey<GenerationDefinition> Generation{};
        inline constexpr FieldKey<TaskDefinition> Task{};
        inline constexpr FieldKey<OperationDefinition> Operation{};
        inline constexpr FieldKey<ProtocolDefinition> Protocol{};
        inline constexpr FieldKey<RouteDefinition> Route{};
        inline constexpr FieldKey<StreamDefinition> Stream{};
        inline constexpr FieldKey<CarrierDefinition> Carrier{};
        inline constexpr FieldKey<SniDefinition> Sni{};
        inline constexpr FieldKey<AlpnDefinition> Alpn{};
        inline constexpr FieldKey<TlsVersionDefinition> TlsVersion{};
        inline constexpr FieldKey<StageDefinition> Stage{};
        inline constexpr FieldKey<StatusDefinition> Status{};
        inline constexpr FieldKey<FaultCodeDefinition> FaultCode{};
        inline constexpr FieldKey<NativeErrorDefinition> NativeError{};
        inline constexpr FieldKey<ElapsedMsDefinition> ElapsedMs{};
    } // namespace Fields

} // namespace Preview::Diagnose
