/**
 * @file FieldCatalog.hpp
 * @brief 冻结的编译期 Diagnose 字段目录。
 */
#pragma once

#include <Preview/Foundation/Utility/Diagnose/FieldKey.hpp>

#include <array>
#include <cstddef>
#include <optional>
#include <span>

namespace Preview::Diagnose
{

    /**
     * @brief 在类型层面打包一组字段定义。
     * @tparam Definitions 被收集到该包中的字段元数据类型。
     */
    template <typename... Definitions>
    struct FieldDescriptorPack final
    {
        static constexpr std::size_t Size = sizeof...(Definitions); ///< 描述包中的字段定义数量。
    };

    /** @brief Diagnose 内置字段的编译期定义集合。 */
    using BuiltinFieldPack = FieldDescriptorPack<Fields::WorkerDefinition, Fields::SessionDefinition,
        Fields::CorrelationDefinition, Fields::ProcessDefinition, Fields::GenerationDefinition,
        Fields::TaskDefinition, Fields::OperationDefinition, Fields::ProtocolDefinition,
        Fields::RouteDefinition, Fields::StreamDefinition, Fields::CarrierDefinition, Fields::SniDefinition,
        Fields::AlpnDefinition, Fields::TlsVersionDefinition, Fields::StageDefinition,
        Fields::StatusDefinition, Fields::FaultCodeDefinition, Fields::NativeErrorDefinition,
        Fields::ElapsedMsDefinition>;

    /**
     * @brief 供上下文快照和解码器使用的单个字段元数据副本。
     * @details 该运行时描述由编译期字段定义生成，保留输出、限长、脱敏和身份处理所需属性。
     */
    struct FieldDescriptor final
    {
        FieldId Id{};                                                ///< 稳定字段槽位。
        std::string_view Name{};                                     ///< Human/JSON 输出使用的稳定字段名。
        FieldValueKind Kind{FieldValueKind::Unsigned};               ///< 值在快照中的编码类型。
        FieldVisibility Visibility{FieldVisibility::StructuredOnly}; ///< HumanWithFields 的可见性。
        std::size_t MaxLength{0U};   ///< 文本最大 UTF-8 字节数；数值字段为 0。
        bool Sensitive{false};       ///< 是否必须在进入异步队列前脱敏。
        bool ContextIdentity{false}; ///< 是否参与固定 W/S 身份前缀。
    };

    namespace Detail
    {

        /**
         * @brief 将字段定义转换为运行时字段描述。
         * @tparam Definition 提供字段 ID、名称及策略常量的编译期字段定义。
         * @return 由 Definition 中的元数据初始化的字段描述。
         */
        template <typename Definition>
        [[nodiscard]] constexpr auto MakeFieldDescriptor() noexcept -> FieldDescriptor
        {
            return FieldDescriptor{Definition::Id, Definition::Name, Definition::Kind, Definition::Visibility,
                Definition::MaxLength, Definition::Sensitive, Definition::ContextIdentity};
        }

        /**
         * @brief 将字段定义包展开为固定大小的描述数组。
         * @details 接收的 FieldDescriptorPack 对象仅用于推导 Definitions，不携带运行时字段数据；
         * 数组顺序与模板参数 Definitions 中的字段顺序一致。
         * @tparam Definitions 待转换的字段定义类型包。
         * @return 每个字段定义对应一个元素的描述数组。
         */
        template <typename... Definitions>
        [[nodiscard]] constexpr auto MakeFieldDescriptors(FieldDescriptorPack<Definitions...>) noexcept
            -> std::array<FieldDescriptor, sizeof...(Definitions)>
        {
            return {MakeFieldDescriptor<Definitions>()...};
        }

    } // namespace Detail

    /**
     * @brief 编译期生成的内置字段目录。
     * @details 目录描述在静态存储期构造，调用方可读取固定范围的描述视图，
     * 也可按字段 ID 查找单条描述；目录本身不提供运行时修改接口。
     */
    class FieldCatalog final
    {
    public:
        static constexpr std::size_t Count = BuiltinFieldPack::Size; ///< 内置字段总数。

        /**
         * @brief 获取所有内置字段的只读描述视图。
         * @return 固定长度为 Count、指向静态目录存储的视图。
         */
        [[nodiscard]] static constexpr auto Descriptors() noexcept -> std::span<const FieldDescriptor, Count>
        {
            return BuiltinDescriptors_;
        }

        /**
         * @brief 按字段 ID 查找内置字段描述。
         * @param Id 要查找的字段 ID。
         * @return 找到时返回描述副本；目录中没有该 ID 时返回 std::nullopt。
         */
        [[nodiscard]] static constexpr auto Find(const FieldId Id) noexcept -> std::optional<FieldDescriptor>
        {
            for (const auto& Descriptor : BuiltinDescriptors_)
            {
                if (Descriptor.Id == Id)
                {
                    return Descriptor;
                }
            }
            return std::nullopt;
        }

    private:
        /** @brief 由内置字段定义在编译期生成的静态目录存储。 */
        inline static constexpr auto BuiltinDescriptors_ = Detail::MakeFieldDescriptors(BuiltinFieldPack{});
    };

} // namespace Preview::Diagnose
