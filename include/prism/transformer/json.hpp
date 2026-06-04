/**
 * @file json.hpp
 * @brief JSON 序列化与反序列化
 * @details 提供基于 glaze 库的 JSON 序列化和反序列化功能，
 * 封装为类型安全、内存高效的接口。集成 PMR 内存系统，
 * 支持自定义内存分配器。
 * @note 需要为序列化类型定义 glz::meta 特化或
 * 使用 GLZ_META 宏。
 * @warning 大 JSON 文档反序列化可能消耗大量内存。
 */
#pragma once

#include <prism/memory/container.hpp>

#include <glaze/glaze.hpp>

#include <string_view>
#include <type_traits>
#include <utility>


namespace psm::transformer::json
{

    /**
     * @struct parse_opts
     * @brief 反序列化选项
     * @details 收敛反序列化的内存资源和错误上下文参数
     */
    struct parse_opts
    {
        memory::resource_pointer mr = memory::current_resource();
        glz::error_ctx *ec = nullptr;
    };

    /**
     * @brief 将对象序列化为 JSON 字符串
     * @tparam StructureObject 待序列化的对象类型
     * @param value 待序列化的对象实例
     * @param out 用于存储序列化结果的字符串，使用前会被清空
     * @return true 序列化成功，false 序列化失败
     */
    template <typename StructureObject>
    [[nodiscard]] auto serialize(const StructureObject &value, memory::string &out)
        -> bool
    {
        out.clear();
        using write_result = decltype(glz::write_json(value, out));

        if constexpr (std::is_same_v<write_result, glz::error_ctx>)
        {
            if (const auto ec = glz::write_json(value, out))
            {
                out.clear();
                return false;
            }
            return true;
        }
        else
        {
            glz::write_json(value, out);
            return true;
        }
    }

    /**
     * @brief 将对象序列化为 JSON 字符串（带错误上下文）
     * @tparam StructureObject 待序列化的对象类型
     * @param value 待序列化的对象实例
     * @param out 用于存储序列化结果的字符串
     * @param out_ec 用于存储序列化错误上下文
     * @return true 序列化成功，false 序列化失败
     */
    template <typename StructureObject>
    [[nodiscard]] auto serialize(const StructureObject &value, memory::string &out, glz::error_ctx &out_ec)
        -> bool
    {
        out.clear();
        using write_result = decltype(glz::write_json(value, out));

        if constexpr (std::is_same_v<write_result, glz::error_ctx>)
        {
            out_ec = glz::write_json(value, out);
        }
        else
        {
            glz::write_json(value, out);
            out_ec = {};
        }

        if (out_ec)
        {
            out.clear();
            return false;
        }
        return true;
    }

    /**
     * @brief 将对象序列化为 JSON 字符串（带内存资源）
     * @tparam StructureObject 待序列化的对象类型
     * @param value 待序列化的对象实例
     * @param mr 内存资源指针，默认使用当前线程的内存资源
     * @return 序列化后的 JSON 字符串
     */
    template <typename StructureObject>
    [[nodiscard]] auto serialize(const StructureObject &value, const memory::resource_pointer mr = memory::current_resource())
        -> memory::string
    {
        memory::string out(mr);
        if (!serialize(value, out))
        {
            out.clear();
        }
        return out;
    }

    /**
     * @brief 将 JSON 字符串反序列化为对象
     * @tparam StructureObject 目标对象类型
     * @param json_data JSON 原始数据
     * @param value 接收数据的对象引用
     * @return true 反序列化成功，false 反序列化失败
     * @details 对于支持移动构造的类型，使用临时对象
     * 避免破坏原对象状态。
     */
    template <typename StructureObject>
    [[nodiscard]] auto deserialize(const std::string_view json_data, StructureObject &value)
        -> bool
    {
        using read_result = decltype(glz::read_json(value, json_data));

        if constexpr (std::is_same_v<read_result, glz::error_ctx>)
        {
            if constexpr (std::is_default_constructible_v<StructureObject> && std::is_move_assignable_v<StructureObject>)
            {
                StructureObject temp;
                if (const auto ec = glz::read_json(temp, json_data))
                {
                    return false;
                }
                value = std::move(temp);
                return true;
            }
            else
            {
                const auto ec = glz::read_json(value, json_data);
                return !ec;
            }
        }
        else
        {
            if constexpr (std::is_default_constructible_v<StructureObject> && std::is_move_assignable_v<StructureObject>)
            {
                StructureObject temp;
                glz::read_json(temp, json_data);
                value = std::move(temp);
                return true;
            }
            else
            {
                glz::read_json(value, json_data);
                return true;
            }
        }
    }

    /**
     * @brief 将 JSON 反序列化为对象（带错误上下文）
     * @tparam StructureObject 目标对象类型
     * @param json_data JSON 原始数据
     * @param value 接收数据的对象引用
     * @param out_ec 用于存储反序列化错误上下文
     * @return true 反序列化成功，false 反序列化失败
     */
    template <typename StructureObject>
    [[nodiscard]] auto deserialize(const std::string_view json_data, StructureObject &value, glz::error_ctx &out_ec)
        -> bool
    {
        using read_result = decltype(glz::read_json(value, json_data));

        if constexpr (std::is_same_v<read_result, glz::error_ctx>)
        {
            if constexpr (std::is_default_constructible_v<StructureObject> && std::is_move_assignable_v<StructureObject>)
            {
                StructureObject temp;
                out_ec = glz::read_json(temp, json_data);
                if (out_ec)
                {
                    return false;
                }
                value = std::move(temp);
                return true;
            }
            else
            {
                out_ec = glz::read_json(value, json_data);
            }
        }
        else
        {
            if constexpr (std::is_default_constructible_v<StructureObject> && std::is_move_assignable_v<StructureObject>)
            {
                StructureObject temp;
                glz::read_json(temp, json_data);
                out_ec = {};
                value = std::move(temp);
                return true;
            }
            else
            {
                glz::read_json(value, json_data);
                out_ec = {};
                return true;
            }
        }

        return !out_ec;
    }

    /**
     * @brief 将 JSON 反序列化为对象（带内存资源）
     * @tparam StructureObject 目标对象类型
     * @param json_data JSON 原始数据
     * @param value 接收数据的对象引用
     * @param mr 缓冲区使用的内存资源
     * @param out_ec 用于存储反序列化错误上下文
     * @return true 反序列化成功，false 反序列化失败
     */
    template <typename StructureObject>
    [[nodiscard]] auto deserialize(const std::string_view json_data, StructureObject &value, parse_opts opts)
        -> bool
    {
        auto &mr = opts.mr;
        auto &out_ec_ptr = opts.ec;
        if (!mr)
        {
            mr = memory::current_resource();
        }

        glz::error_ctx local_ec{};

        using read_result = decltype(glz::read_json(value, json_data));

        if constexpr (std::is_same_v<read_result, glz::error_ctx>)
        {
            constexpr bool has_pmr_ctor = std::is_constructible_v<StructureObject, memory::resource_pointer>;
            constexpr bool is_move_assign = std::is_move_assignable_v<StructureObject>;
            if constexpr (has_pmr_ctor && is_move_assign)
            {
                StructureObject temp(mr);
                local_ec = glz::read_json(temp, json_data);
                if (local_ec)
                {
                    if (out_ec_ptr) *out_ec_ptr = local_ec;
                    return false;
                }
                value = std::move(temp);
                if (out_ec_ptr) *out_ec_ptr = local_ec;
                return true;
            }
            else
            {
                local_ec = glz::read_json(value, json_data);
                if (out_ec_ptr) *out_ec_ptr = local_ec;
                return !local_ec;
            }
        }
        else
        {
            constexpr bool has_pmr_ctor = std::is_constructible_v<StructureObject, memory::resource_pointer>;
            constexpr bool is_move_assign = std::is_move_assignable_v<StructureObject>;
            if constexpr (has_pmr_ctor && is_move_assign)
            {
                StructureObject temp(mr);
                glz::read_json(temp, json_data);
                value = std::move(temp);
                if (out_ec_ptr) *out_ec_ptr = {};
                return true;
            }
            else
            {
                glz::read_json(value, json_data);
                if (out_ec_ptr) *out_ec_ptr = {};
                return true;
            }
        }
    }

    /**
     * @brief 将 JSON 反序列化为对象（带内存资源，忽略错误）
     * @tparam StructureObject 目标对象类型
     * @param json_data JSON 原始数据
     * @param value 接收数据的对象引用
     * @param mr 缓冲区使用的内存资源
     * @return true 反序列化成功，false 反序列化失败
     */
    template <typename StructureObject>
    [[nodiscard]] auto deserialize(const std::string_view json_data, StructureObject &value, memory::resource_pointer mr)
        -> bool
    {
        glz::error_ctx ignored_ec{};
        return deserialize(json_data, value, parse_opts{mr, &ignored_ec});
    }

} // namespace psm::transformer::json
