#pragma once

#include <string_view>
#include <type_traits>
#include <utility>

#include <glaze/glaze.hpp>

#include <memory/container.hpp>

namespace ngx::transformer::json
{
    /**
     * @brief 将对象序列化为 JSON 字符串
     * @tparam StructureObject 待序列化的对象类型
     * @param value 待序列化的对象实例
     * @param out 用于存储序列化结果的字符串引用
     * @return true 序列化成功，false 序列化失败
     */
    template <typename StructureObject>
    [[nodiscard]] bool serialize(const StructureObject &value, memory::string &out)
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
     * @brief 将对象序列化为 JSON 字符串 (带错误处理回调)
     * @tparam StructureObject 待序列化的对象类型
     * @param value 待序列化的对象实例
     * @param out 用于存储序列化结果的字符串引用
     * @param out_ec 用于存储序列化错误上下文的引用
     * @return true 序列化成功，false 序列化失败
     */
    template <typename StructureObject>
    [[nodiscard]] bool serialize(const StructureObject &value, memory::string &out, glz::error_ctx &out_ec)
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
     * @brief 将对象序列化为 JSON 字符串 (带内存资源参数)
     * @tparam StructureObject 待序列化的对象类型
     * @param value 待序列化的对象实例
     * @param mr 内存资源指针，默认使用当前线程的内存资源
     * @return memory::string 序列化后的 JSON 字符串
     */
    template <typename StructureObject>
    [[nodiscard]] memory::string serialize(const StructureObject &value, memory::resource_pointer mr = memory::current_resource())
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
     */
    template <typename StructureObject>
    [[nodiscard]] bool deserialize(const std::string_view json_data, StructureObject &value)
    {
        using read_result = decltype(glz::read_json(value, json_data));

        if constexpr (std::is_same_v<read_result, glz::error_ctx>)
        {
            if constexpr (std::is_default_constructible_v<StructureObject> && std::is_move_assignable_v<StructureObject>)
            {
                StructureObject temp{};
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
                StructureObject temp{};
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
     * @brief 将 JSON 字符串反序列化为对象 (带错误处理回调)
     * @tparam StructureObject 目标对象类型
     * @param json_data JSON 原始数据
     * @param value 接收数据的对象引用
     * @param out_ec 用于存储反序列化错误上下文的引用
     * @return true 反序列化成功，false 反序列化失败
     */
    template <typename StructureObject>
    [[nodiscard]] bool deserialize(const std::string_view json_data, StructureObject &value, glz::error_ctx &out_ec)
    {
        using read_result = decltype(glz::read_json(value, json_data));

        if constexpr (std::is_same_v<read_result, glz::error_ctx>)
        {   // 模板类型有无参构造函数或移动赋值运算符
            if constexpr (std::is_default_constructible_v<StructureObject> && std::is_move_assignable_v<StructureObject>)
            {
                StructureObject temp{};
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
                StructureObject temp{};
                glz::read_json(temp, json_data);
                out_ec = {};
                value = std::move(temp);
                return true;
            }
            else
            {
                glz::read_json(value, json_data);
                out_ec = {};
            }
        }

        return !out_ec;
    }

    /**
     * @brief 将 JSON 字符串反序列化为对象 (带内存资源参数)
     * @tparam StructureObject 目标对象类型
     * @param json_data JSON 原始数据
     * @param value 接收数据的对象引用
     * @param mr 缓冲区使用的内存资源
     * @param out_ec 用于存储反序列化错误上下文的引用
     */
    template <typename StructureObject>
    [[nodiscard]] bool deserialize(const std::string_view json_data, StructureObject &value, memory::resource_pointer mr, glz::error_ctx &out_ec)
    {
        if (!mr)
        {
            mr = memory::current_resource();
        }

        using read_result = decltype(glz::read_json(value, json_data));

        if constexpr (std::is_same_v<read_result, glz::error_ctx>)
        {
            if constexpr (std::is_constructible_v<StructureObject, memory::resource_pointer> && std::is_move_assignable_v<StructureObject>)
            {
                StructureObject temp(mr);
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
                return deserialize(json_data, value, out_ec);
            }
        }
        else
        {
            if constexpr (std::is_constructible_v<StructureObject, memory::resource_pointer> && std::is_move_assignable_v<StructureObject>)
            {
                StructureObject temp(mr);
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
    }

    template <typename StructureObject>
    [[nodiscard]] bool deserialize(const std::string_view json_data, StructureObject &value, memory::resource_pointer mr)
    {
        glz::error_ctx ignored_ec{};
        return deserialize(json_data, value, mr, ignored_ec);
    }

} // namespace ngx::transformer::json
