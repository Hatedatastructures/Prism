#pragma once

#include <string_view>
#include <fstream>
#include <memory_resource>

// 引入 Glaze 核心库
#include <glaze/glaze.hpp>

// 引入项目内部的容器定义 (适配 memory::string)
#include "forward-engine/memory/container.hpp"

namespace ngx::transformer::json
{
    /**
     * @brief 将对象序列化为 JSON 字符串
     * @tparam StructureObject 待序列化的对象类型
     * @param value 待序列化的对象引用
     * @param mr 用于分配结果字符串内存的资源
     * @return memory::string 序列化后的 JSON 字符串
     */
    template <typename StructureObject>
    [[nodiscard]] memory::string serialize(const StructureObject &value, memory::resource *mr = std::pmr::get_default_resource())
    {
        memory::string buffer(mr);
        // glz::write_json 写入 buffer 时通常返回 void 或 error_ctx（取决于版本），这里假设写入内存通常成功
        glz::write_json(value, buffer);
        return buffer;
    }

    /**
     * @brief 将 JSON 字符串反序列化为对象
     * @tparam T 目标对象类型
     * @param json_data JSON 原始数据
     * @param value 接收数据的对象引用
     * @return glz::error_ctx 错误上下文 (包含 error_code 和错误位置)
     */
    template <typename T>
    [[nodiscard]] glz::error_ctx deserialize(const std::string_view json_data, T &value)
    {
        return glz::read_json(value, json_data);
    }

    /**
     * @brief [重载] 将 JSON 字符串反序列化为对象 (带错误处理回调)
     * @tparam T 目标对象类型
     * @param json_data JSON 原始数据
     * @return std::pair<T, glz::error_ctx> 结果对象和错误码
     */
    template <typename T>
    [[nodiscard]] std::pair<T, glz::error_ctx> deserialize(const std::string_view json_data)
    {
        T value{};
        auto ec = glz::read_json(value, json_data);
        return {std::move(value), ec};
    }

    // /**
    //  * @brief 从文件读取并解析 JSON
    //  * @tparam T 目标对象类型
    //  * @param path 文件路径
    //  * @param value 接收数据的对象引用
    //  * @return glz::error_ctx 错误上下文
    //  */
    // template <typename T>
    // [[nodiscard]] glz::error_ctx load_from_file(const std::string &path, T &value)
    // {
    //     // glz::read_file_json 返回 error_ctx
    //     return glz::read_file_json(value, path, std::string{});
    // }

    // /**
    //  * @brief 将对象保存为 JSON 文件
    //  * @tparam T 待保存的对象类型
    //  * @param path 文件保存路径
    //  * @param value 待保存的对象引用
    //  * @param mr 缓冲区使用的内存资源 (可选)
    //  * @return glz::error_ctx 错误上下文
    //  */
    // template <typename T>
    // [[nodiscard]] glz::error_ctx save_to_file(const std::string &path, const T &value, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
    // {
    //     memory::string buffer(mr);
    //     glz::write_json(value, buffer);

    //     std::ofstream file(path, std::ios::out | std::ios::trunc);
    //     if (!file)
    //     {
    //         // 手动构建一个 error_ctx 返回文件打开错误
    //         return {glz::error_code::file_open_failure};
    //     }
    //     file.write(buffer.data(), buffer.size());

    //     // 返回无错误
    //     return {glz::error_code::none};
    // }

} // namespace ngx::transformer::json