/**
 * @file json.hpp
 * @brief JSON 序列化与反序列化
 * @details 提供了基于 `glaze` 库的 `JSON` 序列化和反序列化功能，封装为类型安全、内存高效的接口。
 * 作为 `ForwardEngine` 数据转换层的核心组件，支持配置加载、状态持久化和 `RPC` 通信等场景。
 *
 * 架构说明：
 * - 序列化功能：`serialize()` 函数将 `C++` 对象转换为 `JSON` 字符串；
 * - 反序列化功能：`deserialize()` 函数将 `JSON` 字符串转换为 `C++` 对象；
 * - 内存管理：集成 `PMR` 系统，支持自定义内存分配器；
 * - 错误处理：提供多种错误处理方式，包括返回值、错误上下文和异常安全设计。
 *
 * 设计特性：
 * - 类型安全：利用 `C++` 模板和编译期反射，确保序列化/反序列化的类型安全；
 * - 零拷贝解析：`glaze` 库支持零拷贝解析，减少内存分配和复制；
 * - `PMR` 内存管理：使用 `memory::string` 和 `memory::resource_pointer` 支持自定义内存分配；
 * - 错误处理：提供多种错误处理方式，包括返回值、错误上下文和异常安全设计。
 *
 * 性能考虑：
 * - `glaze` 库提供编译期 `JSON` 模式生成，减少运行时开销；
 * - 使用 `std::string_view` 避免不必要的字符串复制；
 * - 内存分配通过 `PMR` 系统管理，减少堆碎片；
 * - 错误处理通过返回值而非异常，避免异常抛出开销。
 *
 * 使用场景：
 * - 配置文件加载和持久化；
 * - `RESTful API` 请求/响应序列化；
 * - 进程间通信数据格式转换；
 * - 状态快照和恢复。
 *
 * @note 需要为序列化/反序列化的类型定义 `glz::meta` 特化或使用 `GLZ_META` 宏。
 * @warning 大 `JSON` 文档反序列化可能消耗大量内存，需合理设置大小限制。
 * @warning 线程安全性：单个函数调用是线程安全的，但共享的输出缓冲区需要外部同步。
 * @see nlohmann::json 官方文档
 * @see glaze 官方文档
 *
 */
#pragma once

#include <string_view>
#include <type_traits>
#include <utility>

#include <glaze/glaze.hpp>

#include <forward-engine/memory/container.hpp>

/**
 * @namespace ngx::transformer::json
 * @brief JSON 数据转换
 * @warning - 该命名空间的内容主要用于数据序列化和反序列化，请勿在业务逻辑中直接调用。
 * @warning - 未定义 `glz::meta` 的类型无法序列化/反序列化，会导致编译错误。
 * @throws 序列化/反序列化操作可能抛出 `std::bad_alloc`（内存不足）或 `std::runtime_error`（格式错误）
 * @details 提供了 `JSON` 格式的序列化和反序列化功能，封装 `glaze` 库提供类型安全、高性能的接口。
 * 该命名空间实现了基于 `glaze` 的现代 C++ JSON 序列化，包含：
 * @details - 序列化功能：将 `C++` 对象转换为 `JSON` 字符串，支持多种输出方式和错误处理；
 * @details - 反序列化功能：将 `JSON` 字符串转换为 `C++` 对象，支持编译期模式匹配和内存控制；
 * @details - 内存管理：集成 `PMR` 系统，支持自定义内存分配器；
 * @details - 错误处理：提供详细的错误上下文，便于调试和问题排查。
 *
 *
 * 序列化/反序列化流程：
 *
 * ```
 * C++ 对象
 * ↓
 * glz::meta 反射
 * ↓
 * JSON 字符串
 * ↓
 * 内存缓冲区 (PMR)
 * ```
 */
namespace ngx::transformer::json
{
    /**
     * @brief 将对象序列化为 JSON 字符串
     * @details 将 `C++` 对象序列化为 `JSON` 格式字符串，存储到提供的输出缓冲区。
     * 该函数是序列化功能的基础版本，使用简单的布尔返回值表示成功/失败。
     *
     * 执行流程：
     * @details - 清空输出缓冲区；
     * @details - 调用 `glz::write_json` 进行序列化；
     * @details - 根据 `glaze` 版本适配错误处理（`glz::error_ctx` 或异常）；
     * @details - 序列化失败时清空缓冲区并返回 `false`。
     *
     * 模板约束：
     * @details - `StructureObject` 必须定义了 `glz::meta` 特化或使用 `GLZ_META` 宏；
     * @details - `StructureObject` 应该是可平凡复制的值类型或定义了合适的序列化适配器。
     *
     * 内存管理：
     * @details - 输出缓冲区使用 `memory::string`，继承调用者的内存分配器；
     * @details - 序列化过程可能分配内存存储 `JSON` 字符串，使用 `PMR` 分配器。
     *
     * 错误处理：
     * @details - 序列化成功返回 `true`，输出缓冲区包含 `JSON` 字符串；
     * @details - 序列化失败返回 `false`，输出缓冲区被清空；
     * @details - 不抛出异常，适合在异常禁用或性能敏感场景使用。
     *
     * @tparam StructureObject 待序列化的对象类型，必须定义 `glz::meta` 特化
     * @param value 待序列化的对象实例，按常量引用传递
     * @param out 用于存储序列化结果的字符串引用，使用前会被清空
     * @return `true` 序列化成功，`false` 序列化失败
     * @note 该函数不提供详细的错误信息，如需错误上下文请使用 `serialize(value, out, out_ec)` 重载。
     * @note 输出缓冲区使用 `memory::string`，支持 `PMR` 内存分配器。
     * @warning 对象必须正确定义 `glz::meta` 特化，否则会导致编译错误。
     * @warning 大对象序列化可能分配大量内存，需注意内存使用。
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
     * @details 将 `C++` 对象序列化为 `JSON` 格式字符串，存储到提供的输出缓冲区。
     * 该函数支持错误上下文输出，提供详细的序列化错误信息。
     *
     * 执行流程：
     * @details - 清空输出缓冲区；
     * @details - 调用 `glz::write_json` 进行序列化；
     * @details - 将错误上下文写入 `out_ec` 参数；
     * @details - 序列化失败时清空缓冲区并返回 `false`。
     *
     * 模板约束：
     * @details - `StructureObject` 必须定义了 `glz::meta` 特化或使用 `GLZ_META` 宏；
     * @details - `StructureObject` 应该是可平凡复制的值类型或定义了合适的序列化适配器。
     *
     * 内存管理：
     * @details - 输出缓冲区使用 `memory::string`，继承调用者的内存分配器；
     * @details - 序列化过程可能分配内存存储 `JSON` 字符串，使用 `PMR` 分配器。
     *
     * 错误处理：
     * @details - 序列化成功返回 `true`，输出缓冲区包含 `JSON` 字符串；
     * @details - 序列化失败返回 `false`，输出缓冲区被清空；
     * @details - 错误上下文写入 `out_ec` 参数，便于调试；
     * @details - 不抛出异常，适合在异常禁用或性能敏感场景使用。
     *
     * @tparam StructureObject 待序列化的对象类型，必须定义 `glz::meta` 特化
     * @param value 待序列化的对象实例，按常量引用传递
     * @param out 用于存储序列化结果的字符串引用，使用前会被清空
     * @param out_ec 用于存储序列化错误上下文的引用
     * @return `true` 序列化成功，`false` 序列化失败
     * @note 该函数提供详细的错误上下文，便于调试序列化失败的原因。
     * @note 输出缓冲区使用 `memory::string`，支持 `PMR` 内存分配器。
     * @warning 对象必须正确定义 `glz::meta` 特化，否则会导致编译错误。
     * @warning 大对象序列化可能分配大量内存，需注意内存使用。
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
     * @details 将 `C++` 对象序列化为 `JSON` 格式字符串，返回新分配的字符串。
     * 该函数支持自定义内存分配器，用于控制序列化操作的内存分配行为。
     *
     * 执行流程：
     * @details - 使用指定的内存资源分配输出缓冲区；
     * @details - 调用 `serialize(value, out)` 进行序列化；
     * @details - 序列化失败时清空缓冲区；
     * @details - 返回输出缓冲区，所有权转移给调用者。
     *
     * 模板约束：
     * @details - `StructureObject` 必须定义了 `glz::meta` 特化或使用 `GLZ_META` 宏；
     * @details - `StructureObject` 应该是可平凡复制的值类型或定义了合适的序列化适配器。
     *
     * 内存管理：
     * @details - 使用指定的内存资源分配输出缓冲区；
     * @details - 序列化过程可能分配内存存储 `JSON` 字符串，使用 `PMR` 分配器；
     * @details - 返回的字符串所有权转移给调用者，调用者负责释放。
     *
     * 错误处理：
     * @details - 序列化成功返回包含 `JSON` 字符串的 `memory::string`；
     * @details - 序列化失败返回空字符串；
     * @details - 不抛出异常，适合在异常禁用或性能敏感场景使用。
     *
     * @tparam StructureObject 待序列化的对象类型，必须定义 `glz::meta` 特化
     * @param value 待序列化的对象实例，按常量引用传递
     * @param mr 内存资源指针，默认使用当前线程的内存资源
     * @return `memory::string` 序列化后的 JSON 字符串
     * @note 返回的字符串所有权转移给调用者，调用者负责释放。
     * @note 默认使用当前线程的内存资源，可自定义分配器优化性能。
     * @warning 对象必须正确定义 `glz::meta` 特化，否则会导致编译错误。
     * @warning 大对象序列化可能分配大量内存，需注意内存使用。
     */
    template <typename StructureObject>
    [[nodiscard]] memory::string serialize(const StructureObject &value, const memory::resource_pointer mr = memory::current_resource())
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
     * @details 将 `JSON` 格式字符串反序列化为 `C++` 对象，存储到提供的输出对象。
     * 该函数是反序列化功能的基础版本，使用简单的布尔返回值表示成功/失败。
     *
     * 执行流程：
     * @details - 调用 `glz::read_json` 进行反序列化；
     * @details - 根据 `glaze` 版本适配错误处理（`glz::error_ctx` 或异常）；
     * @details - 对于支持移动构造的类型，使用临时对象避免破坏原对象状态；
     * @details - 反序列化失败时保持原对象不变并返回 `false`。
     *
     * 模板约束：
     * @details - `StructureObject` 必须定义了 `glz::meta` 特化或使用 `GLZ_META` 宏；
     * @details - `StructureObject` 应该是可默认构造和移动赋值的类型。
     *
     * 内存管理：
     * @details - 反序列化过程可能分配内存存储中间数据，使用 `PMR` 分配器；
     * @details - 对于支持移动构造的类型，使用临时对象避免破坏原对象状态。
     *
     * 错误处理：
     * @details - 反序列化成功返回 `true`，输出对象包含反序列化的数据；
     * @details - 反序列化失败返回 `false`，输出对象保持不变；
     * @details - 不抛出异常，适合在异常禁用或性能敏感场景使用。
     *
     * @tparam StructureObject 目标对象类型
     * @param json_data JSON 原始数据
     * @param value 接收数据的对象引用
     * @return `true` 反序列化成功，`false` 反序列化失败
     * @note 该函数不提供详细的错误信息，如需错误上下文请使用 `deserialize(json_data, value, out_ec)` 重载。
     * @note 对于支持移动构造的类型，使用临时对象避免破坏原对象状态。
     * @warning 对象必须正确定义 `glz::meta` 特化，否则会导致编译错误。
     * @warning 大 JSON 文档反序列化可能分配大量内存，需注意内存使用。
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
     * @details 将 `JSON` 格式字符串反序列化为 `C++` 对象，存储到提供的输出对象。
     * 该函数支持错误上下文输出，提供详细的反序列化错误信息。
     *
     * 执行流程：
     * @details - 调用 `glz::read_json` 进行反序列化；
     * @details - 将错误上下文写入 `out_ec` 参数；
     * @details - 对于支持移动构造的类型，使用临时对象避免破坏原对象状态；
     * @details - 反序列化失败时保持原对象不变并返回 `false`。
     *
     * 模板约束：
     * @details - `StructureObject` 必须定义了 `glz::meta` 特化或使用 `GLZ_META` 宏；
     * @details - `StructureObject` 应该是可默认构造和移动赋值的类型。
     *
     * 内存管理：
     * @details - 反序列化过程可能分配内存存储中间数据，使用 `PMR` 分配器；
     * @details - 对于支持移动构造的类型，使用临时对象避免破坏原对象状态。
     *
     * 错误处理：
     * @details - 反序列化成功返回 `true`，输出对象包含反序列化的数据；
     * @details - 反序列化失败返回 `false`，输出对象保持不变；
     * @details - 错误上下文写入 `out_ec` 参数，便于调试；
     * @details - 不抛出异常，适合在异常禁用或性能敏感场景使用。
     *
     * @tparam StructureObject 目标对象类型
     * @param json_data JSON 原始数据
     * @param value 接收数据的对象引用
     * @param out_ec 用于存储反序列化错误上下文的引用
     * @return `true` 反序列化成功，`false` 反序列化失败
     * @note 该函数提供详细的错误上下文，便于调试反序列化失败的原因。
     * @note 对于支持移动构造的类型，使用临时对象避免破坏原对象状态。
     * @warning 对象必须正确定义 `glz::meta` 特化，否则会导致编译错误。
     * @warning 大 JSON 文档反序列化可能分配大量内存，需注意内存使用。
     */
    template <typename StructureObject>
    [[nodiscard]] bool deserialize(const std::string_view json_data, StructureObject &value, glz::error_ctx &out_ec)
    {
        using read_result = decltype(glz::read_json(value, json_data));

        if constexpr (std::is_same_v<read_result, glz::error_ctx>)
        { // 模板类型有无参构造函数或移动赋值运算符
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
                return true;
            }
        }

        return !out_ec;
    }

    /**
     * @brief 将 JSON 字符串反序列化为对象 (带内存资源参数)
     * @details 将 `JSON` 格式字符串反序列化为 `C++` 对象，存储到提供的输出对象。
     * 该函数支持自定义内存分配器，用于控制反序列化操作的内存分配行为。
     *
     * 执行流程：
     * @details - 使用指定的内存资源分配缓冲区；
     * @details - 调用 `glz::read_json` 进行反序列化；
     * @details - 将错误上下文写入 `out_ec` 参数；
     * @details - 对于支持移动构造的类型，使用临时对象避免破坏原对象状态；
     * @details - 反序列化失败时保持原对象不变并返回 `false`。
     *
     * 模板约束：
     * @details - `StructureObject` 必须定义了 `glz::meta` 特化或使用 `GLZ_META` 宏；
     * @details - `StructureObject` 应该是可默认构造、移动赋值和可使用内存资源构造的类型。
     *
     * 内存管理：
     * @details - 使用指定的内存资源分配缓冲区；
     * @details - 反序列化过程可能分配内存存储中间数据，使用 `PMR` 分配器；
     * @details - 对于支持移动构造的类型，使用临时对象避免破坏原对象状态。
     *
     * 错误处理：
     * @details - 反序列化成功返回 `true`，输出对象包含反序列化的数据；
     * @details - 反序列化失败返回 `false`，输出对象保持不变；
     * @details - 错误上下文写入 `out_ec` 参数，便于调试；
     * @details - 不抛出异常，适合在异常禁用或性能敏感场景使用。
     *
     * @tparam StructureObject 目标对象类型
     * @param json_data JSON 原始数据
     * @param value 接收数据的对象引用
     * @param mr 缓冲区使用的内存资源
     * @param out_ec 用于存储反序列化错误上下文的引用
     * @return `true` 反序列化成功，`false` 反序列化失败
     * @note 该函数提供详细的错误上下文，便于调试反序列化失败的原因。
     * @note 对于支持移动构造的类型，使用临时对象避免破坏原对象状态。
     * @warning 对象必须正确定义 `glz::meta` 特化，否则会导致编译错误。
     * @warning 大 JSON 文档反序列化可能分配大量内存，需注意内存使用。
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

    /**
     * @brief 将 JSON 字符串反序列化为对象 (带内存资源参数，忽略错误)
     * @details 将 `JSON` 格式字符串反序列化为 `C++` 对象，存储到提供的输出对象。
     * 该函数支持自定义内存分配器，错误上下文被忽略。
     *
     * 执行流程：
     * @details - 使用指定的内存资源分配缓冲区；
     * @details - 调用 `deserialize(json_data, value, mr, out_ec)` 进行反序列化；
     * @details - 忽略错误上下文，仅返回成功/失败状态。
     *
     * 模板约束：
     * @details - `StructureObject` 必须定义了 `glz::meta` 特化或使用 `GLZ_META` 宏；
     * @details - `StructureObject` 应该是可默认构造、移动赋值和可使用内存资源构造的类型。
     *
     * 内存管理：
     * @details - 使用指定的内存资源分配缓冲区；
     * @details - 反序列化过程可能分配内存存储中间数据，使用 `PMR` 分配器；
     * @details - 对于支持移动构造的类型，使用临时对象避免破坏原对象状态。
     *
     * 错误处理：
     * @details - 反序列化成功返回 `true`，输出对象包含反序列化的数据；
     * @details - 反序列化失败返回 `false`，输出对象保持不变；
     * @details - 错误上下文被忽略，不返回详细错误信息；
     * @details - 不抛出异常，适合在异常禁用或性能敏感场景使用。
     *
     * @tparam StructureObject 目标对象类型
     * @param json_data JSON 原始数据
     * @param value 接收数据的对象引用
     * @param mr 缓冲区使用的内存资源
     * @return `true` 反序列化成功，`false` 反序列化失败
     * @note 该函数忽略错误上下文，仅返回成功/失败状态。
     * @note 对于支持移动构造的类型，使用临时对象避免破坏原对象状态。
     * @warning 对象必须正确定义 `glz::meta` 特化，否则会导致编译错误。
     * @warning 大 JSON 文档反序列化可能分配大量内存，需注意内存使用。
     */
    template <typename StructureObject>
    [[nodiscard]] bool deserialize(const std::string_view json_data, StructureObject &value, memory::resource_pointer mr)
    {
        glz::error_ctx ignored_ec{};
        return deserialize(json_data, value, mr, ignored_ec);
    }

} // namespace ngx::transformer::json
