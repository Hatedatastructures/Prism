/**
 * @file frame.hpp
 * @brief 通用协议帧定义
 * @details 定义了用于内部传输的通用数据帧结构，支持文本、二进制及控制帧。
 * 该模块提供了跨协议的统一数据表示格式，支持序列化和反序列化操作。
 *
 * 设计目的：
 * - 统一数据表示：为不同协议提供通用的数据帧格式；
 * - 跨协议传输：支持在 HTTP、SOCKS5、TLS 等协议间传输结构化数据；
 * - 帧式通信：支持多路复用、流量控制和可靠传输；
 * - 序列化支持：提供二进制序列化和反序列化功能。
 *
 * 帧特性：
 * - 类型安全：使用 `enum class` 定义帧类型，防止无效值；
 * - 扩展性：帧结构可容纳任意二进制数据；
 * - 轻量级：帧头开销小（5字节），适合高频通信；
 * - 自描述：包含类型和ID，支持多路复用和排序。
 *
 * 使用场景：
 * - 内部组件间通信（如 `agent` 与 `transport` 之间）；
 * - 协议桥接（将 HTTP 请求转换为帧格式传输）；
 * - 控制信令（连接管理、心跳检测等）。
 *
 * 序列化格式：
 * - 帧头：1字节类型 + 4字节ID（网络字节序）；
 * - 负载：可变长度二进制数据；
 * - 总长度：5字节 + 负载长度。
 *
 * @note 该帧格式类似于 WebSocket 帧，但更简化，适合代理内部使用。
 * @warning 帧负载使用 `std::string` 存储，可能引起内存拷贝开销。
 * @see ngx::protocol::analysis 协议分析
 * @see ngx::agent 协议处理器
 *
 */
#pragma once

#include <string>
#include <string_view>
#include <forward-engine/gist.hpp>

namespace ngx::protocol
{
    /**
     * @brief 协议帧结构
     * @details 包含帧类型、ID 和负载数据，是跨协议通信的基本数据单元。
     * 该结构体定义了代理内部通信的统一数据格式，支持序列化和反序列化。
     *
     * 设计原则：
     * - 简单性：仅包含必要字段，避免过度设计；
     * - 通用性：支持文本和二进制数据，满足多种场景；
     * - 可扩展性：通过类型字段支持新的帧类型；
     * - 兼容性：使用标准类型，确保跨平台兼容。
     *
     * 内存管理：
     * - 负载使用 `std::string` 存储，方便与现有代码集成；
     * - 可使用 `std::string_view` 构造，避免不必要的数据拷贝；
     * - 大负载可能引起内存分配，应注意性能影响。
     *
     * 使用模式：
     * 1. 创建帧对象并设置类型、ID 和负载；
     * 2. 使用 `serialize()` 转换为二进制数据；
     * 3. 通过传输层发送二进制数据；
     * 4. 接收方使用 `deserialize()` 还原帧对象。
     *
     * @note 帧 ID 可用于多路复用、排序或关联请求-响应。
     * @warning 负载数据可能较大，传输时应注意分片和流量控制。
     */
    struct frame
    {
        /**
         * @brief 帧类型枚举
         * @details 定义帧的功能类别，影响接收方的处理逻辑。
         * 枚举值基于 WebSocket 帧类型设计，但经过简化以适应代理场景。
         *
         * 枚举值说明：
         * - `text`：文本帧，负载为 UTF-8 编码的文本数据；
         * - `binary`：二进制帧，负载为任意二进制数据；
         * - `close`：关闭帧，表示连接应被关闭；
         * - `ping`：Ping 帧，用于心跳检测和保活；
         * - `pong`：Pong 帧，对 Ping 帧的响应。
         *
         * 类型语义：
         * - 数据帧：`text` 和 `binary` 携带应用数据；
         * - 控制帧：`close`、`ping`、`pong` 用于连接管理；
         * - 扩展类型：预留值空间（0x0, 0x3-0x7, 0xB-0xF）供未来使用。
         *
         * 数值选择：
         * - 与 WebSocket 帧类型值保持一致，便于理解；
         * - 使用十六进制表示，突出位模式；
         * - 基础类型使用低位值，控制类型使用高位值。
         *
         * @note 使用 `std::uint8_t` 作为底层类型，确保序列化后为 1 字节。
         * @warning 不要使用未定义的枚举值，可能导致未定义行为。
         */
        enum class type : std::uint8_t
        {
            text = 0x1,   ///< 文本帧，负载为 UTF-8 编码的文本数据
            binary = 0x2, ///< 二进制帧，负载为任意二进制数据
            close = 0x8,  ///< 关闭帧，表示连接应被关闭
            ping = 0x9,   ///< Ping 帧，用于心跳检测和保活
            pong = 0xA,   ///< Pong 帧，对 Ping 帧的响应
        };

        type type;           ///< 帧类型，决定帧的语义和处理方式
        std::uint32_t id;    ///< 帧 ID，用于多路复用、排序或关联请求-响应
        std::string payload; ///< 帧负载数据，可以是文本或二进制内容

        /**
         * @brief 默认构造函数
         * @details 创建未初始化的帧对象，所有成员使用默认值。
         * 默认构造的帧类型为值初始化的 `type`（实际上是 `type(0)`），
         * ID 为 0，负载为空字符串。
         *
         * 使用场景：
         * - 作为容器元素占位符；
         * - 在反序列化前创建目标对象；
         * - 需要延迟初始化的场景。
         *
         * @note 默认构造的帧可能包含无效类型值，应尽快初始化。
         * @warning 不要使用未初始化的帧进行序列化或传输。
         */
        frame() = default;

        /**
         * @brief 参数化构造函数
         * @details 使用指定的类型、ID 和负载数据构造帧对象。
         * 构造函数通过 `std::string_view` 接受负载数据，避免不必要的拷贝。
         *
         * 参数说明：
         * - `type`：帧类型，必须是有效的 `frame::type` 枚举值；
         * - `id`：帧 ID，通常由调用者分配，用于标识帧的用途；
         * - `payload`：负载数据，可以是文本或二进制，通过视图传递。
         *
         * 性能考虑：
         * - 负载数据通过 `std::string_view` 传递，避免拷贝；
         * - 内部使用 `std::string` 的构造函数从视图创建字符串；
         * - 如果负载数据已存在于 `std::string` 中，可能引起内存分配。
         *
         * @param type 帧类型，必须是有效的 `frame::type` 枚举值
         * @param id 帧 ID，用于多路复用、排序或关联请求-响应
         * @param payload 负载数据，通过 `std::string_view` 传递以避免拷贝
         * @note 负载数据被拷贝到内部的 `std::string` 中，确保生命周期独立。
         * @warning ID 为 0 是有效值，但某些协议可能赋予特殊含义。
         */
        frame(const enum type type, const std::uint32_t id, const std::string_view payload)
            : type(type), id(id), payload(payload) {}
    };

    /**
     * @brief 序列化帧
     * @details 将帧对象转换为二进制数据，用于网络传输或持久化存储。
     * 序列化后的数据格式为：1字节类型 + 4字节ID（网络字节序）+ 可变长度负载。
     *
     * 序列化格式：
     * - 字节 0：帧类型（`std::uint8_t`），直接存储枚举值；
     * - 字节 1-4：帧 ID（`std::uint32_t`），大端字节序（网络字节序）；
     * - 字节 5+：负载数据，原始二进制内容。
     *
     * 性能特性：
     * - 返回 `std::string` 包含二进制数据，可能引起内存分配；
     * - 负载数据直接拷贝，无编码或转义开销；
     * - 帧头使用固定大小，计算复杂度 O(1)。
     *
     * 错误处理：
     * - 无效帧类型：直接存储枚举值，反序列化时可能产生无效帧；
     * - 内存不足：抛出 `std::bad_alloc` 异常；
     * - 负载过大：可能导致大内存分配，调用者应注意限制负载大小。
     *
     * 使用场景：
     * - 网络传输前将帧转换为二进制格式；
     * - 将帧存储到文件或数据库；
     * - 调试和日志记录（可转换为十六进制字符串）。
     *
     * @param frame_instance 待序列化的帧对象，包含类型、ID 和负载数据
     * @return `std::string` 序列化后的二进制数据，可直接通过套接字发送
     * @throws `std::bad_alloc` 如果内存分配失败
     * @note 序列化后的数据不包含长度前缀，接收方需要知道格式才能正确解析。
     * @warning 负载数据可能包含空字节，不能作为 C 字符串处理。
     * @warning 大负载可能导致性能问题，应考虑分帧传输。
     *
     * ```
     * // 使用示例：序列化帧并发送
     * frame f{frame::type::text, 123, "Hello, World!"};
     * auto binary_data = serialize(f);
     * // 通过传输层发送 binary_data
     * co_await trans->async_write_some(binary_data, ec);
     *
     */
    [[nodiscard]] auto serialize(const frame &frame_instance)
        -> std::string;

    /**
     * @brief 反序列化帧
     * @details 将二进制数据还原为帧对象，是 `serialize()` 的逆操作。
     * 该函数解析符合帧格式的二进制数据，提取帧类型、ID 和负载，填充到输出帧对象中。
     *
     * 解析流程：
     * 1. 长度检查：验证输入数据至少包含 5 字节帧头；
     * 2. 类型提取：读取第一个字节作为帧类型；
     * 3. ID 提取：读取接下来 4 字节（网络字节序）作为帧 ID；
     * 4. 负载提取：剩余字节作为负载数据，拷贝到帧对象中；
     * 5. 验证检查：验证帧类型是否为有效枚举值。
     *
     * 错误处理：
     * - 数据过短：返回 `gist::code::invalid_argument`；
     * - 无效类型：返回 `gist::code::invalid_argument`；
     * - 内存不足：返回 `gist::code::out_of_memory`；
     * - 成功：返回 `gist::code::ok`。
     *
     * 输入要求：
     * - 二进制数据必须由 `serialize()` 函数生成；
     * - 数据必须完整，不能是分片或部分数据；
     * - 帧头必须使用网络字节序（大端）。
     *
     * 输出说明：
     * - 成功时，`frame_instance` 被填充为解析出的帧；
     * - 失败时，`frame_instance` 的状态未定义，不应使用；
     * - 函数不修改输入数据，仅读取。
     *
     * 性能特性：
     * - 使用 `std::string_view` 避免数据拷贝；
     * - 负载数据拷贝到输出帧的 `std::string` 中；
     * - 帧头解析使用简单指针运算，无额外开销。
     *
     * 使用场景：
     * - 从网络接收数据后还原为帧对象；
     * - 从存储介质读取持久化的帧数据；
     * - 调试和测试序列化/反序列化逻辑。
     *
     * @param string_value 输入的二进制数据，必须是完整的序列化帧数据
     * @param frame_instance 输出的帧对象，成功时被填充为解析结果
     * @return `gist::code` 反序列化结果状态码，`gist::code::ok` 表示成功
     * @note 输入数据必须至少 5 字节，否则无法解析帧头。
     * @warning 失败时不要使用 `frame_instance`，它的状态可能被部分修改。
     * @warning 负载数据可能包含空字节，不能作为 C 字符串处理。
     *
     * ```
     * // 使用示例：接收并反序列化帧
     * std::array<std::byte, 4096> buffer;
     * std::error_code ec;
     * std::size_t n = co_await trans->async_read_some(buffer, ec);
     *
     * frame f;
     * auto code = deserialize(std::string_view(reinterpret_cast<const char*>(buffer.data()), n), f);
     * if (code == gist::code::ok)
     * {
     *     // 处理帧 f
     *     log::info("收到帧: type={}, id={}, size={}",
     *               to_string_view(f.type), f.id, f.payload.size());
     * }
     *
     */
    [[nodiscard]] auto deserialize(std::string_view string_value, frame &frame_instance)
        -> gist::code;
}
