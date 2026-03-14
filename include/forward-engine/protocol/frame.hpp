/**
 * @file frame.hpp
 * @brief 通用协议帧定义
 * @details 定义了用于内部传输的通用数据帧结构，支持文本、二进制及控制帧。
 * 该模块提供了跨协议的统一数据表示格式，支持序列化和反序列化操作。
 * 设计目的包括统一数据表示，为不同协议提供通用的数据帧格式。支持跨
 * 协议传输，在 HTTP、SOCKS5、TLS 等协议间传输结构化数据。支持帧式
 * 通信，实现多路复用、流量控制和可靠传输。提供序列化支持，支持二进制
 * 序列化和反序列化功能。帧特性包括类型安全，使用 enum class 定义帧类型，
 * 防止无效值。具有扩展性，帧结构可容纳任意二进制数据。轻量级设计，
 * 帧头开销小仅 5 字节，适合高频通信。自描述特性，包含类型和 ID，支持
 * 多路复用和排序。序列化格式为帧头 1 字节类型加 4 字节 ID 网络字节序，
 * 负载为可变长度二进制数据，总长度为 5 字节加负载长度。
 * @note 该帧格式类似于 WebSocket 帧，但更简化，适合代理内部使用。
 * @warning 帧负载使用 std::string 存储，可能引起内存拷贝开销。
 */
#pragma once

#include <string>
#include <string_view>
#include <forward-engine/gist.hpp>

/**
 * @namespace ngx::protocol
 * @brief 协议处理模块
 * @details 该命名空间包含所有协议相关的实现，包括协议分析、帧定义、
 * HTTP、SOCKS5、Trojan 等协议的完整实现。模块设计遵循零拷贝和高性能
 * 原则，所有协议处理器都使用 PMR 内存池管理内存，确保热路径无堆分配。
 */
namespace ngx::protocol
{
    /**
     * @struct frame
     * @brief 协议帧结构
     * @details 包含帧类型、ID 和负载数据，是跨协议通信的基本数据单元。
     * 该结构体定义了代理内部通信的统一数据格式，支持序列化和反序列化。
     * 设计原则包括简单性，仅包含必要字段，避免过度设计。具有通用性，
     * 支持文本和二进制数据，满足多种场景。具有可扩展性，通过类型字段
     * 支持新的帧类型。具有兼容性，使用标准类型，确保跨平台兼容。内存
     * 管理方面，负载使用 std::string 存储，方便与现有代码集成。可使用
     * std::string_view 构造，避免不必要的数据拷贝。大负载可能引起内存
     * 分配，应注意性能影响。使用模式为创建帧对象并设置类型、ID 和负载，
     * 使用 serialize 转换为二进制数据，通过传输层发送二进制数据，接收方
     * 使用 deserialize 还原帧对象。
     * @note 帧 ID 可用于多路复用、排序或关联请求响应。
     * @warning 负载数据可能较大，传输时应注意分片和流量控制。
     */
    struct frame
    {
        /**
         * @enum type
         * @brief 帧类型枚举
         * @details 定义帧的功能类别，影响接收方的处理逻辑。枚举值基于
         * WebSocket 帧类型设计，但经过简化以适应代理场景。text 为文本帧，
         * 负载为 UTF-8 编码的文本数据。binary 为二进制帧，负载为任意二进制
         * 数据。close 为关闭帧，表示连接应被关闭。ping 为 Ping 帧，用于
         * 心跳检测和保活。pong 为 Pong 帧，对 Ping 帧的响应。类型语义方面，
         * text 和 binary 携带应用数据为数据帧，close、ping、pong 用于连接
         * 管理为控制帧。数值选择与 WebSocket 帧类型值保持一致，便于理解。
         * 使用十六进制表示，突出位模式。基础类型使用低位值，控制类型使用
         * 高位值。
         * @note 使用 std::uint8_t 作为底层类型，确保序列化后为 1 字节。
         * @warning 不要使用未定义的枚举值，可能导致未定义行为。
         */
        enum class type : std::uint8_t
        {
            text = 0x1,
            binary = 0x2,
            close = 0x8,
            ping = 0x9,
            pong = 0xA,
        };

        // 帧类型，决定帧的语义和处理方式
        enum type type;
        // 帧 ID，用于多路复用、排序或关联请求响应
        std::uint32_t id;
        // 帧负载数据，可以是文本或二进制内容
        std::string payload;

        /**
         * @brief 默认构造函数
         * @details 创建未初始化的帧对象，所有成员使用默认值。默认构造的
         * 帧类型为值初始化的 type 即 type(0)，ID 为 0，负载为空字符串。
         * 使用场景包括作为容器元素占位符，在反序列化前创建目标对象，
         * 以及需要延迟初始化的场景。
         * @note 默认构造的帧可能包含无效类型值，应尽快初始化。
         * @warning 不要使用未初始化的帧进行序列化或传输。
         */
        frame() = default;

        /**
         * @brief 参数化构造函数
         * @details 使用指定的类型、ID 和负载数据构造帧对象。构造函数通过
         * std::string_view 接受负载数据，避免不必要的拷贝。type 为帧类型，
         * 必须是有效的 frame::type 枚举值。id 为帧 ID，通常由调用者分配，
         * 用于标识帧的用途。payload 为负载数据，可以是文本或二进制，
         * 通过视图传递。性能考虑方面，负载数据通过 std::string_view 传递，
         * 避免拷贝。内部使用 std::string 的构造函数从视图创建字符串。如果
         * 负载数据已存在于 std::string 中，可能引起内存分配。
         * @param type 帧类型，必须是有效的 frame::type 枚举值
         * @param id 帧 ID，用于多路复用、排序或关联请求响应
         * @param payload 负载数据，通过 std::string_view 传递以避免拷贝
         * @note 负载数据被拷贝到内部的 std::string 中，确保生命周期独立。
         * @warning ID 为 0 是有效值，但某些协议可能赋予特殊含义。
         */
        frame(const enum type type, const std::uint32_t id, const std::string_view payload)
            : type(type), id(id), payload(payload) {}
    };

    /**
     * @brief 序列化帧
     * @details 将帧对象转换为二进制数据，用于网络传输或持久化存储。
     * 序列化后的数据格式为 1 字节类型加 4 字节 ID 网络字节序加可变长度
     * 负载。字节 0 为帧类型 std::uint8_t，直接存储枚举值。字节 1 到 4
     * 为帧 ID std::uint32_t，大端字节序即网络字节序。字节 5 及以后为
     * 负载数据，原始二进制内容。性能特性方面，返回 std::string 包含
     * 二进制数据，可能引起内存分配。负载数据直接拷贝，无编码或转义开销。
     * 帧头使用固定大小，计算复杂度 O(1)。错误处理方面，无效帧类型直接
     * 存储枚举值，反序列化时可能产生无效帧。内存不足抛出 std::bad_alloc
     * 异常。负载过大可能导致大内存分配，调用者应注意限制负载大小。
     * @param frame_instance 待序列化的帧对象，包含类型、ID 和负载数据
     * @return std::string 序列化后的二进制数据，可直接通过套接字发送
     * @throws std::bad_alloc 如果内存分配失败
     * @note 序列化后的数据不包含长度前缀，接收方需要知道格式才能正确解析。
     * @warning 负载数据可能包含空字节，不能作为 C 字符串处理。
     * @warning 大负载可能导致性能问题，应考虑分帧传输。
     */
    [[nodiscard]] auto serialize(const frame &frame_instance)
        -> std::string;

    /**
     * @brief 反序列化帧
     * @details 将二进制数据还原为帧对象，是 serialize 的逆操作。该函数
     * 解析符合帧格式的二进制数据，提取帧类型、ID 和负载，填充到输出帧
     * 对象中。解析流程为首先进行长度检查，验证输入数据至少包含 5 字节
     * 帧头。然后进行类型提取，读取第一个字节作为帧类型。接着进行 ID
     * 提取，读取接下来 4 字节网络字节序作为帧 ID。再进行负载提取，剩余
     * 字节作为负载数据，拷贝到帧对象中。最后进行验证检查，验证帧类型
     * 是否为有效枚举值。错误处理方面，数据过短返回 gist::code::invalid
     * _argument，无效类型返回 gist::code::invalid_argument，内存不足
     * 返回 gist::code::out_of_memory，成功返回 gist::code::ok。输入
     * 要求数据必须由 serialize 函数生成，数据必须完整不能是分片或部分
     * 数据，帧头必须使用网络字节序大端。输出说明方面，成功时 frame
     * _instance 被填充为解析出的帧，失败时 frame_instance 的状态未定义
     * 不应使用，函数不修改输入数据仅读取。性能特性方面，使用 std::string
     * _view 避免数据拷贝，负载数据拷贝到输出帧的 std::string 中，帧头
     * 解析使用简单指针运算无额外开销。
     * @param string_value 输入的二进制数据，必须是完整的序列化帧数据
     * @param frame_instance 输出的帧对象，成功时被填充为解析结果
     * @return gist::code 反序列化结果状态码，gist::code::ok 表示成功
     * @note 输入数据必须至少 5 字节，否则无法解析帧头。
     * @warning 失败时不要使用 frame_instance，它的状态可能被部分修改。
     * @warning 负载数据可能包含空字节，不能作为 C 字符串处理。
     */
    [[nodiscard]] auto deserialize(std::string_view string_value, frame &frame_instance)
        -> gist::code;
}
