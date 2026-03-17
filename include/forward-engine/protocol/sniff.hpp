/**
 * @file sniff.hpp
 * @brief 协议探测
 * @details 从传输层检测协议类型，支持 HTTP、SOCKS5、TLS 等协议识别。
 * 该文件是 agent::detection 命名空间的重构版本，职责下沉到 protocol 层。
 * 核心功能包括异步预读传输层数据，基于预读数据识别协议类型，返回探测
 * 结果和预读数据供后续处理。设计特性包括零拷贝，预读数据直接传递给
 * 协议处理器。支持协程，使用 awaitable 异步接口。错误容忍，探测失败
 * 返回 unknown 类型。
 * @note 预读数据默认为 24 字节，足够识别大多数协议的头部特征。
 * @warning 探测结果基于有限数据，后续数据可能推翻当前判断。
 */
#pragma once

#include <array>
#include <cstddef>
#include <span>
#include <string_view>

#include <boost/asio.hpp>

#include <forward-engine/gist/code.hpp>
#include <forward-engine/protocol/analysis.hpp>
#include <forward-engine/channel/transport/transmission.hpp>

/**
 * @namespace ngx::protocol::sniff
 * @brief 协议探测模块
 * @details 该命名空间提供协议探测功能，从传输层异步读取初始数据并识别
 * 协议类型。模块设计为无状态，所有操作通过函数实现。探测结果包含协议
 * 类型、预读数据和错误代码，供后续协议处理器使用。
 */
namespace ngx::protocol::sniff
{
    namespace net = boost::asio;

    /**
     * @struct detection_result
     * @brief 协议检测结果
     * @details 包含协议类型和预读数据。该结构体由 probe 函数返回，用于
     * 传递协议检测的结果和预读的初始数据。设计目的包括结果封装，统一封装
     * 协议检测的类型、数据和错误信息。支持数据复用，预读数据可被协议处理
     * 器复用，避免重复读取。提供错误处理，通过 gist::code 提供详细的错误
     * 信息。数据流为 probe 预读数据并检测协议类型，将检测结果和预读数据
     * 填充到 detection_result，会话将结果传递给对应的协议处理器，处理器
     * 使用预读数据避免重复读取。成员说明方面，type 为检测到的协议类型
     * 枚举值，失败时为 unknown。pre_read_data 为 32 字节的预读数据缓冲区。
     * pre_read_size 为实际预读的数据大小，范围 0 到 32 字节。ec 为检测过程
     * 中的错误代码，成功时为 gist::code::success。
     * @note 预读数据的大小最多为 32 字节，足够识别大多数协议的头部特征。
     * @warning 如果检测失败，type 为 unknown，ec 包含错误代码。
     */
    struct detection_result
    {
        // 检测到的协议类型，失败时为 unknown
        protocol_type type{protocol_type::unknown};
        // 预读数据缓冲区，最大 32 字节
        std::array<std::byte, 32> pre_read_data{};
        // 实际预读的数据大小
        std::size_t pre_read_size{0};
        // 检测过程中的错误代码
        gist::code ec{gist::code::success};

        /**
         * @brief 检测是否成功
         * @details 检查协议检测是否成功。成功的条件为错误代码为
         * gist::code::success，且协议类型不是 unknown。
         * @return true 如果检测成功，否则 false
         */
        auto success() const noexcept -> bool
        {
            return ec == gist::code::success && type != protocol_type::unknown;
        }

        /**
         * @brief 获取预读数据的字符串视图
         * @details 将预读的二进制数据转换为字符串视图，方便协议检测
         * 函数使用。返回的视图指向内部缓冲区，生命周期与结构体相同。
         * @return std::string_view 预读数据的字符串视图
         */
        auto preload_view() const noexcept -> std::string_view
        {
            return std::string_view(reinterpret_cast<const char *>(pre_read_data.data()), pre_read_size);
        }
    };

    /**
     * @brief 从 transmission 对象检测协议类型
     * @details 异步预读传输层数据并检测协议类型。这是协议识别的核心函数。
     * 执行流程为首先异步预读，调用 async_read_some 读取最多 max_peek_size
     * 字节数据。然后进行协议检测，将读取的数据转换为字符串视图，调用
     * analysis::detect 检测协议。接着填充结果，将检测结果和预读数据填充
     * 到 detection_result。最后处理错误，处理读取错误和 EOF 情况。预读
     * 策略方面，默认预读 24 字节，足够识别 HTTP、SOCKS5 和 TLS 协议头部。
     * 实际读取量受传输层可用数据和缓冲区大小限制。读取的数据保存在结果
     * 中，避免协议处理器重复读取。
     * @param trans 传输层对象引用，必须处于已连接状态
     * @param max_peek_size 最大预读字节数，默认 24，应足够识别协议特征
     * @return net::awaitable<detection_result> 异步检测结果
     * @note 预读数据大小不应超过 32 字节，即 detection_result 缓冲区大小。
     * @warning 如果传输层已关闭或出错，返回的 ec 将包含相应错误代码。
     */
    inline auto probe(ngx::channel::transport::transmission &trans, std::size_t max_peek_size = 24)
        -> net::awaitable<detection_result>
    {
        detection_result result;

        const std::size_t peek_size = (std::min)(max_peek_size, result.pre_read_data.size());
        auto span = std::span<std::byte>(result.pre_read_data.data(), peek_size);

        std::error_code sys_ec;
        std::size_t n = co_await trans.async_read_some(span, sys_ec);
        if (sys_ec)
        {
            result.ec = gist::to_code(sys_ec);
            co_return result;
        }
        if (n == 0)
        {
            result.ec = gist::code::eof;
            co_return result;
        }

        std::string_view peek_view(reinterpret_cast<const char *>(result.pre_read_data.data()), n);
        result.type = protocol::analysis::detect(peek_view);

        result.pre_read_size = n;
        result.ec = gist::code::success;

        co_return result;
    }
}
