#pragma once

/**
 * @file primitives.hpp
 * @brief 管道原语定义
 * @details 定义协议管道共享的通用原语组件，包括连接关闭、预读回放、
 * 上游拨号、TLS 握手以及双向隧道转发等核心功能。这些原语为 HTTP、SOCKS5、TLS
 * 等具体协议处理提供底层支撑，确保协议处理逻辑的一致性和可复用性。
 */

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <memory>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <forward-engine/agent/context.hpp>
#include <forward-engine/resolve/router.hpp>
#include <forward-engine/fault/code.hpp>
#include <forward-engine/memory/container.hpp>
#include <forward-engine/protocol/analysis.hpp>
#include <forward-engine/trace/spdlog.hpp>
#include <forward-engine/channel/transport/transmission.hpp>
#include <forward-engine/channel/adapter/connector.hpp>

/**
 * @namespace ngx::agent::pipeline::primitives
 * @brief 管道原语命名空间
 * @details 提供协议处理管道的基础原语实现，包括传输层资源管理、
 * 上游连接建立、预读数据回放以及全双工隧道转发等功能。这些原语
 * 被上层协议处理器直接调用，不应在协议检测阶段使用。
 */
namespace ngx::agent::pipeline::primitives
{
    namespace net = boost::asio;
    namespace ssl = net::ssl;

    using ssl_connector = channel::connector;
    using ssl_stream = ssl::stream<ssl_connector>;
    using shared_ssl_stream = std::shared_ptr<ssl_stream>;
    using shared_transmission = channel::transport::shared_transmission;

    /**
     * @brief 关闭裸指针指向的传输对象
     * @param trans 传输对象的裸指针，可为空
     * @details 安全地关闭传输连接，若指针为空则不做任何操作。
     * 该函数不释放内存，仅调用传输对象的 close 方法。
     */
    inline void shut_close(ngx::channel::transport::transmission *trans) noexcept
    {
        if (trans)
        {
            trans->close();
        }
    }

    /**
     * @brief 关闭并释放智能指针持有的传输对象
     * @param trans 持有传输对象的智能指针
     * @details 先关闭传输连接，然后释放智能指针持有的所有权。
     * 该函数确保资源被正确清理，适用于需要同时关闭连接和释放
     * 所有权的场景。
     */
    inline void shut_close(shared_transmission &trans) noexcept
    {
        if (trans)
        {
            trans->close();
            trans.reset();
        }
    }

    /**
     * @brief 拨号连接上游服务器并包装为可靠传输
     * @param router 路由器，用于选择上游路由
     * @param label 协议标签，用于日志记录
     * @param target 解析后的上游目标地址
     * @param allow_reverse 是否允许使用反向路由
     * @param require_open 是否要求返回的套接字已打开
     * @return 协程对象，完成后返回结果码和传输对象的配对
     * @details 根据目标地址的正向或反向标记，调用路由器的正向或反向
     * 路由方法建立连接。连接成功后，将原始套接字包装为可靠传输对象
     * 返回。若路由失败或连接无效，返回相应的错误码和空指针。
     */
    auto dial(std::shared_ptr<resolve::router> router, std::string_view label,
              const protocol::analysis::target &target, bool allow_reverse, bool require_open)
        -> net::awaitable<std::pair<fault::code, shared_transmission>>;

    /**
     * @brief 执行 TLS 服务端握手
     * @param ctx 会话上下文，包含入站传输和 SSL 配置
     * @param data 预读数据，协议检测时读取的初始数据
     * @return 协程对象，完成后返回错误码和 TLS 流的共享指针
     * @details 将入站传输层包装为 connector，执行 TLS 服务端握手，
     * 返回可用于后续协议处理的 TLS 流。该函数是所有需要 TLS 的协议
     * 的通用握手入口，支持 HTTPS、Trojan over TLS 等场景。
     * @note 返回的 TLS 流通过 shared_ptr 管理，可被多个组件共享。
     * @warning 调用后 ctx.inbound 的所有权被转移，调用者不应再使用。
     */
    auto ssl_handshake(session_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<std::pair<fault::code, shared_ssl_stream>>;

    /**
     * @class preview
     * @brief 预读数据回放包装器
     * @details 在协议嗅探阶段，部分数据可能已被从入站传输中读取。
     * 该包装器将这些预读数据保存在内部，在后续读取时优先返回预读
     * 数据，待预读数据耗尽后再委托给内部传输对象。这确保了协议
     * 管道在嗅探后仍能一致地处理数据流。
     * @note 该类继承自 transmission 抽象基类，可透明地替换原始传输。
     * @note 预读数据在构造时被复制到内部缓冲区，确保数据生命周期安全。
     */
    class preview final : public channel::transport::transmission
    {
    public:
        /**
         * @brief 构造预读回放包装器
         * @param inner 被包装的内部传输对象
         * @param preread 协议嗅探期间捕获的预读数据
         * @param mr 内存资源，用于预读缓冲区分配
         * @details 构造时会将预读数据复制到内部缓冲区，确保数据所有权安全。
         */
        explicit preview(shared_transmission inner, std::span<const std::byte> preread,
                         memory::resource_pointer mr = memory::current_resource());

        /**
         * @brief 报告内部传输是否可靠
         * @return 若内部传输可靠则返回 true，否则返回 false
         */
        [[nodiscard]] bool is_reliable() const noexcept override;

        /**
         * @brief 获取内部传输的执行器
         * @return 绑定到内部传输的执行器
         */
        [[nodiscard]] executor_type executor() const override;

        /**
         * @brief 从预读缓冲区或内部流读取数据
         * @param buffer 目标缓冲区
         * @param ec 输出错误码
         * @return 协程对象，完成后返回读取的字节数
         * @details 优先从预读缓冲区返回数据，预读数据耗尽后委托给
         * 内部传输对象进行实际读取。
         */
        auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 将数据写入内部流
         * @param buffer 源数据缓冲区
         * @param ec 输出错误码
         * @return 协程对象，完成后返回写入的字节数
         */
        auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 完整写入操作
         * @details 委托给内部传输的 async_write，让子类（如 UDP）的特化生效。
         */
        auto async_write(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!inner_)
            {
                ec = std::make_error_code(std::errc::bad_file_descriptor);
                co_return 0;
            }
            co_return co_await inner_->async_write(buffer, ec);
        }

        /**
         * @brief 关闭内部传输流
         */
        void close() override;

        /**
         * @brief 取消内部传输的待处理操作
         */
        void cancel() override;

    private:
        shared_transmission inner_;                // 内部传输对象
        memory::vector<std::byte> preread_buffer_; // 预读数据缓冲区（拥有所有权）
        std::size_t offset_{0};                    // 当前预读偏移量
    };

    /**
     * @brief 在两个流之间运行全双工隧道
     * @param inbound 入站流对象
     * @param outbound 出站流对象
     * @param ctx 会话上下文，提供内存资源和缓冲区配置
     * @param complete_write 是否使用完整写入语义（默认 true）
     * @return 协程对象，隧道结束后完成
     * @details 建立双向数据转发隧道，同时处理入站到出站和出站到入站
     * 的数据流。隧道使用两个半缓冲区分别处理两个方向的数据转发，
     * 任一方向断开即终止整个隧道。隧道结束后自动关闭两端的连接。
     * 当 complete_write 为 true 时，写入操作采用完整写入语义，
     * 确保所有读取的数据都被完整写入对端；为 false 时使用单次写入，
     * 适用于对吞吐量优先于可靠性的场景。
     * @note 缓冲区大小至少为 2 字节，实际使用时建议不小于 64KB。
     */
    auto tunnel(shared_transmission inbound, shared_transmission outbound,
                const session_context &ctx, bool complete_write = true)
        -> net::awaitable<void>;
} // namespace ngx::agent::pipeline::primitives
