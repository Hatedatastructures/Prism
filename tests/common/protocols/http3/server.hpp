/**
 * @file server.hpp
 * @brief HTTP/3 服务端独立入口（preview::http3 通用封装）
 * @details 从 core/http3/session.hpp 的 hysteria2::h3::auth_server 提炼
 * 通用服务端入口：统一命名空间 preview::http3，以 server_options
 * 收敛构造参数（内存资源 / 认证回调 / 数据回调），并提供
 * make_server 工厂。内部薄封装 hysteria2::h3::auth_server，不重复
 * 实现 nghttp3 接线逻辑（session.hpp 已字节级兼容 quic-go）。
 * @note 认证数据路径：feed() 喂入 nghttp3 → auth_headers_complete()
 *       就绪 → check_auth() 走认证回调 → submit_auth_response()。
 *       on_data 回调为预留接口，当前后端丢弃 DATA 载荷
 *       （仅认证场景），接入完整数据路径后触发。
 * @note 所有 nghttp3 调用必须在同一 io_context 线程串行执行。
 */

#pragma once

#include <common/protocols/http3/session.hpp>

#include <common/core/fault/code.hpp>
#include <common/core/memory/container.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string_view>

namespace preview::http3
{

    /**
     * @struct server_options
     * @brief HTTP/3 服务端构造选项
     * @details 统一服务端配置入口：内存资源 + 认证判定回调 +
     * 数据回调。认证回调返回 true 视为通过，空回调默认放行。
     */
    struct server_options
    {
        memory::resource_pointer mr{nullptr}; ///< 内存资源（nullptr = 当前默认资源）
        /**
         * @brief 认证回调
         * @param method 请求方法（:method）
         * @param path 请求路径（:path）
         * @param auth 认证凭据（Hysteria-Auth 头）
         * @return 通过返回 true
         */
        std::function<bool(std::string_view method, std::string_view path, std::string_view auth)>
            authenticate;
        /**
         * @brief 数据回调（预留，认证阶段不触发）
         * @param stream_id 流 ID
         * @param data 载荷
         * @param fin 流是否结束
         */
        std::function<void(std::int64_t stream_id, std::span<const std::byte> data, bool fin)> on_data;
    };

    /// nghttp3 输出包（目标 QUIC 流 + 待发字节，对齐后端类型）
    using out_packet = preview::http3::out_packet;

    /**
     * @class server
     * @brief HTTP/3 服务端通用入口
     * @details 薄封装 hysteria2::h3::auth_server：持有构造选项，
     * 对外暴露同一套 feed / pump_output / 认证查询接口，
     * 并追加 check_auth()（走 options.authenticate）与
     * options() 访问器。其余行为与后端完全一致。
     */
    class server : public std::enable_shared_from_this<server>
    {
    public:
        /**
         * @brief 构造函数
         * @param options 构造选项（内部补齐 mr 默认值）
         */
        explicit server(server_options options)
            : options_(std::move(options)),
              inner_([&]() -> memory::resource_pointer {
                  if (options_.mr)
                  {
                      return options_.mr;
                  }
                  return memory::current_resource();
              }())
        {
        }

        server(const server &) = delete;
        auto operator=(const server &) -> server & = delete;

        /**
         * @brief 初始化：创建 nghttp3 服务端连接 + 控制流/QPACK 流
         * @param open_uni_stream QUIC 层开单向流回调（失败返回 -1）
         * @return 是否成功
         */
        [[nodiscard]] auto init(std::function<std::int64_t()> open_uni_stream) -> bool
        {
            return inner_.init(std::move(open_uni_stream));
        }

        /**
         * @brief 喂入流数据（QUIC 流 → nghttp3）
         * @param stream_id 流 ID
         * @param data 明文数据
         * @param fin 是否为流末尾
         * @return 协议处理是否成功（失败即连接错误，应断开）
         */
        [[nodiscard]] auto feed(std::int64_t stream_id, std::span<const std::byte> data, bool fin)
            -> fault::code
        {
            return inner_.feed(stream_id, data, fin);
        }

        /**
         * @brief 收集待发数据（nghttp3 → QUIC 流）
         * @param out 输出包集合（写回 QUIC 后调用 add_write_offset 告知消费）
         * @return 是否成功
         */
        [[nodiscard]] auto pump_output(memory::vector<out_packet> &out) -> bool
        {
            return inner_.pump_output(out);
        }

        /**
         * @brief 告知 nghttp3 某流已写回字节数
         * @param stream_id 流 ID
         * @param len 已写回字节数
         */
        void add_write_offset(std::int64_t stream_id, std::size_t len)
        {
            inner_.add_write_offset(stream_id, len);
        }

        /**
         * @brief 认证请求头是否已接收完整
         * @return 是否已接收完整
         */
        [[nodiscard]] auto auth_headers_complete() const noexcept -> bool
        {
            return inner_.auth_headers_complete();
        }

        /** @brief 获取认证请求方法（:method） */
        [[nodiscard]] auto method() const noexcept -> std::string_view
        {
            return inner_.method();
        }

        /** @brief 获取认证请求路径（:path） */
        [[nodiscard]] auto path() const noexcept -> std::string_view
        {
            return inner_.path();
        }

        /** @brief 获取认证凭据（Hysteria-Auth 头） */
        [[nodiscard]] auto auth() const noexcept -> std::string_view
        {
            return inner_.auth();
        }

        /** @brief 获取客户端声明的接收速率（Hysteria-CC-RX 头） */
        [[nodiscard]] auto rx() const noexcept -> std::uint64_t
        {
            return inner_.rx();
        }

        /**
         * @brief 认证请求所在流 ID
         * @return 认证请求流 ID
         */
        [[nodiscard]] auto auth_stream_id() const noexcept -> std::int64_t
        {
            return inner_.auth_stream_id();
        }

        /**
         * @brief 执行认证回调判定
         * @return 通过返回 true；未配置回调默认放行
         * @note 需在 auth_headers_complete() 为 true 后调用
         */
        [[nodiscard]] auto check_auth() const -> bool
        {
            if (!options_.authenticate)
            {
                return true;
            }
            return options_.authenticate(method(), path(), auth());
        }

        /**
         * @brief 提交认证成功响应（:status 233 + Hysteria 头）
         * @return 是否成功（响应字节随下次 pump_output 输出）
         */
        [[nodiscard]] auto submit_auth_response() -> fault::code
        {
            return inner_.submit_auth_response();
        }

        /**
         * @brief 释放 nghttp3 连接状态
         */
        void close()
        {
            inner_.close();
        }

        /**
         * @brief 获取构造选项
         * @return 构造选项只读引用
         */
        [[nodiscard]] auto options() const noexcept -> const server_options &
        {
            return options_;
        }

        /**
         * @brief 获取底层 nghttp3 连接指针
         * @return nghttp3_conn* 原生连接指针
         */
        [[nodiscard]] auto native() const noexcept -> nghttp3_conn *
        {
            return inner_.native();
        }

    private:
        server_options options_; ///< 构造选项
        preview::http3::auth_server inner_; ///< 后端实现（nghttp3 接线）
    };

    /// 服务端共享指针
    using shared_server = std::shared_ptr<server>;

    /**
     * @brief 创建 HTTP/3 服务端
     * @param options 构造选项
     * @return 服务端共享指针
     * @details 内部包装 hysteria2::h3::auth_server；mr 为 nullptr 时
     * 自动回退到当前默认内存资源。
     */
    [[nodiscard]] inline auto make_server(const server_options &options) -> shared_server
    {
        return std::make_shared<server>(options);
    }

} // namespace preview::http3
