/**
 * @file Server.hpp
 * @brief HTTP/3 服务端独立入口（Preview::Http3 通用封装）
 * @details 从 core/http3/Session.hpp 的 Hysteria2::h3::AuthServer 提炼
 * 通用服务端入口：统一命名空间 Preview::Http3，以 ServerOptions
 * 收敛构造参数（内存资源 / 认证回调 / 数据回调），并提供
 * MakeServer 工厂。内部薄封装 Hysteria2::h3::AuthServer，不重复
 * 实现 nghttp3 接线逻辑（Session.hpp 已字节级兼容 quic-go）。
 * @note 认证数据路径：Feed() 喂入 nghttp3 → AuthHeadersComplete()
 *       就绪 → CheckAuth() 走认证回调 → SubmitAuthResponse()。
 *       OnData 回调为预留接口，当前后端丢弃 DATA 载荷
 *       （仅认证场景），接入完整数据路径后触发。
 * @note 所有 nghttp3 调用必须在同一 io_context 线程串行执行。
 */

#pragma once

#include <common/Protocols/Http3/Session.hpp>

#include <common/Core/Fault/Code.hpp>
#include <common/Core/Memory/Container.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string_view>

namespace Preview::Http3
{

    /**
     * @struct ServerOptions
     * @brief HTTP/3 服务端构造选项
     * @details 统一服务端配置入口：内存资源 + 认证判定回调 +
     * 数据回调。认证回调返回 true 视为通过，空回调默认放行。
     */
    struct ServerOptions
    {
        Preview::Memory::ResourcePointer mr{nullptr}; ///< 内存资源（nullptr = 当前默认资源）
        /**
         * @brief 认证回调
         * @param Method 请求方法（:Method）
         * @param Path 请求路径（:Path）
         * @param Auth 认证凭据（Hysteria-Auth 头）
         * @return 通过返回 true
         */
        std::function<bool(std::string_view Method, std::string_view Path, std::string_view Auth)>
            authenticate;
        /**
         * @brief 数据回调（预留，认证阶段不触发）
         * @param StreamId 流 ID
         * @param Data 载荷
         * @param fin 流是否结束
         */
        std::function<void(std::int64_t StreamId, std::span<const std::byte> Data, bool fin)> OnData;
    };

    /// nghttp3 输出包（目标 QUIC 流 + 待发字节，对齐后端类型）
    using OutPacket = Preview::Http3::OutPacket;

    /**
     * @class Server
     * @brief HTTP/3 服务端通用入口
     * @details 薄封装 Hysteria2::h3::AuthServer：持有构造选项，
     * 对外暴露同一套 Feed / PumpOutput / 认证查询接口，
     * 并追加 CheckAuth()（走 Options.authenticate）与
     * Options() 访问器。其余行为与后端完全一致。
     */
    class Server : public std::enable_shared_from_this<Server>
    {
    public:
        /**
         * @brief 构造函数
         * @param Options 构造选项（内部补齐 mr 默认值）
         */
        explicit Server(ServerOptions Options)
            : Options_(std::move(Options)),
              Inner_([&]() -> Preview::Memory::ResourcePointer {
                  if (Options_.mr)
                  {
                      return Options_.mr;
                  }
                  return Preview::Memory::CurrentResource();
              }())
        {
        }

        Server(const Server &) = delete;
        auto operator=(const Server &) -> Server & = delete;

        /**
         * @brief 初始化：创建 nghttp3 服务端连接 + 控制流/QPACK 流
         * @param OpenUniStream QUIC 层开单向流回调（失败返回 -1）
         * @return 是否成功
         */
        [[nodiscard]] auto Init(std::function<std::int64_t()> OpenUniStream) -> bool
        {
            return Inner_.Init(std::move(OpenUniStream));
        }

        /**
         * @brief 喂入流数据（QUIC 流 → nghttp3）
         * @param StreamId 流 ID
         * @param Data 明文数据
         * @param fin 是否为流末尾
         * @return 协议处理是否成功（失败即连接错误，应断开）
         */
        [[nodiscard]] auto Feed(std::int64_t StreamId, std::span<const std::byte> Data, bool fin)
            -> Fault::Code
        {
            return Inner_.Feed(StreamId, Data, fin);
        }

        /**
         * @brief 收集待发数据（nghttp3 → QUIC 流）
         * @param out 输出包集合（PumpOutput 内部已消费写偏移，直接写回 QUIC）
         * @return 是否成功
         */
        [[nodiscard]] auto PumpOutput(std::vector<OutPacket> &out) -> bool
        {
            return Inner_.PumpOutput(out);
        }

        /**
         * @brief 告知 nghttp3 某流已写回字节数
         * @param StreamId 流 ID
         * @param len 已写回字节数
         */
        void AddWriteOffset(std::int64_t StreamId, std::size_t len)
        {
            Inner_.AddWriteOffset(StreamId, len);
        }

        /**
         * @brief 认证请求头是否已接收完整
         * @return 是否已接收完整
         */
        [[nodiscard]] auto AuthHeadersComplete() const noexcept -> bool
        {
            return Inner_.AuthHeadersComplete();
        }

        /** @brief 获取认证请求方法（:Method） */
        [[nodiscard]] auto Method() const noexcept -> std::string_view
        {
            return Inner_.Method();
        }

        /** @brief 获取认证请求路径（:Path） */
        [[nodiscard]] auto Path() const noexcept -> std::string_view
        {
            return Inner_.Path();
        }

        /** @brief 获取认证凭据（Hysteria-Auth 头） */
        [[nodiscard]] auto Auth() const noexcept -> std::string_view
        {
            return Inner_.Auth();
        }

        /** @brief 获取客户端声明的接收速率（Hysteria-CC-RX 头） */
        [[nodiscard]] auto Rx() const noexcept -> std::uint64_t
        {
            return Inner_.Rx();
        }

        /**
         * @brief 认证请求所在流 ID
         * @return 认证请求流 ID
         */
        [[nodiscard]] auto AuthStreamId() const noexcept -> std::int64_t
        {
            return Inner_.AuthStreamId();
        }

        /**
         * @brief 执行认证回调判定
         * @return 通过返回 true；未配置回调默认放行
         * @note 需在 AuthHeadersComplete() 为 true 后调用
         */
        [[nodiscard]] auto CheckAuth() const -> bool
        {
            if (!Options_.authenticate)
            {
                return true;
            }
            return Options_.authenticate(Method(), Path(), Auth());
        }

        /**
         * @brief 提交认证成功响应（:status 233 + Hysteria 头）
         * @return 是否成功（响应字节随下次 PumpOutput 输出）
         */
        [[nodiscard]] auto SubmitAuthResponse() -> Fault::Code
        {
            return Inner_.SubmitAuthResponse();
        }

        /**
         * @brief 释放 nghttp3 连接状态
         */
        void Close()
        {
            Inner_.Close();
        }

        /**
         * @brief 获取构造选项
         * @return 构造选项只读引用
         */
        [[nodiscard]] auto Options() const noexcept -> const ServerOptions &
        {
            return Options_;
        }

        /**
         * @brief 获取底层 nghttp3 连接指针
         * @return nghttp3_conn* 原生连接指针
         */
        [[nodiscard]] auto Native() const noexcept -> nghttp3_conn *
        {
            return Inner_.Native();
        }

    private:
        ServerOptions Options_; ///< 构造选项
        Preview::Http3::AuthServer Inner_; ///< 后端实现（nghttp3 接线）
    };

    /// 服务端共享指针
    using SharedServer = std::shared_ptr<Server>;

    /**
     * @brief 创建 HTTP/3 服务端
     * @param Options 构造选项
     * @return 服务端共享指针
     * @details 内部包装 Hysteria2::h3::AuthServer；mr 为 nullptr 时
     * 自动回退到当前默认内存资源。
     */
    [[nodiscard]] inline auto MakeServer(const ServerOptions &Options) -> SharedServer
    {
        return std::make_shared<Server>(Options);
    }

} // namespace Preview::Http3
