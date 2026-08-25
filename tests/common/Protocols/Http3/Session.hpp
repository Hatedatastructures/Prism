/**
 * @file Session.hpp
 * @brief Hysteria2 HTTP/3 认证会话（nghttp3 服务端封装）
 * @details 基于 nghttp3（ngtcp2 官方 HTTP/3 帧层 + QPACK 完整实现）封装
 *          服务端认证状态机：
 *          1. 创建 nghttp3 服务端连接 + 服务器控制流/QPACK 流（SETTINGS）
 *          2. 流数据喂入 nghttp3_conn_read_stream2，回调收集认证头字段
 *          3. 认证判定后提交响应（:status 233 + Hysteria 头）
 *          4. writev_stream 收集待发字节由外部写回 QUIC 流
 *          与 quic-go（mihomo 客户端）完整 HTTP/3 栈字节级兼容。
 */

#pragma once

#include <common/Core/ByteSpan.hpp>
#include <common/Core/Diagnose/Log.hpp>

#include <common/Core/Fault/Code.hpp>
#include <common/Core/Memory/Container.hpp>

#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string_view>

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>

namespace Preview::Http3 {

    /**
     * @struct OutPacket
     * @brief nghttp3 输出包（目标 QUIC 流 + 待发字节）
     */
    struct OutPacket
    {
        std::int64_t StreamId{0};      ///< 目标 QUIC 流
        std::vector<std::byte> Data; ///< 待发字节
        explicit OutPacket(Preview::Memory::ResourcePointer mr) : Data(mr)
        {
        }
    };

    /**
     * @class AuthServer
     * @brief Hysteria2 HTTP/3 认证服务端会话
     * @details 单条 QUIC 连接一个实例；所有 nghttp3 调用必须在同一线程
     *          （quic_gateway 的 io_context 线程）串行执行。
     */
    class AuthServer : public std::enable_shared_from_this<AuthServer>
    {
    public:
        /**
         * @brief 构造函数
         * @param mr 内存资源
         */
        explicit AuthServer(Preview::Memory::ResourcePointer mr);

        /**
         * @brief 析构函数，释放 nghttp3 连接状态
         */
        ~AuthServer() noexcept;

        AuthServer(const AuthServer &) = delete;
        AuthServer &operator=(const AuthServer &) = delete;

        /**
         * @brief 初始化：创建 nghttp3 服务端连接 + 服务器控制流/QPACK 流
         * @param open_uni_stream QUIC 层开单向流回调（失败返回 -1）
         * @return 是否成功
         */
        [[nodiscard]] auto Init(std::function<std::int64_t()> open_uni_stream) -> bool;

        /**
         * @brief 喂入流数据（QUIC 流 → nghttp3）
         * @param StreamId 流 ID
         * @param Data 明文数据
         * @param fin 是否为流末尾
         * @return 协议处理是否成功（失败即连接错误，应断开）
         */
        [[nodiscard]] auto Feed(std::int64_t StreamId, std::span<const std::byte> Data, bool fin)
            -> Fault::Code;

        /**
         * @brief 收集待发数据（nghttp3 → QUIC 流）
         * @param out 输出包集合（写回 QUIC 后调用 AddWriteOffset 告知消费）
         * @return 是否成功
         */
        [[nodiscard]] auto PumpOutput(std::vector<OutPacket> &out) -> bool;

        /**
         * @brief 告知 nghttp3 某流已写回字节数（writev_stream 输出消费确认）
         * @param StreamId 流 ID
         * @param len 已写回字节数
         */
        void AddWriteOffset(std::int64_t StreamId, std::size_t len);

        /**
         * @brief 认证请求头是否已接收完整（end_headers 已触发）
         * @return 是否已接收完整
         */
        [[nodiscard]] auto AuthHeadersComplete() const noexcept -> bool;

        /** @brief 获取认证请求方法（:Method） */
        [[nodiscard]] auto Method() const noexcept -> std::string_view;
        /** @brief 获取认证请求路径（:Path） */
        [[nodiscard]] auto Path() const noexcept -> std::string_view;
        /** @brief 获取认证凭据（Hysteria-Auth 头） */
        [[nodiscard]] auto Auth() const noexcept -> std::string_view;
        /** @brief 获取客户端声明的接收速率（Hysteria-CC-RX 头） */
        [[nodiscard]] auto Rx() const noexcept -> std::uint64_t;

        /**
         * @brief 认证请求所在流 ID（首个出现 HEADERS 的 bidi 流）
         * @return 认证请求流 ID
         */
        [[nodiscard]] auto AuthStreamId() const noexcept -> std::int64_t;

        /**
         * @brief 提交认证成功响应（:status 233 + Hysteria-UDP/CC-RX/Padding）
         * @return 是否成功（响应字节随下次 PumpOutput 输出）
         */
        [[nodiscard]] auto SubmitAuthResponse() -> Fault::Code;

        /**
         * @brief 释放 nghttp3 连接状态
         */
        void Close();

        /**
         * @brief 获取底层 nghttp3 连接指针
         * @return nghttp3_conn* 原生连接指针
         */
        [[nodiscard]] auto Native() const noexcept -> nghttp3_conn *
        {
            return conn_;
        }

    private:
        /** @brief nghttp3 回调：流开始接收头字段 */
        static auto CbBeginHeaders(nghttp3_conn *Conn, int64_t StreamId, void *user_data,
                                     void *stream_user_data) -> int;
        /** @brief nghttp3 回调：接收单个头字段 */
        static auto CbRecvHeader(nghttp3_conn *Conn, int64_t StreamId, int32_t token, nghttp3_rcbuf *Name,
                                   nghttp3_rcbuf *value, uint8_t Flags, void *user_data,
                                   void *stream_user_data) -> int;
        /** @brief nghttp3 回调：头字段接收完毕（end_headers） */
        static auto CbEndHeaders(nghttp3_conn *Conn, int64_t StreamId, int fin, void *user_data,
                                   void *stream_user_data) -> int;
        /** @brief nghttp3 回调：接收请求体数据 */
        static auto CbRecvData(nghttp3_conn *Conn, int64_t StreamId, const uint8_t *Data, size_t datalen,
                                 void *user_data, void *stream_user_data) -> int;
        /** @brief nghttp3 回调：对端停止发送 */
        static auto CbStopSending(nghttp3_conn *Conn, int64_t StreamId, uint64_t app_error_code,
                                    void *user_data, void *stream_user_data) -> int;
        /** @brief nghttp3 回调：流结束（fin） */
        static auto CbEndStream(nghttp3_conn *Conn, int64_t StreamId, void *user_data,
                                  void *stream_user_data) -> int;
        /** @brief nghttp3 随机数回调（密钥材料生成） */
        static void CbRand(uint8_t *dest, size_t destlen);

        /**
         * 当前微秒时间戳（ngtcp2/nghttp3 共用）
         */
        [[nodiscard]] static auto NowTstamp() -> std::uint64_t;

        nghttp3_conn *conn_{nullptr};   ///< nghttp3 连接状态
        Preview::Memory::ResourcePointer mr_{}; ///< 内存资源
        std::int64_t CtrlStream_{-1};  ///< 服务器控制流
        std::int64_t EncStream_{-1};   ///< 服务器 QPACK encoder 流
        std::int64_t DecStream_{-1};   ///< 服务器 QPACK decoder 流
        std::int64_t AuthStream_{-1};  ///< 认证请求流
        bool HeadersDone_{false};      ///< 认证头接收完整
        std::string method_;         ///< :Method
        std::string path_;           ///< :Path
        std::string auth_;           ///< Hysteria-Auth 头
        std::uint64_t rx_{0};           ///< Hysteria-CC-RX 头
    };



    namespace
    {
        /**
         * @brief 从 rcbuf 取字节视图
         * @param rc nghttp3 接收缓冲区
         * @return 缓冲区字节视图
         */
        [[nodiscard]] auto RcbufView(nghttp3_rcbuf *rc) -> std::string_view
        {
            const auto buf = nghttp3_rcbuf_get_buf(rc);
            return AsStrView(std::span<const std::uint8_t>(buf.base, buf.len));
        }
    } // namespace

    inline AuthServer::AuthServer(const Preview::Memory::ResourcePointer mr) : mr_(mr), method_(mr), path_(mr), auth_(mr)
    {
    }

    inline AuthServer::~AuthServer() noexcept
    {
        Close();
    }

    inline auto AuthServer::NowTstamp() -> std::uint64_t
    {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                              std::chrono::steady_clock::now().time_since_epoch())
                                              .count());
    }

    inline auto AuthServer::Init(std::function<std::int64_t()> open_uni_stream) -> bool
    {
        if (conn_)
        {
            return true;
        }

        nghttp3_callbacks callbacks{};
        callbacks.begin_headers = CbBeginHeaders;
        callbacks.recv_header = CbRecvHeader;
        callbacks.end_headers = CbEndHeaders;
        callbacks.recv_data = CbRecvData;
        callbacks.stop_sending = CbStopSending;
        callbacks.end_stream = CbEndStream;
        callbacks.rand = CbRand;

        nghttp3_settings settings{};
        nghttp3_settings_default_versioned(NGHTTP3_SETTINGS_VERSION, &settings);

        const auto rv = nghttp3_conn_server_new_versioned(&conn_, NGHTTP3_CALLBACKS_VERSION, &callbacks,
                                                          NGHTTP3_SETTINGS_VERSION, &settings,
                                                          nghttp3_mem_default(), this);
        if (rv != 0)
        {
            conn_ = nullptr;
            Diagnose::Warn("hysteria2: nghttp3_conn_server_new Failed: {}", nghttp3_strerror(rv));
            return false;
        }

        // 服务器控制流（SETTINGS）+ QPACK encoder/decoder 流
        CtrlStream_ = open_uni_stream();
        EncStream_ = open_uni_stream();
        DecStream_ = open_uni_stream();
        if (CtrlStream_ < 0 || EncStream_ < 0 || DecStream_ < 0)
        {
            Close();
            Diagnose::Warn("hysteria2: cannot Open h3 control streams");
            return false;
        }

        if (nghttp3_conn_bind_control_stream(conn_, CtrlStream_) != 0 ||
            nghttp3_conn_bind_qpack_streams(conn_, EncStream_, DecStream_) != 0)
        {
            Close();
            Diagnose::Warn("hysteria2: cannot Bind h3 control streams");
            return false;
        }
        return true;
    }

    inline auto AuthServer::Feed(const std::int64_t StreamId, std::span<const std::byte> Data, const bool fin)
        -> Fault::Code
    {
        if (!conn_)
        {
            return Fault::Code::protocol_error;
        }

        int FinFlag = 0;
        if (fin)
        {
            FinFlag = 1;
        }
        const auto rc =
            nghttp3_conn_read_stream2(conn_, StreamId, AsU8(Data).data(), Data.size(), FinFlag,
                                      NowTstamp());
        if (rc < 0)
        {
            Diagnose::Warn("hysteria2: nghttp3 read_stream Failed: {}",
                           nghttp3_strerror(static_cast<int>(rc)));
            return Fault::Code::protocol_error;
        }
        return Fault::Code::success;
    }

    inline auto AuthServer::PumpOutput(std::vector<OutPacket> &out) -> bool
    {
        if (!conn_)
        {
            return false;
        }

        std::array<nghttp3_vec, 16> vecs{};
        std::array<std::array<std::byte, 4096>, 16> bufs{};

        for (;;)
        {
            std::int64_t StreamId = -1;
            int fin = 0;
            for (std::size_t i = 0; i < vecs.size(); ++i)
            {
                vecs[i].base = AsU8(std::span(bufs[i])).data();
                vecs[i].len = bufs[i].size();
            }

            nghttp3_ssize sveccnt =
                nghttp3_conn_writev_stream(conn_, &StreamId, &fin, vecs.data(), vecs.size());
            if (sveccnt < 0)
            {
                Diagnose::Warn("hysteria2: nghttp3 writev_stream Failed: {}",
                               nghttp3_strerror(static_cast<int>(sveccnt)));
                return false;
            }
            if (sveccnt == 0)
            {
                break;
            }

            // 输出字节复制到 out 缓冲（应用保证写回 QUIC），立即告知 nghttp3 消费，
            // 否则下次 writev_stream 返回相同数据导致死循环
            OutPacket pkt(mr_);
            pkt.StreamId = StreamId;
            for (nghttp3_ssize i = 0; i < sveccnt; ++i)
            {
                const auto Bytes = AsBytes(std::span<const std::uint8_t>(vecs[i].base, vecs[i].len));
                pkt.Data.insert(pkt.Data.end(), Bytes.begin(), Bytes.end());
            }
            const auto nwritten = pkt.Data.size();
            out.push_back(std::move(pkt));
            nghttp3_conn_add_write_offset(conn_, StreamId, nwritten);

            if (fin)
            {
                nghttp3_conn_shutdown_stream_write(conn_, StreamId);
            }
        }
        return true;
    }

    inline void AuthServer::AddWriteOffset(const std::int64_t StreamId, const std::size_t len)
    {
        if (conn_ && len > 0)
        {
            nghttp3_conn_add_write_offset(conn_, StreamId, len);
        }
    }

    inline auto AuthServer::AuthHeadersComplete() const noexcept -> bool
    {
        return HeadersDone_;
    }

    inline auto AuthServer::Method() const noexcept -> std::string_view
    {
        return std::string_view(method_.data(), method_.size());
    }

    inline auto AuthServer::Path() const noexcept -> std::string_view
    {
        return std::string_view(path_.data(), path_.size());
    }

    inline auto AuthServer::Auth() const noexcept -> std::string_view
    {
        return std::string_view(auth_.data(), auth_.size());
    }

    inline auto AuthServer::Rx() const noexcept -> std::uint64_t
    {
        return rx_;
    }

    inline auto AuthServer::AuthStreamId() const noexcept -> std::int64_t
    {
        return AuthStream_;
    }

    inline auto AuthServer::SubmitAuthResponse() -> Fault::Code
    {
        if (!conn_ || AuthStream_ < 0)
        {
            return Fault::Code::protocol_error;
        }

        std::array<nghttp3_nv, 4> nva{};
        std::size_t n = 0;
        nva[n++] = nghttp3_nv{reinterpret_cast<const uint8_t *>(":status"),
                              reinterpret_cast<const uint8_t *>("233"), 7, 3, NGHTTP3_NV_FLAG_NONE};
        nva[n++] = nghttp3_nv{reinterpret_cast<const uint8_t *>("hysteria-udp"),
                              reinterpret_cast<const uint8_t *>("true"), 12, 4, NGHTTP3_NV_FLAG_NONE};
        nva[n++] = nghttp3_nv{reinterpret_cast<const uint8_t *>("hysteria-cc-Rx"),
                              reinterpret_cast<const uint8_t *>("0"), 13, 1, NGHTTP3_NV_FLAG_NONE};
        nva[n++] = nghttp3_nv{reinterpret_cast<const uint8_t *>("hysteria-padding"),
                              reinterpret_cast<const uint8_t *>("0"), 15, 1, NGHTTP3_NV_FLAG_NONE};

        const auto rv = nghttp3_conn_submit_response(conn_, AuthStream_, nva.data(), n, nullptr);
        if (rv != 0)
        {
            Diagnose::Warn("hysteria2: nghttp3 submit_response Failed: {}", nghttp3_strerror(rv));
            return Fault::Code::protocol_error;
        }
        return Fault::Code::success;
    }

    inline void AuthServer::Close()
    {
        if (conn_)
        {
            nghttp3_conn_del(conn_);
            conn_ = nullptr;
        }
    }

    inline auto AuthServer::CbBeginHeaders(nghttp3_conn *Conn, const int64_t StreamId, void *user_data,
                                  void *stream_user_data) -> int
    {
        (void)Conn;
        (void)stream_user_data;
        auto *self = static_cast<AuthServer *>(user_data);
        if (self->AuthStream_ < 0)
        {
            self->AuthStream_ = StreamId;
        }
        return 0;
    }

    inline auto AuthServer::CbRecvHeader(nghttp3_conn *Conn, const int64_t StreamId, const int32_t token,
                                nghttp3_rcbuf *Name, nghttp3_rcbuf *value, const uint8_t Flags,
                                void *user_data, void *stream_user_data) -> int
    {
        (void)Conn;
        (void)Flags;
        (void)stream_user_data;
        auto *self = static_cast<AuthServer *>(user_data);
        if (self->AuthStream_ < 0 || StreamId != self->AuthStream_)
        {
            return 0;
        }

        const auto v = RcbufView(value);
        switch (token)
        {
        case NGHTTP3_QPACK_TOKEN__METHOD: self->method_.assign(v.data(), v.size()); return 0;
        case NGHTTP3_QPACK_TOKEN__PATH: self->path_.assign(v.data(), v.size()); return 0;
        default: break;
        }

        const auto nm = RcbufView(Name);
        if (nm == "hysteria-Auth")
        {
            self->auth_.assign(v.data(), v.size());
        }
        else if (nm == "hysteria-cc-Rx")
        {
            std::from_chars(v.data(), v.data() + v.size(), self->rx_);
        }
        return 0;
    }

    inline auto AuthServer::CbEndHeaders(nghttp3_conn *Conn, const int64_t StreamId, const int fin, void *user_data,
                                void *stream_user_data) -> int
    {
        (void)Conn;
        (void)fin;
        (void)stream_user_data;
        auto *self = static_cast<AuthServer *>(user_data);
        if (StreamId == self->AuthStream_)
        {
            self->HeadersDone_ = true;
        }
        return 0;
    }

    inline auto AuthServer::CbRecvData(nghttp3_conn *Conn, const int64_t StreamId, const uint8_t *Data,
                              const size_t datalen, void *user_data, void *stream_user_data) -> int
    {
        (void)Conn;
        (void)StreamId;
        (void)Data;
        (void)datalen;
        (void)user_data;
        (void)stream_user_data;
        return 0;
    }

    inline auto AuthServer::CbStopSending(nghttp3_conn *Conn, const int64_t StreamId, const uint64_t app_error_code,
                                 void *user_data, void *stream_user_data) -> int
    {
        (void)Conn;
        (void)StreamId;
        (void)app_error_code;
        (void)user_data;
        (void)stream_user_data;
        return 0;
    }

    inline auto AuthServer::CbEndStream(nghttp3_conn *Conn, const int64_t StreamId, void *user_data,
                               void *stream_user_data) -> int
    {
        (void)Conn;
        (void)StreamId;
        (void)user_data;
        (void)stream_user_data;
        return 0;
    }

    inline void AuthServer::CbRand(uint8_t *dest, const size_t destlen)
    {
        for (std::size_t i = 0; i < destlen; ++i)
        {
            dest[i] = static_cast<std::uint8_t>(std::rand());
        }
    }


} // namespace Preview::Http3
