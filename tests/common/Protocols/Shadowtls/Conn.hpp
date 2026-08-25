/**
 * @file Conn.hpp
 * @brief ShadowTLS v3 会话连接对象（Transmission 装饰器）
 * @details 将底层传输包装为 ShadowTLS v3 连接（对齐 sing v3 客户端）：
 * 1. WriteHandshake：构造 ClientHello 帧（SessionId 内嵌 HMAC 认证码）
 * 2. ReadHandshake：服务端校验 ClientHello SessionId HMAC
 * 3. 握手后数据面透传（帧 HMAC 认证由上层负责，测试库简化透传）
 * @note 与 shadowtls.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <common/Core/ByteSpan.hpp>
#include <common/Core/Error.hpp>
#include <common/Core/Memory/Container.hpp>
#include <common/Core/Memory/Pointer.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Protocols/Shadowtls/Codec.hpp>
#include <common/Protocols/Shadowtls/Types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace Preview::Shadowtls
{

    /**
     * @class Conn
     * @brief ShadowTLS v3 会话连接（Transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后通过
     * Transmission 接口透传数据。
     * @tparam Memory 会话内存策略（默认 8KB Arena；可注入自定义策略）
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Conn : public Preview::Transmission, public std::enable_shared_from_this<Conn<Memory>>
    {
    public:
        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using MemoryType = Memory;

        /**
         * @brief 构造函数
         * @param upstream 底层传输（所有权移交）
         * @param password 认证密码
         */
        explicit Conn(SharedTransmission upstream, std::string password)
            : next_layer_(std::move(upstream)), password_(std::move(password))
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const   
          -> net::any_io_executor override
        {
            return next_layer_->Executor();
        }

        /**
         * @brief 客户端握手：构造并发送带认证 SessionId 的 ClientHello 帧
         * @param ServerRandom 服务端随机数（32 字节，真实 TLS 中由握手生成）
         * @param client_random 客户端随机数（32 字节）
         * @return 错误码
         * @details 构造简化 ClientHello：TLS 记录头(5) + 握手头(4) +
         * version(2) + random(32) + sidLen(1) + SessionId(32)，
         * SessionId 末尾 4 字节为 HMAC 认证码。
         */
        [[nodiscard]] auto WriteHandshake(std::span<const std::uint8_t> ServerRandom,
                                           std::span<const std::uint8_t> client_random)
          -> net::awaitable<Error>
        {
            std::vector<std::uint8_t> hello = BuildClientHello(client_random);

            // 构造 SessionId：前 28 字节固定模式 + 末尾 4 字节 HMAC
            std::array<std::uint8_t, TlsSessionIdSz> SessionId{};
            for (std::size_t i = 0; i < TlsSessionIdSz - HmacSize; ++i)
                SessionId[i] = static_cast<std::uint8_t>(i * 7 + 3);
                  
            const auto HmacHello = std::span<const std::uint8_t>(hello).subspan(TlsHdrsize);
            auto err = GenerateSessionId(SessionIdInput{password_, HmacHello, SessionId});
            if (err != Error::none)
                co_return err;
            std::memcpy(hello.data() + TlsHdrsize + SessionIdStart, SessionId.data(),
                        TlsSessionIdSz);

            if (co_await SendBytes(hello))
                co_return Error::io_error;

            // 保存会话状态
            ServerRandom_.assign(ServerRandom.begin(), ServerRandom.end());
            handshaken_ = true;
            co_return Error::none;
        }

        /**
         * @brief 服务端握手：读取并校验 ClientHello SessionId HMAC
         * @return 错误码
         */
        [[nodiscard]] auto ReadHandshake()
          -> net::awaitable<Error>
        {
            // 完整 hello：TLS 头 + 握手头 + version + random + sidLen + SessionId + 尾部
            constexpr std::size_t HelloLen = TlsHdrsize + SessionIdStart + TlsSessionIdSz + 16;
            std::vector<std::uint8_t> hello(HelloLen);
            if (co_await ReadExact(hello))
                co_return Error::unexpected_eof;
            const auto HelloSpan = AsBytesSpan(hello);
            if (!VerifyClientHello(password_, HelloSpan))
                co_return Error::bad_auth;
            handshaken_ = true;
            co_return Error::none;
        }

        /**
         * @brief 透传读取（握手后数据面为裸流）
         */
        [[nodiscard]] auto AsyncReadSome(std::span<std::byte> Buffer, std::error_code &ec)
          -> net::awaitable<std::size_t> override
        {
            if (!handshaken_)
            {
                ec = make_error_code(Error::not_open);
                co_return 0;
            }
            co_return co_await next_layer_->AsyncReadSome(Buffer, ec);
        }

        /**
         * @brief 透传写入（握手后数据面为裸流）
         */
        [[nodiscard]] auto AsyncWriteSome(std::span<const std::byte> Buffer, std::error_code &ec)
          -> net::awaitable<std::size_t> override
        {
            if (!handshaken_)
            {
                ec = make_error_code(Error::not_open);
                co_return 0;
            }
            co_return co_await next_layer_->AsyncWriteSome(Buffer, ec);
        }

        /**
         * @brief 关闭底层传输
         */
        void Close() override
        {
            next_layer_->Close();
        }

        /**
         * @brief 取消挂起操作
         */
        void Cancel() override
        {
            next_layer_->Cancel();
        }

        /**
         * @brief 获取底层传输（装饰器链导航）
         */
        [[nodiscard]] auto NextLayer() noexcept 
          -> Preview::Transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept 
          -> const Preview::Transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto Release() 
          -> SharedTransmission override
        {
            return std::move(next_layer_);
        }

    private:
        /**
         * @brief 构造简化 ClientHello（无 TLS 头版本的握手数据）
         * @param client_random 32 字节客户端随机数
         * @return 完整 ClientHello（含 TLS 记录头 5 字节）
         */
        [[nodiscard]] auto BuildClientHello(std::span<const std::uint8_t> client_random)
          -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> hello(TlsHdrsize + SessionIdStart + TlsSessionIdSz + 16,
                                             0);
            hello[0] = 0x16; // content_handshake
            hello[TlsHdrsize] = HsTypeClienthello;
            hello[TlsHdrsize + SessionIdStart - 1] = TlsSessionIdSz;
            if (client_random.size() >= TlsRndSize)
            {
                std::memcpy(hello.data() + TlsHdrsize + 1 + 3 + 2, client_random.data(),
                            TlsRndSize);
            }
            return hello;
        }

        /**
         * @brief 精确读取指定字节数
         * @param dst 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> dst)
          -> net::awaitable<bool>
        {
            std::size_t Done = 0;
            while (Done < dst.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->AsyncReadSome(AsBytes(dst.subspan(Done)), ec);
                if (ec || n == 0)
                    co_return true;
                Done += n;
            }
            co_return false;
        }

        /**
         * @brief 发送全部字节
         * @param Data 数据
         * @return true = 失败
         */
        [[nodiscard]] auto SendBytes(std::span<const std::uint8_t> Data) const
          -> net::awaitable<bool>
        {
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->AsyncWriteSome(AsBytes(Data.subspan(Done)), ec);
                if (ec)
                    co_return true;
                Done += n;
            }
            co_return false;
        }

        SharedTransmission next_layer_;      ///< 底层传输（独占所有权）
        std::string password_;                ///< 认证密码
        Memory mem_;                          ///< 会话内存策略（Arena，热路径零释放分配）
        /// 服务端随机数（握手后，Arena 分配）
        typename std::template Buffer<std::uint8_t> ServerRandom_{mem_.Arena()};
        bool handshaken_{false};              ///< 握手完成标志
    };

    /// 流连接共享指针（默认内存策略）
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Shadowtls
