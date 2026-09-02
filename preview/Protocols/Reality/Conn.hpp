/**
 * @file Conn.hpp
 * @brief Reality 会话连接对象（Transmission 装饰器）
 * @details 将底层传输包装为 Reality 连接（对齐 mihomo
 * component/tls/reality.go）：
 * 1. WriteHandshake：客户端生成 X25519 临时密钥对 → 派生 AuthKey
 *    → Seal SessionId（短 ID 内嵌）
 * 2. ReadHandshake：服务端 X25519 共享密钥 → 派生 AuthKey
 *    → Open SessionId 校验
 * 3. 数据面：TLS 1.3 记录透传（测试库简化）
 * @note 与 reality.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Reality/Codec.hpp>
#include <preview/Protocols/Reality/Types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace Preview::Reality
{

    /// 握手参数（ClientRandom + hello + ShortId）
    struct HandshakeParams
    {
        std::span<const std::uint8_t> ClientRandom; ///< 客户端随机数（40 字节）
        std::span<const std::uint8_t> hello;         ///< ClientHello 原始消息（AAD）
        std::array<std::uint8_t, MaxShortIdLen> ShortId{}; ///< 短 ID（8 字节）
    };

    /**
     * @class Conn
     * @brief Reality 会话连接（Transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后数据面透传。
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
         * @param private_key_st 服务端/客户端 X25519 私钥（32 字节）
         */
        explicit Conn(SharedTransmission upstream, std::array<std::uint8_t, KeyLen> private_key_st)
            : NextLayer_(std::move(upstream)), private_key_st(private_key_st)
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return NextLayer_->Executor();
        }

        /**
         * @brief 客户端握手：派生 AuthKey + Seal SessionId 并发送
         * @param PeerPublicKey 服务端公钥（32 字节）
         * @param params 握手参数（ClientRandom + hello + ShortId）
         * @return 错误码
         */
        [[nodiscard]] auto WriteHandshake(std::span<const std::uint8_t> PeerPublicKey,
                                           const HandshakeParams &params)
        -> net::awaitable<Error>
        {
            const auto &ClientRandom = params.ClientRandom;
            const auto &hello = params.hello;
            const auto &ShortId = params.ShortId;
            // X25519 共享密钥
            std::array<std::uint8_t, KeyLen> shared{};
            if (X25519Shared(private_key_st, PeerPublicKey, shared))
                co_return Error::KdfError;
            SharedSecret_ = shared;

            // 派生 AuthKey
            std::array<std::uint8_t, KeyLen> AuthKey{};
            if (DeriveAuthKey(shared, ClientRandom, AuthKey))
                co_return Error::KdfError;
            AuthKey_ = AuthKey;

            // 构造明文 SessionId：version(1) + random(7) + ShortId(8)
            std::array<std::uint8_t, 16> plain{};
            plain[0] = 0x01;
            std::copy(ShortId.begin(), ShortId.end(), plain.begin() + 8);

            // Seal 并发送
            std::array<std::uint8_t, SessionIdAuthLen> sealed{};
            if (SealSessionId(SessionIdSealInput{AuthKey, ClientRandom, plain, hello},
                                sealed))
                co_return Error::KdfError;
            SessionId_ = sealed;
            if (co_await SendBytes(sealed))
            {
                std::fprintf(stderr, "[reality] send sealed sid Failed\n");
                co_return Error::IoError;
            }
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 服务端握手：读取 SessionId → 派生 AuthKey → 校验
         * @param PeerPublicKey 客户端公钥（32 字节）
         * @param params 握手参数（ClientRandom + hello）
         * @param ShortId 输出短 ID（8 字节）
         * @return 错误码；bad_auth = 解密失败或版本不匹配
         */
        [[nodiscard]] auto ReadHandshake(std::span<const std::uint8_t> PeerPublicKey,
                                          const HandshakeParams &params,
                                          std::array<std::uint8_t, MaxShortIdLen> &ShortId)
        -> net::awaitable<Error>
        {
            const auto &ClientRandom = params.ClientRandom;
            const auto &hello = params.hello;
            // 读取客户端 SessionId 密文（32 字节）
            std::array<std::uint8_t, SessionIdAuthLen> SessionId{};
            if (co_await ReadExact(std::span<std::uint8_t>(SessionId)))
                co_return Error::UnexpectedEof;

            std::array<std::uint8_t, KeyLen> shared{};
            if (X25519Shared(private_key_st, PeerPublicKey, shared))
                co_return Error::KdfError;
            SharedSecret_ = shared;

            std::array<std::uint8_t, KeyLen> AuthKey{};
            if (DeriveAuthKey(shared, ClientRandom, AuthKey))
                co_return Error::KdfError;
            AuthKey_ = AuthKey;

            std::array<std::uint8_t, 16> plain{};
            if (OpenSessionId(SessionIdOpenInput{AuthKey, ClientRandom, SessionId, hello},
                                plain))
                co_return Error::BadAuth;
            if (plain[0] != 0x01)
                co_return Error::BadAuth;
            std::copy(plain.begin() + 8, plain.begin() + 16, ShortId.begin());
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 透传读取（数据面原样）
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
        -> net::awaitable<std::size_t> override
        {
            if (!Handshaken_)
            {
                ec = make_error_code(Error::NotOpen);
                co_return 0;
            }
            co_return co_await NextLayer_->async_read_some(Buffer, ec);
        }

        /**
         * @brief 透传写入（数据面原样）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer,
                                            std::error_code &ec)
        -> net::awaitable<std::size_t> override
        {
            if (!Handshaken_)
            {
                ec = make_error_code(Error::NotOpen);
                co_return 0;
            }
            co_return co_await NextLayer_->async_write_some(Buffer, ec);
        }

        /**
         * @brief 关闭底层传输
         */
        void Close() override
        {
            NextLayer_->Close();
        }

        /**
         * @brief 取消挂起操作
         */
        void Cancel() override
        {
            NextLayer_->Cancel();
        }

        /**
         * @brief 获取底层传输（装饰器链导航）
         */
        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto Release() -> SharedTransmission override
        {
            return std::move(NextLayer_);
        }

        /**
         * @brief 获取派生认证密钥（握手后有效）
         */
        [[nodiscard]] auto AuthKey() const -> const std::array<std::uint8_t, KeyLen> &
        {
            return AuthKey_;
        }

        /**
         * @brief 获取共享密钥（握手后有效）
         */
        [[nodiscard]] auto SharedSecret() const -> const std::array<std::uint8_t, KeyLen> &
        {
            return SharedSecret_;
        }

        /**
         * @brief 获取 Seal 后的 SessionId（客户端握手后有效）
         */
        [[nodiscard]] auto SessionId() const -> const std::array<std::uint8_t, SessionIdAuthLen> &
        {
            return SessionId_;
        }

    private:
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
                const auto N = co_await NextLayer_->async_read_some(AsBytes(dst.subspan(Done)), ec);
                if (ec || N == 0)
                    co_return true;
                Done += N;
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
                const auto N = co_await NextLayer_->async_write_some(AsBytes(Data.subspan(Done)), ec);
                if (ec)
                    co_return true;
                Done += N;
            }
            co_return false;
        }

        SharedTransmission NextLayer_;                              ///< 底层传输（独占所有权）
        std::array<std::uint8_t, KeyLen> private_key_st{};             ///< X25519 私钥
        std::array<std::uint8_t, KeyLen> SharedSecret_{};          ///< 共享密钥
        std::array<std::uint8_t, KeyLen> AuthKey_{};               ///< 认证密钥
        std::array<std::uint8_t, SessionIdAuthLen> SessionId_{}; ///< Seal 后的 SessionId
        bool Handshaken_{false};                                      ///< 握手完成标志
    };

    /// 流连接共享指针（默认内存策略）
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Reality
