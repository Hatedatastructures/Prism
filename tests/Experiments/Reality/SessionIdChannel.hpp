/**
 * @file SessionIdChannel.hpp
 * @brief 测试实验用 Reality SessionId 通道
 * @details 将底层传输包装为 Reality 连接（对齐 mihomo
 * component/tls/reality.go）：
 * 1. WriteHandshake：实验客户端派生 AuthKey
 *    → Seal SessionId（短 ID 内嵌）
 * 2. ReadHandshake：实验服务端派生 AuthKey
 *    → Open SessionId 校验
 * 3. 数据面：TLS 1.3 记录透传（测试库简化）
 * @note 仅供 Experiments 的 SessionId/record 实验使用，不是完整 TLS carrier
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once
#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Foundation/Utility/Diagnose/Facade.hpp>
#include <Preview/Transport/Detail/IoCompletion.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Reality/Detail/Key.hpp>
#include <Preview/Protocols/Reality/Types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <system_error>
#include <utility>

namespace Preview::Reality::Detail
{

    /// 握手参数（ClientRandom + hello + ShortId）
    struct HandshakeParams
    {
        std::span<const std::uint8_t> ClientRandom; ///< TLS ClientRandom（32 字节）
        std::span<const std::uint8_t> hello;         ///< ClientHello 原始消息（AAD）
        std::array<std::uint8_t, MaxShortIdLen> ShortId{}; ///< 短 ID（8 字节）
    };

    /**
     * @class SessionIdChannel
     * @brief Reality 会话连接（Transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后数据面透传。
     * @tparam Memory 会话内存策略（默认 8KB Arena；可注入自定义策略）
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class SessionIdChannel : public Preview::Transmission
    {
    public:
        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using MemoryType = Memory;

        /**
         * @brief 构造函数
         * @param Upstream 底层传输（所有权移交）
         * @param PrivateKey 服务端/客户端 X25519 私钥（32 字节）
         */
        explicit SessionIdChannel(SharedTransmission Upstream,
                      std::array<std::uint8_t, KeyLen> PrivateKey)
            : Preview::Transmission(Upstream ? Upstream->Executor() : Net::any_io_executor{}),
              NextLayer_(std::move(Upstream)), PrivateKey_(PrivateKey)
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (!NextLayer_)
            {
                return Preview::Transmission::Executor();
            }
            return NextLayer_->Executor();
        }

        /**
         * @brief 客户端握手：派生 AuthKey + Seal SessionId 并发送
         * @param PeerPublicKey 服务端公钥（32 字节）
         * @param Params 握手参数（ClientRandom + hello + ShortId）
         * @return 错误码
         */
        [[nodiscard]] auto WriteHandshake(
            std::span<const std::uint8_t> PeerPublicKey,
            const HandshakeParams &Params) -> Net::awaitable<Error>
        {
            Handshaken_ = false;
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }

            const auto ClientRandom = Params.ClientRandom;
            const auto Hello = Params.hello;
            const auto &ShortId = Params.ShortId;
            // X25519 共享密钥
            std::array<std::uint8_t, KeyLen> Shared{};
            if (X25519Shared(PrivateKey_, PeerPublicKey, Shared))
                co_return Error::KdfError;
            SharedSecret_ = Shared;

            // 派生 AuthKey
            std::array<std::uint8_t, KeyLen> AuthKey{};
            if (DeriveAuthKey(Shared, ClientRandom, AuthKey))
                co_return Error::KdfError;
            AuthKey_ = AuthKey;

            // 构造明文 SessionId：version(1) + random(7) + ShortId(8)
            std::array<std::uint8_t, 16> Plain{};
            Plain[0] = 0x01;
            std::copy(ShortId.begin(), ShortId.end(), Plain.begin() + 8);

            // Seal 并发送
            std::array<std::uint8_t, SessionIdAuthLen> Sealed{};
            if (SealSessionId(SessionIdSealInput{AuthKey, ClientRandom, Plain, Hello},
                              Sealed))
                co_return Error::KdfError;
            SessionId_ = Sealed;
            if (co_await SendBytes(Sealed))
            {
                (void)Preview::Diagnose::Trace("RealitySessionIdWriteFailed");
                co_return Error::IoError;
            }
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 服务端握手：读取 SessionId → 派生 AuthKey → 校验
         * @param PeerPublicKey 客户端公钥（32 字节）
         * @param Params 握手参数（ClientRandom + hello）
         * @param ShortId 输出短 ID（8 字节）
         * @return 错误码；bad_auth = 解密失败或版本不匹配
         */
        [[nodiscard]] auto ReadHandshake(
            std::span<const std::uint8_t> PeerPublicKey,
            const HandshakeParams &Params,
            std::array<std::uint8_t, MaxShortIdLen> &ShortId) -> Net::awaitable<Error>
        {
            Handshaken_ = false;
            ShortId.fill(0);
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }

            const auto ClientRandom = Params.ClientRandom;
            const auto Hello = Params.hello;
            // 读取客户端 SessionId 密文（32 字节）
            std::array<std::uint8_t, SessionIdAuthLen> SessionId{};
            if (co_await ReadExact(SessionId))
                co_return Error::UnexpectedEof;

            std::array<std::uint8_t, KeyLen> Shared{};
            if (X25519Shared(PrivateKey_, PeerPublicKey, Shared))
                co_return Error::KdfError;
            SharedSecret_ = Shared;

            std::array<std::uint8_t, KeyLen> AuthKey{};
            if (DeriveAuthKey(Shared, ClientRandom, AuthKey))
                co_return Error::KdfError;
            AuthKey_ = AuthKey;

            std::array<std::uint8_t, 16> Plain{};
            if (OpenSessionId(SessionIdOpenInput{AuthKey, ClientRandom, SessionId, Hello},
                              Plain))
                co_return Error::BadAuth;
            if (Plain[0] != 0x01)
                co_return Error::BadAuth;
            std::copy(Plain.begin() + 8, Plain.begin() + 16, ShortId.begin());
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 透传读取（数据面原样）
         * @details 未握手或底层已释放时异步交付一次 NotOpen；否则 token 直通底层，
         *          保留底层短读与 EOF 事实，不复制 buffer。
         */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            if (!NextLayer_ || !Handshaken_)
            {
                Preview::Transport::Detail::PostResult(
                    Executor(),
                    std::move(Handler),
                    Preview::IoResult{0, Preview::Fault::FromNative(make_error_code(Error::NotOpen))});
                return;
            }
            NextLayer_->ReadSome(Buffer, std::move(Handler));
        }

        /**
         * @brief 透传写入（数据面原样）
         * @details 未握手或底层已释放时异步交付一次 NotOpen；否则 token 直通底层，
         *          保留底层短写事实。
         */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            if (!NextLayer_ || !Handshaken_)
            {
                Preview::Transport::Detail::PostResult(
                    Executor(),
                    std::move(Handler),
                    Preview::IoResult{0, Preview::Fault::FromNative(make_error_code(Error::NotOpen))});
                return;
            }
            NextLayer_->WriteSome(Buffer, std::move(Handler));
        }

        /**
         * @brief 真实写半关闭转交底层载体；反向读取仍然可用。
         */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Preview::Transport::Detail::PostResult(
                    Executor(),
                    std::move(Handler),
                    Preview::IoResult{0, Preview::Fault::FromNative(make_error_code(Error::NotOpen))});
                return;
            }
            NextLayer_->WriteShutdown(std::move(Handler));
        }

        /**
         * @brief 清除握手状态并交付底层关闭
         * @return 命令接管成功；实际退出由 Activity()->Drain() 另行等待。
         */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Handshaken_ = false;
            if (!NextLayer_)
            {
                return {};
            }
            return NextLayer_->Close();
        }

        /**
         * @brief 可重复取消底层挂起操作
         * @return 命令接管成功只表示取消请求已排入原 executor，不宣称已经关闭。
         */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            if (!NextLayer_)
            {
                return {};
            }
            return NextLayer_->Cancel();
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
            Handshaken_ = false;
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
         * @param Dst 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> Dst) -> Net::awaitable<bool>
        {
            if (!NextLayer_)
            {
                co_return true;
            }

            std::size_t Done = 0;
            while (Done < Dst.size())
            {
                const auto Part = co_await NextLayer_->ReadSome(
                    AsBytes(Dst.subspan(Done)));
                const auto ErrorCode = Preview::Fault::ToNative(Part.Failure);
                const auto N = Part.Bytes;
                if (ErrorCode || N == 0)
                    co_return true;
                if (N > Dst.size() - Done)
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
            -> Net::awaitable<bool>
        {
            if (!NextLayer_)
            {
                co_return true;
            }

            std::size_t Done = 0;
            while (Done < Data.size())
            {
                const auto Part = co_await NextLayer_->WriteSome(
                    AsBytes(Data.subspan(Done)));
                const auto ErrorCode = Preview::Fault::ToNative(Part.Failure);
                const auto N = Part.Bytes;
                if (ErrorCode || N == 0 || N > Data.size() - Done)
                    co_return true;
                Done += N;
            }
            co_return false;
        }

        SharedTransmission NextLayer_; ///< 底层传输（独占所有权）
        std::array<std::uint8_t, KeyLen> PrivateKey_{}; ///< X25519 私钥
        std::array<std::uint8_t, KeyLen> SharedSecret_{}; ///< 共享密钥
        std::array<std::uint8_t, KeyLen> AuthKey_{}; ///< 认证密钥
        std::array<std::uint8_t, SessionIdAuthLen> SessionId_{}; ///< Seal 后的 SessionId
        bool Handshaken_{false}; ///< 握手完成标志
    };

    /// 流连接共享指针（默认内存策略）
    using SharedConn = std::shared_ptr<SessionIdChannel<>>;

    static_assert(Preview::TransmissionLike<SessionIdChannel<>>);

} // namespace Preview::Reality::Detail
