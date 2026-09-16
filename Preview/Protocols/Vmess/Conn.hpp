/**
 * @file Conn.hpp
 * @brief VMess 客户端会话（Transmission 装饰器）
 * @details 客户端视角的完整 VMess（AEAD）实现：
 * 1. 生成随机 IV/Key/验证字节/填充与 AuthID 随机数
 * 2. 构造请求头明文 → SealAuthHeader 密封 → 发送
 *    （命令由 handshake(Target, cmd) 参数化：Tcp/udp/mux）
 * 3. 读取 18B 响应长度块 → 解密确定响应头长度 → 读取响应头密文 →
 *    OpenResponseHeader 校验验证字节回显
 * 4. 派生分块密钥（chunkKey = KDF(requestKey, requestNonce)[:16]）
 * 5. 隧道：async_read_some 解密 chunk，async_write_some 分块加密发送
 * 6. UDP 数据面：目标地址固定来自指令头，chunk 即包边界
 *    （AsyncSendDatagram 一次 Seal 一块，AsyncReceiveDatagram
 *    一次 ReadChunk 一块即一个完整数据报）
 * @note 与 vmess.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Authenticator.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Foundation/Utility/Crypto/Random.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Vmess/Codec.hpp>
#include <Preview/Protocols/Vmess/Types.hpp>

namespace Preview::Vmess
{

    namespace Net = boost::asio;

    /**
     * @class Client
     * @brief VMess 客户端会话
     * @details 将底层传输层包装为 VMess 客户端，持有底层传输的
     * 独占所有权。handshake(Target, cmd) 完成请求头密封发送与响应
     * 校验，成功后通过 Transmission 接口透传（加解密）隧道数据，
     * 或通过 AsyncSendDatagram / AsyncReceiveDatagram 收发
     * UDP 数据报。
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Conn : public Preview::Transmission, public std::enable_shared_from_this<Conn<Memory>>
    {
    public:
        /**
         * @brief 构造函数
         * @param Uuid 客户端 UUID（16 字节）
         * @param Source 可选随机源
         * @details 接管底层传输所有权，调用者不应再使用原指针。
         */
        explicit Conn(std::array<std::uint8_t, 16> Uuid,
                      RandomSource Source = {},
                      const Preview::Authenticator *Auth = nullptr,
                      Preview::SharedAuthenticator AuthOwner = {})
            : Uuid_(Uuid), Random_(std::move(Source)), AuthOwner_(std::move(AuthOwner)), Auth_(Auth)
        {
            if (AuthOwner_)
            {
                Auth_ = AuthOwner_.get();
            }
        }

        /**
         * @brief 获取关联的执行器
         * @return 底层传输的执行器
         * @details 透传底层传输的执行器，供协程调度使用。
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (!NextLayer_)
            {
                return {};
            }
            return NextLayer_->Executor();
        }

        /**
         * @brief 异步读取（解密后明文）
         * @param Buffer 接收缓冲区
         * @param ErrorCode 错误码输出参数
         * @return 实际读取字节数；0 = 流结束（结束块或对端关闭）
         * @details 握手成功后：底层读取一个分块密文 → 解密 → 从内部
         * 明文缓冲拷贝给调用方。
         * @warning 未握手或已结束时返回 0 并置 ErrorCode
         */
        [[nodiscard]] auto async_read_some(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            ErrorCode.clear();
            if (!NextLayer_ || !Handshaken_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            if (Eof_)
            {
                co_return 0;
            }
            while (PlainOff_ >= PlainRx_.size())
            {
                const auto Err = co_await ReadChunk();
                if (Err != Error::None)
                {
                    ErrorCode = make_error_code(Err);
                    co_return 0;
                }
                if (Eof_)
                {
                    co_return 0;
                }
            }
            const auto N = std::min(Buffer.size(), PlainRx_.size() - PlainOff_);
            std::memcpy(Buffer.data(), PlainRx_.data() + PlainOff_, N);
            PlainOff_ += N;
            co_return N;
        }

        /**
         * @brief 异步写入（加密后发送，16KB 分块）
         * @param Buffer 发送缓冲区（明文）
         * @param ErrorCode 错误码输出参数
         * @return 实际写入的明文长度
         * @details VMess AEAD chunk 上限 16KB：超过时按块分片加密发送。
         * @warning 未握手时返回 0 并置 ErrorCode
         */
        [[nodiscard]] auto async_write_some(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            ErrorCode.clear();
            if (!NextLayer_ || !Handshaken_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            if (Buffer.empty())
            {
                co_return 0;
            }
            std::size_t Done = 0;
            // 循环外复用加密缓冲（消除每块堆分配）；16KB+ 走线程局部池（分级分配）
            auto Out = Mem_.template MakeBuffer<std::uint8_t>(MaxChunkLen + ChunkEncryptor::Overhead);
            while (Done < Buffer.size())
            {
                const auto N = std::min(MaxChunkLen, Buffer.size() - Done);
                const auto Enc = Enc_->Seal(AsU8(Buffer.subspan(Done, N)), Out);
                if (Enc == 0)
                {
                    ErrorCode = make_error_code(Error::BadLength);
                    co_return 0;
                }
                if (co_await SendBytes(std::span<const std::uint8_t>(Out.data(), Enc)))
                {
                    ErrorCode = make_error_code(Error::IoError);
                    co_return 0;
                }
                Done += N;
            }
            co_return Buffer.size();
        }

        /**
         * @brief 关闭传输层
         * @details 透传关闭到底层传输，挂起的读写立即返回。
         */
        auto Close() -> void override
        {
            if (NextLayer_)
            {
                NextLayer_->Close();
            }
        }

        /**
         * @brief 取消未完成异步操作
         * @details 透传取消到底层传输，挂起的读立即返回 0。
         */
        auto Cancel() -> void override
        {
            if (NextLayer_)
            {
                NextLayer_->Cancel();
            }
        }

        /**
         * @brief 获取内层传输（装饰器链导航）
         * @return 内层传输指针
         */
        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 获取内层传输（const 版本）
         * @return 内层传输指针
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         * @return 底层传输共享指针（所有权转移给调用者）
         */
        [[nodiscard]] auto Release() -> SharedTransmission override
        {
            return std::move(NextLayer_);
        }
        /**
         * @brief 会话是否有效（已握手且底层存在）
         * @return 有效返回 true
         */
        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return NextLayer_ != nullptr && Handshaken_;
        }

        /**
         * @brief 获取底层传输引用（非拥有）
         * @return 底层传输
         */
        [[nodiscard]] auto Underlying() noexcept -> SharedTransmission
        {
            return NextLayer_;
        }

        /**
         * @brief 获取会话级内存竞技场
         * @return 非拥有资源指针（供握手/解析的临时分配）
         * @note 分配的对象随 Conn 存活，Conn 析构时一次性回收
         */
        [[nodiscard]] auto Arena() noexcept -> Preview::Memory::ResourcePointer
        {
            return Mem_.Arena();
        }

        /**
         * @brief 执行客户端握手
         * @param Target 目标地址
         * @param CommandValue 命令（默认 Tcp；UDP 数据面传 Command::Udp）
         * @return 错误码
         * @details 生成随机参数 → 密封请求头（命令写入指令头）→
         * 发送 → 读取响应校验。
         * @warning 调用前必须确保 NextLayer_ 已建立连接
         */
        [[nodiscard]] auto WriteHandshake(
            SharedTransmission Upstream,
            const Address &Target,
            std::uint8_t CommandValue = static_cast<std::uint8_t>(Command::Tcp))
            -> Net::awaitable<Error>
        {
            NextLayer_ = std::move(Upstream);
            Handshaken_ = false;
            Eof_ = false;
            AuthId_.fill(0);
            AuthLease_.Release();
            AccountId_ = {};
            Identity_.clear();
            Parsed_ = Message{};
            ChunkOptions_ = static_cast<std::uint8_t>(Option::AuthenticatedLength);
            PlainRx_.clear();
            PlainOff_ = 0;
            Enc_.reset();
            Dec_.reset();
            // 1. 生成随机参数
            std::array<std::uint8_t, 16> Iv{};
            std::array<std::uint8_t, 16> Key{};
            std::array<std::uint8_t, 4> AuthRandom{};
            std::array<std::uint8_t, 2> MetadataRandom{};
            if (!FillRandomBytes(std::span<std::uint8_t>(Iv)) ||
                !FillRandomBytes(std::span<std::uint8_t>(Key)) ||
                !FillRandomBytes(std::span<std::uint8_t>(AuthRandom)) ||
                !FillRandomBytes(std::span<std::uint8_t>(MetadataRandom)))
            {
                co_return Error::IoError;
            }
            const auto VersionByte = MetadataRandom[0];
            const auto PaddingLength = static_cast<std::uint8_t>(MetadataRandom[1] % 16);
            const auto TimeSec = std::chrono::duration_cast<std::chrono::seconds>(
                                      std::chrono::system_clock::now().time_since_epoch())
                                      .count();

            // 2. 构造请求头明文并密封
            RequestHeader RequestValue;
            RequestValue.Version = ProtocolVersion;
            RequestValue.Cmd = CommandValue;
            RequestValue.opt = static_cast<std::uint8_t>(Option::ChunkStream) |
                      static_cast<std::uint8_t>(Option::ChunkMasking);
            RequestValue.sec = Security::Aes128Gcm;
            RequestValue.Target = Target;
            const auto Plain = BuildRequestHeader(
                RequestValue,
                RequestMeta{Iv, Key, VersionByte, PaddingLength});
            const auto CmdKey = CmdKeyFromUuid(Uuid_);
            const auto Sealed = SealAuthHeader(
                CmdKey,
                AuthHeaderInput{Plain, TimeSec, AuthRandom},
                Random_);
            const auto AuthId = CreateAuthId(CmdKey, TimeSec, AuthRandom);
            if (Sealed.empty())
            {
                co_return Error::CryptoError;
            }
            if (co_await SendBytes(Sealed))
            {
                co_return Error::IoError;
            }

            // 3. 读取 18 字节响应长度块
            std::array<std::uint8_t, 18> LenEnc{};
            if (co_await RecvExact(std::span<std::uint8_t>(LenEnc)))
            {
                co_return Error::IoError;
            }

            // 4. 派生响应密钥并解密长度字段
            const auto RespBodyKey = detail::Sha256(Key);
            const auto RespBodyIv = detail::Sha256(Iv);
            std::array<std::uint8_t, 16> RespKey16{};
            std::memcpy(RespKey16.data(), RespBodyKey.data(), 16);
            std::array<std::uint8_t, 16> RespIv16{};
            std::memcpy(RespIv16.data(), RespBodyIv.data(), 16);
            const auto RespLenKey = Kdf(RespKey16, KdfRespLenKey);
            const auto RespLenIv = Kdf(RespIv16, KdfRespLenIv);
            std::array<std::uint8_t, 16> ResponseLengthKey{};
            std::memcpy(ResponseLengthKey.data(), RespLenKey.data(), 16);
            std::array<std::uint8_t, 12> ResponseLengthIv{};
            std::memcpy(ResponseLengthIv.data(), RespLenIv.data(), 12);
            const auto LenPlain = detail::AesGcmOpen(
                detail::OpenInput{ResponseLengthKey, ResponseLengthIv, LenEnc, {}});
            if (LenPlain.size() != 2)
            {
                co_return Error::BadAuth;
            }
            const auto ResponseLength = static_cast<std::size_t>(LenPlain[0]) << 8 | LenPlain[1];

            // 5. 读取响应头密文并校验验证字节
            if (ResponseLength > 0xFFFF - 16)
            {
                co_return Error::BadLength;
            }
            std::vector<std::uint8_t> RespEnc(ResponseLength + 16);
            if (co_await RecvExact(RespEnc))
            {
                co_return Error::IoError;
            }
            const auto RespKey = Kdf(RespKey16, KdfRespKey);
            const auto RespIv = Kdf(RespIv16, KdfRespIv);
            std::array<std::uint8_t, 16> ResponseKey{};
            std::memcpy(ResponseKey.data(), RespKey.data(), 16);
            std::array<std::uint8_t, 12> ResponseIv{};
            std::memcpy(ResponseIv.data(), RespIv.data(), 12);
            ResponseHeader ResponseValue;
            if (OpenResponseHeader(
                    ResponseKey,
                    RespHeaderParseInput{ResponseIv, RespEnc, AuthId},
                    ResponseValue) != Error::None)
            {
                co_return Error::BadAuth;
            }
            if (ResponseValue.Version != VersionByte)
            {
                co_return Error::BadAuth;
            }

            // 6. 数据方向分别绑定 request 与 response key/nonce。
            Enc_.emplace(std::span<const std::uint8_t, 16>(Key),
                         std::span<const std::uint8_t, 16>(Iv), RequestValue.opt);
            Dec_.emplace(std::span<const std::uint8_t, 16>(RespKey16),
                         std::span<const std::uint8_t, 16>(RespIv16), RequestValue.opt);
            ChunkOptions_ = RequestValue.opt;
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 发送一个 UDP 数据报（UDP 数据面，chunk 即包边界）
         * @param Payload 数据报载荷
         * @return 错误码
         * @details 目标地址固定来自指令头（不随包携带）。一次调用 =
         * 加密并发送一个数据分块（长度掩码 + 载荷密文），对端
         * AsyncReceiveDatagram 恰好读到该分块即完整数据报。
         * @warning 仅在 handshake() 使用 Command::Udp 后调用；数据报
         * 模式与流式模式互斥，同一会话不可混用
         */
        [[nodiscard]] auto AsyncSendDatagram(
            std::span<const std::uint8_t> Payload) -> Net::awaitable<Error>
        {
            if (!NextLayer_ || !Handshaken_)
            {
                co_return Error::NotOpen;
            }
            if (Payload.size() > (std::numeric_limits<std::size_t>::max)() - ChunkEncryptor::Overhead)
            {
                co_return Error::BadLength;
            }
            std::vector<std::uint8_t> Out(Payload.size() + ChunkEncryptor::Overhead);
            const auto N = Enc_->Seal(Payload, Out);
            if (N == 0)
            {
                co_return Error::BadLength;
            }
            const auto Wire = std::span<const std::uint8_t>(Out.data(), N);
            if (co_await SendBytes(Wire))
            {
                co_return Error::IoError;
            }
            co_return Error::None;
        }

        /**
         * @brief 接收一个 UDP 数据报（UDP 数据面，chunk 即包边界）
         * @param Payload 输出数据报载荷
         * @return 错误码
         * @details 一次调用 = 读取并解密一个数据分块，分块明文即完整
         * 数据报。读到结束块（len=0）返回 unexpected_eof。
         * @warning 仅在 handshake() 使用 Command::Udp 后调用；数据报
         * 模式与流式模式互斥，同一会话不可混用
         */
        [[nodiscard]] auto AsyncReceiveDatagram(
            std::vector<std::uint8_t> &Payload) -> Net::awaitable<Error>
        {
            if (!NextLayer_ || !Handshaken_)
            {
                co_return Error::NotOpen;
            }
            if (Eof_)
            {
                co_return Error::UnexpectedEof;
            }
            const auto Err = co_await ReadChunk();
            if (Err != Error::None)
            {
                co_return Err;
            }
            if (Eof_)
            {
                co_return Error::UnexpectedEof;
            }
            Payload.assign(PlainRx_.begin(), PlainRx_.end());
            PlainOff_ = 0;
            co_return Error::None;
        }

        /**
         * @brief 服务端握手：解析认证头 → 校验 → 发送 AEAD 响应
         * @param Upstream 上游传输（所有权移交）
         * @param EnableUdp 是否允许 UDP command
         * @return 错误码与解析的请求
         * @details 精确分段读取认证头（42B 前缀 → 解密长度 → 请求头
         * 密文），cmdKey 解密成功即 UUID 匹配，发送 38B 响应头并
         * 派生分块密钥。认证失败不发送响应，静默断开。
         */
        [[nodiscard]] auto ReadHandshake(SharedTransmission Upstream,
                                         const bool EnableUdp = true,
                                         const bool EnableMux = true)
            -> Net::awaitable<std::pair<Error, Message>>
        {
            NextLayer_ = std::move(Upstream);
            Handshaken_ = false;
            Eof_ = false;
            AuthId_.fill(0);
            Parsed_ = Message{};
            ChunkOptions_ = static_cast<std::uint8_t>(Option::AuthenticatedLength);
            PlainRx_.clear();
            PlainOff_ = 0;
            Enc_.reset();
            Dec_.reset();
            Message Out;
            auto Err = co_await ReadRequest(Out);
            if (Err != Error::None)
            {
                co_return std::pair{Err, Message{}};
            }

            // 命令校验（Tcp/udp/mux 合法）
            const auto Cmd = static_cast<Command>(Out.Cmd);
            if (Cmd != Command::Tcp && Cmd != Command::Udp && Cmd != Command::Mux)
            {
                co_return std::pair{Error::BadMessage, Message{}};
            }
            if (Cmd == Command::Mux && !EnableMux)
            {
                co_return std::pair{Error::NotSupported, Message{}};
            }
            if (Cmd == Command::Udp && !EnableUdp)
            {
                co_return std::pair{Error::NotSupported, Message{}};
            }

            // 发送 AEAD 响应头
            Err = co_await SendSuccess(Out);
            if (Err != Error::None)
            {
                co_return std::pair{Err, Message{}};
            }

            // 数据方向分别绑定 request 与 response key/nonce。
            const auto RespBodyKey = detail::Sha256(Out.RequestKey);
            const auto RespBodyIv = detail::Sha256(Out.RequestNonce);
            std::array<std::uint8_t, 16> RespKey16{};
            std::array<std::uint8_t, 16> RespIv16{};
            std::memcpy(RespKey16.data(), RespBodyKey.data(), 16);
            std::memcpy(RespIv16.data(), RespBodyIv.data(), 16);
            Dec_.emplace(std::span<const std::uint8_t, 16>(Out.RequestKey),
                         std::span<const std::uint8_t, 16>(Out.RequestNonce), Out.Option);
            Enc_.emplace(std::span<const std::uint8_t, 16>(RespKey16),
                         std::span<const std::uint8_t, 16>(RespIv16), Out.Option);
            ChunkOptions_ = Out.Option;
            Handshaken_ = true;
            Parsed_ = Out;
            co_return std::pair{Error::None, std::move(Out)};
        }

        /**
         * @brief 获取服务端握手解析的请求
         * @return 请求（ReadHandshake 成功后有效）
         */
        [[nodiscard]] auto Parsed() const -> const Message &
        {
            return Parsed_;
        }

        /** @brief 获取认证后的账户租约。 */
        [[nodiscard]] auto TakeAuthLease() -> Preview::Account::AccountLease
        {
            return std::move(AuthLease_);
        }

        /** @brief 获取认证后的 typed 账户身份。 */
        [[nodiscard]] auto AccountId() const noexcept -> Preview::AccountId
        {
            return AccountId_;
        }

        /** @brief 获取认证后的非敏感身份文本。 */
        [[nodiscard]] auto Identity() const noexcept -> std::string_view
        {
            return Identity_;
        }

    private:
        /**
         * @brief 读取并解析认证头（服务端）
         * @param Out 输出请求消息
         * @return 错误码
         * @details 分阶段精确读取：42B 前缀 → 解密长度字段 → 读取
         * 剩余密文 → 组装解析（cmdKey 解密失败即 UUID 不匹配）→
         * 显式 UUID 校验。
         */
        [[nodiscard]] auto ReadRequest(Message &Out) -> Net::awaitable<Error>
        {
            // 识别阶段与 handler 阶段必须共用同一套 Parser。旧实现
            // 复制了长度解密和认证头解析，导致 AuthenticatedLength
            // 在真实客户端上出现“识别成功、handler BadAuth”的分叉。
            Parser RequestParser(Uuid_);
            std::error_code ParseError;
            std::array<std::uint8_t, 42> Prefix{};
            if (co_await RecvExact(std::span<std::uint8_t>(Prefix)))
            {
                co_return Error::IoError;
            }
            RequestParser.Put(Net::const_buffer(Prefix.data(), Prefix.size()), ParseError);
            const auto NeedMore = make_error_code(Error::NeedMore);
            if (ParseError && ParseError != NeedMore)
            {
                co_return Error::BadAuth;
            }
            while (!RequestParser.IsDone())
            {
                std::array<std::uint8_t, 1> Byte{};
                if (co_await RecvExact(std::span<std::uint8_t>(Byte)))
                {
                    co_return Error::IoError;
                }
                ParseError.clear();
                RequestParser.Put(Net::const_buffer(Byte.data(), Byte.size()), ParseError);
                if (ParseError && ParseError != NeedMore)
                {
                    co_return Error::BadAuth;
                }
            }

            // Parser 已完成 cmdKey/AEAD/UUID 校验；保留显式检查和 typed 账户认证。
            Out = RequestParser.Get();
            std::memcpy(AuthId_.data(), Out.AuthId.data(), AuthId_.size());
            const std::string_view GotUuid(reinterpret_cast<const char *>(Out.uuid.data()), Out.uuid.size());
            const std::string_view ExpectedUuid(reinterpret_cast<const char *>(Uuid_.data()), Uuid_.size());
            if (!Preview::ConstantTimeEqual(GotUuid, ExpectedUuid))
            {
                co_return Error::BadAuth;
            }
            if (Auth_)
            {
                auto AuthenticationResult = Auth_->Authenticate(Preview::AuthenticationRequest{
                    .AccountId = {},
                    .Identity = {},
                    .Credential = Preview::Account::CredentialView{
                        Preview::Account::CredentialKind::Uuid,
                        std::as_bytes(std::span<const std::uint8_t>(Out.uuid))},
                    .Rate = {}});
                if (!AuthenticationResult.Accepted)
                {
                    co_return Error::BadAuth;
                }
                AuthLease_ = std::move(AuthenticationResult.Lease);
                AccountId_ = AuthenticationResult.AccountId;
                Identity_ = std::move(AuthenticationResult.Identity);
            }
            co_return Error::None;
        }

        /**
         * @brief 发送 AEAD 响应头（38B）
         * @param RequestValue 请求消息（RequestKey / RequestNonce / RespHeader）
         * @return 错误码
         * @details 标准 AEAD 响应头不带 AuthID AAD；AuthID 仅保留在
         *          输入结构中兼容既有调用方。
         */
        [[nodiscard]] auto SendSuccess(const Message &RequestValue) const -> Net::awaitable<Error>
        {
            const auto RespBodyKey = detail::Sha256(RequestValue.RequestKey);
            const auto RespBodyIv = detail::Sha256(RequestValue.RequestNonce);
            std::array<std::uint8_t, 16> RespKey16{};
            std::memcpy(RespKey16.data(), RespBodyKey.data(), 16);
            std::array<std::uint8_t, 16> RespIv16{};
            std::memcpy(RespIv16.data(), RespBodyIv.data(), 16);

            const std::array<std::uint8_t, 4> ResponsePlain{
                RequestValue.RespHeader,
                RequestValue.Option,
                0,
                0};
            const auto RespKey = Kdf(RespKey16, KdfRespKey);
            const auto RespIv = Kdf(RespIv16, KdfRespIv);
            std::array<std::uint8_t, 16> ResponseKey{};
            std::memcpy(ResponseKey.data(), RespKey.data(), 16);
            std::array<std::uint8_t, 12> ResponseIv{};
            std::memcpy(ResponseIv.data(), RespIv.data(), 12);
            const auto RespEnc = SealResponseHeader(
                ResponseKey,
                RespHeaderInput{ResponseIv, ResponsePlain, AuthId_});
            if (RespEnc.size() != 20)
            {
                co_return Error::CryptoError;
            }

            const auto RespLenKey = Kdf(RespKey16, KdfRespLenKey);
            const auto RespLenIv = Kdf(RespIv16, KdfRespLenIv);
            std::array<std::uint8_t, 16> ResponseLengthKey{};
            std::memcpy(ResponseLengthKey.data(), RespLenKey.data(), 16);
            std::array<std::uint8_t, 12> ResponseLengthIv{};
            std::memcpy(ResponseLengthIv.data(), RespLenIv.data(), 12);
            const std::array<std::uint8_t, 2> ResponseLengthPlain{0, 4};
            const auto LenEnc =
                detail::AesGcmSeal(detail::SealInput{
                    ResponseLengthKey,
                    ResponseLengthIv,
                    ResponseLengthPlain,
                    {}});
            if (LenEnc.size() != 18)
            {
                co_return Error::CryptoError;
            }

            std::vector<std::uint8_t> Response;
            Response.reserve(LenEnc.size() + RespEnc.size());
            Response.insert(Response.end(), LenEnc.begin(), LenEnc.end());
            Response.insert(Response.end(), RespEnc.begin(), RespEnc.end());
            if (co_await SendBytes(Response))
            {
                co_return Error::IoError;
            }
            co_return Error::None;
        }

        /**
         * @brief 读取并解密一个数据分块（内部循环补读）
         * @return 错误码；none 且 Eof_ = 结束块
         * @details 标准 option 使用 [2B 掩码长度][载荷密文 + 16B tag]；
         *          AuthenticatedLength 兼容路径使用两个 AEAD 长度块。
         *          解密失败（tag 校验）返回 bad_auth。
         */
        [[nodiscard]] auto ReadChunk() -> Net::awaitable<Error>
        {
            const bool AuthenticatedLength =
                detail::HasOption(ChunkOptions_, Option::AuthenticatedLength);
            std::size_t LengthHeaderSize = 2;
            if (AuthenticatedLength)
            {
                LengthHeaderSize = 18;
            }

            // 1. 读取长度头（标准路径为 2 字节，兼容路径为 AEAD 块）
            std::array<std::uint8_t, 18> head{};
            if (co_await RecvExact(std::span<std::uint8_t>(head).first(LengthHeaderSize)))
            {
                co_return Error::UnexpectedEof;
            }

            // 2. 解密长度字段
            auto Len = Dec_->OpenLen(std::span<const std::uint8_t>(head).first(LengthHeaderSize));
            if (!Len)
            {
                co_return Len.error();
            }
            if (*Len == 0) // 结束块
            {
                Eof_ = true;
                co_return Error::None;
            }

            auto EncodedLength = *Len;
            if (AuthenticatedLength)
            {
                EncodedLength += 16;
            }
            if (EncodedLength < 16)
            {
                co_return Error::BadLength;
            }
            const auto PlainLength = EncodedLength - 16;

            // 3. 读取载荷密文并解密
            std::vector<std::uint8_t> Enc(EncodedLength);
            if (co_await RecvExact(Enc))
            {
                co_return Error::UnexpectedEof;
            }
            typename Memory::template Buffer<std::uint8_t> Plain =
                Mem_.template MakeBuffer<std::uint8_t>(PlainLength);
            const auto Err = Dec_->OpenPayload(Enc, Plain);
            if (Err != Error::None)
            {
                co_return Err;
            }

            // 4. 存入待读缓冲
            PlainRx_ = std::move(Plain);
            PlainOff_ = 0;
            co_return Error::None;
        }

        /**
         * @brief 精确读取指定字节数（内部循环补读）
         * @param Buffer 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto RecvExact(std::span<std::uint8_t> Buffer) -> Net::awaitable<bool>
        {
            if (!NextLayer_)
            {
                co_return true;
            }
            std::size_t Done = 0;
            while (Done < Buffer.size())
            {
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_read_some(
                    AsBytes(Buffer.subspan(Done)),
                    ErrorCode);
                if (ErrorCode || N == 0)
                {
                    co_return true;
                }
                if (N > Buffer.size() - Done)
                {
                    co_return true;
                }
                Done += N;
            }
            co_return false;
        }

        /**
         * @brief 发送全部字节
         * @param Data 数据
         * @return true = 失败
         */
        [[nodiscard]] auto SendBytes(std::span<const std::uint8_t> Data) const -> Net::awaitable<bool>
        {
            if (!NextLayer_)
            {
                co_return true;
            }
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_write_some(
                    AsBytes(Data.subspan(Done)),
                    ErrorCode);
                if (ErrorCode)
                {
                    co_return true;
                }
                if (N == 0)
                {
                    co_return true; // 底层零字节写入，防死循环
                }
                if (N > Data.size() - Done)
                {
                    co_return true;
                }
                Done += N;
            }
            co_return false;
        }

        [[nodiscard]] auto FillRandomBytes(std::span<std::uint8_t> Data) -> bool
        {
            if (Random_)
            {
                return Preview::Crypto::FillRandom(Data, Random_);
            }
            return Preview::Crypto::FillRandom(Data);
        }

        SharedTransmission NextLayer_;         ///< 底层传输（独占所有权）
        std::array<std::uint8_t, 16> AuthId_{}; ///< 请求 AuthID（兼容响应头输入）
        Message Parsed_{};                       ///< 服务端握手解析结果
        std::array<std::uint8_t, 16> Uuid_;      ///< 协议 UUID（凭据）
        RandomSource Random_;                    ///< 可注入的 CSPRNG（空 = BoringSSL）
        Preview::SharedAuthenticator AuthOwner_{}; ///< 认证器共享所有权
        const Preview::Authenticator *Auth_{nullptr}; ///< 认证器（非拥有）
        Preview::Account::AccountLease AuthLease_{}; ///< 协议认证租约
        Preview::AccountId AccountId_{};           ///< typed 账户身份
        std::string Identity_{};                   ///< 非敏感身份文本
        std::optional<ChunkEncryptor> Enc_;     ///< 分块加密器（发送侧）
        std::optional<ChunkDecryptor> Dec_;     ///< 分块解密器（接收侧）
        std::uint8_t ChunkOptions_{static_cast<std::uint8_t>(Option::AuthenticatedLength)};
        Memory Mem_;                             ///< 会话内存策略（Arena，热路径零释放分配）
        typename Memory::template Buffer<std::uint8_t> PlainRx_{Mem_.Arena()}; ///< 解密后的明文缓冲
        std::size_t PlainOff_{0};               ///< 明文缓冲消费偏移
        bool Handshaken_{false};                 ///< 握手完成标志
        bool Eof_{false};                        ///< 已读到 EOF（对端关闭）
    };


    /// 流连接共享指针
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Vmess
