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
#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Compatible.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Shadowtls/Detail/ClientHello.hpp>
#include <Prism/Protocols/Shadowtls/Detail/RecordProtector.hpp>
#include <Prism/Protocols/Shadowtls/Detail/CarrierWire.hpp>
#include <Prism/Protocols/Shadowtls/Types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Shadowtls::Detail
{

    namespace Net = boost::asio;

    /** @brief carrier 向已握手连接移交的双向保护与已推进读取状态。 */
    struct RecordProtectionHandover final
    {
        RecordProtector Write;
        RecordProtector Read;
        std::vector<std::uint8_t> PendingPayload;
        std::optional<Failure> PendingTerminal;
    };

    /**
     * @class Conn
     * @brief ShadowTLS v3 会话连接（Transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后通过
     * Transmission 接口透传数据。
     * @tparam Memory 会话内存策略（默认 8KB Arena；可注入自定义策略）
     */
    template <Prism::Memory::Restrict Memory = Prism::Memory::SessionResource<>>
    class Conn : public Prism::Transmission
    {
    public:
        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using MemoryType = Memory;

        /**
         * @brief 构造函数
         * @param Upstream 底层传输（所有权移交）
         * @param Password 认证密码
         * @throws std::invalid_argument 上游为空时，在构造任何 executor 服务前拒绝。
         */
        explicit Conn(SharedTransmission Upstream, std::string Password)
            : Prism::Transmission(RequireExecutor(Upstream)),
              NextLayer_(std::move(Upstream)), Password_(std::move(Password))
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (!NextLayer_)
            {
                return Prism::Transmission::Executor();
            }
            return NextLayer_->Executor();
        }

        /**
         * @brief 客户端握手：构造并发送带认证 SessionId 的 ClientHello 帧
         * @param ServerRandom 服务端随机数（32 字节，真实 TLS 中由握手生成）
         * @param ClientRandom 客户端随机数（32 字节）
         * @return 错误码
         * @details 构造简化 ClientHello：TLS 记录头(5) + 握手头(4) +
         * version(2) + random(32) + sidLen(1) + SessionId(32)，
         * SessionId 末尾 4 字节为 HMAC 认证码。
         */
        [[nodiscard]] auto WriteHandshake(std::span<const std::uint8_t> ServerRandom,
                                           std::span<const std::uint8_t> ClientRandom)
            -> Net::awaitable<Result<void>>
        {
            if (!NextLayer_ || ServerRandom.size() != TlsRndSize || ClientRandom.size() != TlsRndSize)
            {
                co_return std::unexpected(FailureFromError(Error::BadLength));
            }
            Handshaken_ = false;
            WriteProtector_.reset();
            ReadProtector_.reset();
            PendingReadPayload_.clear();
            PendingReadOffset_ = 0;
            ServerRandom_.clear();
            ClientHelloWire_.clear();
            std::vector<std::uint8_t> Hello = Wire::BuildClientHello(ClientRandom);

            // 构造 SessionId：前 28 字节固定模式 + 末尾 4 字节 HMAC
            std::array<std::uint8_t, TlsSessionIdSz> SessionId{};
            for (std::size_t I = 0; I < TlsSessionIdSz - HmacSize; ++I)
                SessionId[I] = static_cast<std::uint8_t>(I * 7 + 3);

            const auto HmacHello = std::span<const std::uint8_t>(Hello).subspan(TlsHdrsize);
            auto Err = GenerateSessionId(SessionIdInput{Password_, HmacHello, SessionId});
            if (Err != Error::None)
            {
                co_return std::unexpected(FailureFromError(Err));
            }
            std::memcpy(Hello.data() + TlsHdrsize + SessionIdStart, SessionId.data(),
                        TlsSessionIdSz);

            auto Sent = co_await Io::SendBytes(NextLayer_, Hello);
            if (!Sent) co_return std::unexpected(Sent.error());

            // 保存会话状态
            ServerRandom_.assign(ServerRandom.begin(), ServerRandom.end());
            Handshaken_ = true;
            co_return Result<void>{};
        }

        /**
         * @brief 发送调用方提供的标准 TLS ClientHello record
         * @param ClientHelloWire 含 TLS record 头的完整 ClientHello 模板
         * @return 错误码
         * @details 模板必须包含 32 字节 SessionId；方法会将末尾 4 字节置零，
         *          按 ShadowTLS v3 规则计算 HMAC 后再发送。这样 TLS ClientHello
         *          的扩展、SNI、cipher suites 和 key share 均由真实 TLS 构造器保留。
         * @note 本方法只负责 ShadowTLS SessionId 认证，不执行 TLS 状态机；外层
         *       TLS 握手完成并取得 ServerRandom 后，调用 EnableRecordProtection()。
         */
        [[nodiscard]] auto WriteStandardHandshake(std::span<const std::uint8_t> ClientHelloWire)
            -> Net::awaitable<Result<void>>
        {
            ClientHelloWire_.clear();
            if (!NextLayer_)
            {
                co_return std::unexpected(FailureFromError(Error::NotOpen));
            }
            Handshaken_ = false;
            WriteProtector_.reset();
            ReadProtector_.reset();
            PendingReadPayload_.clear();
            PendingReadOffset_ = 0;
            ServerRandom_.clear();
            ClientHelloWire_.clear();
            std::vector<std::uint8_t> Wire(ClientHelloWire.begin(), ClientHelloWire.end());
            ClientHelloRecord Parsed;
            auto Err = ParseClientHelloRecord(Wire, Parsed);
            if (Err != Error::None)
            {
                co_return std::unexpected(FailureFromError(Err));
            }
            auto SessionId = std::span<std::uint8_t, TlsSessionIdSz>(
                Wire.data() + Parsed.SessionIdOffset, TlsSessionIdSz);
            std::fill(SessionId.begin() + TlsSessionIdSz - HmacSize, SessionId.end(), 0);
            Err = GenerateSessionId(
                SessionIdInput{Password_, std::span<const std::uint8_t>(Wire).subspan(TlsHdrsize), SessionId});
            if (Err != Error::None)
            {
                co_return std::unexpected(FailureFromError(Err));
            }
            auto Sent = co_await Io::SendBytes(NextLayer_, Wire);
            if (!Sent) co_return std::unexpected(Sent.error());
            ClientHelloWire_ = Wire;
            Handshaken_ = true;
            co_return Result<void>{};
        }

        /**
         * @brief 显式启用标准 ShadowTLS v3 application-data record
         * @param ServerRandom 已完成外层 TLS 握手后取得的 ServerHello random
         * @param WriteDirection 本端写方向标签
         * @param ReadDirection 本端读方向标签
         * @return 初始化结果
         * @note 默认不启用，保留旧的简化 Conn 行为；真实 carrier 完成外层 TLS
         *       后必须显式调用本接口，避免在缺少 ServerRandom 时伪造标准会话。
         */
        [[nodiscard]] auto EnableRecordProtection(
            std::span<const std::uint8_t> ServerRandom,
            RecordDirections Directions = {}) -> Result<void>
        {
            if (!Handshaken_ || ServerRandom.size() != TlsRndSize)
            {
                return std::unexpected(FailureFromError(Error::BadLength));
            }
            RecordProtector Write(RecordProtectionOptions{
                Password_, ServerRandom, Directions.Write, RecordSeed::Directional,
                ProtectionMode::Application});
            RecordProtector Read(RecordProtectionOptions{
                Password_, ServerRandom, Directions.Read, RecordSeed::Directional,
                ProtectionMode::Application});
            if (!Write.IsValid() || !Read.IsValid())
            {
                return std::unexpected(FailureFromError(Error::IoError));
            }
            WriteProtector_ = std::move(Write);
            ReadProtector_ = std::move(Read);
            PendingReadPayload_.clear();
            PendingReadOffset_ = 0;
            return {};
        }

        /**
         * @brief 接管已推进的双向 record 保护状态
         * @param Handover 双向保护器、首帧载荷与已保存终态
         * @return 接管结果
         * @note 供标准 carrier relay 在消费首个客户端 application-data 后
         *       将连接交给内层 handler；不会重新计算或回放该首帧。
         */
        [[nodiscard]] auto AdoptRecordProtection(RecordProtectionHandover Handover) -> Result<void>
        {
            if (!Handshaken_ || !Handover.Write.IsValid() || !Handover.Read.IsValid())
            {
                return std::unexpected(FailureFromError(Error::BadLength));
            }
            WriteProtector_ = std::move(Handover.Write);
            ReadProtector_ = std::move(Handover.Read);
            PendingReadPayload_ = std::move(Handover.PendingPayload);
            PendingReadOffset_ = 0;
            if (Handover.PendingTerminal && !PendingReadFailure_)
            {
                PendingReadFailure_ = std::move(Handover.PendingTerminal);
            }
            return {};
        }

        /**
         * @brief 服务端握手：读取并校验 ClientHello SessionId HMAC
         * @return 错误码
         */
        [[nodiscard]] auto ReadHandshake()
            -> Net::awaitable<Result<void>>
        {
            if (!NextLayer_)
            {
                co_return std::unexpected(FailureFromError(Error::NotOpen));
            }
            Handshaken_ = false;
            WriteProtector_.reset();
            ReadProtector_.reset();
            PendingReadPayload_.clear();
            PendingReadOffset_ = 0;
            ServerRandom_.clear();
            ClientHelloWire_.clear();
            // 完整 hello：TLS 头 + 握手头 + version + random + sidLen + SessionId + 尾部
            constexpr std::size_t HelloLen = TlsHdrsize + SessionIdStart + TlsSessionIdSz + 16;
            std::vector<std::uint8_t> Hello(HelloLen);
            auto Read = co_await Io::ReadExact(NextLayer_, Hello, PendingReadFailure_);
            if (!Read) co_return std::unexpected(Read.error());
            const auto HelloSpan = AsBytesSpan(Hello);
            if (!VerifyClientHello(Password_, HelloSpan))
            {
                co_return std::unexpected(FailureFromError(Error::BadAuth, Hello.size()));
            }
            Handshaken_ = true;
            co_return Result<void>{};
        }

        /**
         * @brief 读取并校验标准 TLS ClientHello record
         * @return typed 握手结果；成功后可通过 TakeClientHelloWire() 取得完整首包
         * @note 与简化 ReadHandshake() 分开，标准 carrier 不会丢失
         *       ClientHello 的扩展、SNI 或后续 relay 所需的原始字节。
         */
        [[nodiscard]] auto ReadStandardHandshake() -> Net::awaitable<Result<void>>
        {
            ClientHelloWire_.clear();
            if (!NextLayer_)
            {
                co_return std::unexpected(FailureFromError(Error::NotOpen));
            }
            Handshaken_ = false;
            WriteProtector_.reset();
            ReadProtector_.reset();
            PendingReadPayload_.clear();
            PendingReadOffset_ = 0;
            ServerRandom_.clear();
            std::array<std::uint8_t, TlsHdrsize> Header{};
            auto HeaderRead = co_await Io::ReadExact(
                NextLayer_, Header, PendingReadFailure_);
            if (!HeaderRead) co_return std::unexpected(HeaderRead.error());
            const auto Length = (static_cast<std::size_t>(Header[3]) << 8) | Header[4];
            if (Length != 0U && PendingReadFailure_)
            {
                co_return std::unexpected(*PendingReadFailure_);
            }
            if (Length > MaxTlsPlaintext)
            {
                co_return std::unexpected(FailureFromError(Error::BadLength, TlsHdrsize));
            }
            ClientHelloWire_.resize(TlsHdrsize + Length);
            std::copy(Header.begin(), Header.end(), ClientHelloWire_.begin());
            auto PayloadRead = co_await Io::ReadExact(
                NextLayer_, std::span<std::uint8_t>(ClientHelloWire_).subspan(TlsHdrsize),
                PendingReadFailure_);
            if (!PayloadRead)
            {
                ClientHelloWire_.clear();
                auto Failure = PayloadRead.error();
                Failure.Bytes += TlsHdrsize;
                PendingReadFailure_ = Failure;
                co_return std::unexpected(Failure);
            }
            ClientHelloRecord Parsed;
            const auto ParseError = ParseClientHelloRecord(ClientHelloWire_, Parsed);
            if (ParseError != Error::None)
            {
                auto Failure = FailureFromError(ParseError, ClientHelloWire_.size());
                ClientHelloWire_.clear();
                co_return std::unexpected(Failure);
            }
            if (!VerifyClientHello(Password_, AsBytesSpan(ClientHelloWire_)))
            {
                auto Failure = FailureFromError(Error::BadAuth, ClientHelloWire_.size());
                ClientHelloWire_.clear();
                co_return std::unexpected(Failure);
            }
            Handshaken_ = true;
            co_return Result<void>{};
        }

        /**
         * @brief 取出已校验的标准 ClientHello 原始 wire
         * @return 完整 TLS record；调用后 Conn 不再持有该首包
         */
        [[nodiscard]] auto TakeClientHelloWire() -> std::vector<std::uint8_t>
        {
            return std::move(ClientHelloWire_);
        }

    private:
        /** @brief 按 ShadowTLS 明文语义读取；原生传输结果不经 error_code 重建。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            if (!NextLayer_ || !Handshaken_)
                co_return Prism::IoResult{0, ToFaultFailure(FailureFromError(Error::NotOpen))};
            if (Buffer.empty()) co_return Prism::IoResult{};
            if (!ReadProtector_)
            {
                if (PendingReadFailure_)
                {
                    co_return Prism::IoResult{0, ToFaultFailure(*PendingReadFailure_)};
                }
                co_return co_await NextLayer_->ReadSome(Buffer);
            }
            while (true)
            {
                if (PendingReadOffset_ < PendingReadPayload_.size())
                {
                    const auto Count = (std::min)(Buffer.size(),
                                                  PendingReadPayload_.size() - PendingReadOffset_);
                    std::memcpy(Buffer.data(), PendingReadPayload_.data() + PendingReadOffset_, Count);
                    PendingReadOffset_ += Count;
                    if (PendingReadOffset_ == PendingReadPayload_.size())
                    {
                        PendingReadPayload_.clear();
                        PendingReadOffset_ = 0;
                    }
                    co_return Prism::IoResult{Count, {}};
                }
                if (PendingReadFailure_)
                {
                    co_return Prism::IoResult{0, ToFaultFailure(*PendingReadFailure_)};
                }

                std::array<std::uint8_t, TlsHdrsize> Header{};
                auto HeaderResult = co_await Io::ReadExact(
                    NextLayer_, Header, PendingReadFailure_);
                if (!HeaderResult)
                    co_return Prism::IoResult{0, ToFaultFailure(HeaderResult.error())};
                if (Header[0] == 0x15)
                    co_return Prism::IoResult{0, {Prism::Fault::Code::Eof}};
                const auto Length = (static_cast<std::size_t>(Header[3]) << 8) | Header[4];
                if (Length != 0U && PendingReadFailure_)
                {
                    co_return Prism::IoResult{0, ToFaultFailure(*PendingReadFailure_)};
                }
                if (Length < HmacSize || Length > HmacSize + MaxTlsPlaintext)
                    co_return Prism::IoResult{0, ToFaultFailure(FailureFromError(Error::BadLength, TlsHdrsize))};
                std::vector<std::uint8_t> Record(TlsHdrsize + Length);
                std::copy(Header.begin(), Header.end(), Record.begin());
                auto PayloadRead = co_await Io::ReadExact(
                    NextLayer_, std::span<std::uint8_t>(Record).subspan(TlsHdrsize),
                    PendingReadFailure_);
                if (!PayloadRead)
                    co_return Prism::IoResult{0, ToFaultFailure(PayloadRead.error())};
                std::vector<std::uint8_t> Payload;
                const auto Err = ReadProtector_->Decode(Record, Payload);
                if (Err != Error::None)
                    co_return Prism::IoResult{0, ToFaultFailure(FailureFromError(Err, Record.size()))};
                PendingReadPayload_ = std::move(Payload);
            }
        }

        /** @brief 按 ShadowTLS 明文语义写入；原生传输结果不经 error_code 重建。 */
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            if (!NextLayer_ || !Handshaken_)
                co_return Prism::IoResult{0, ToFaultFailure(FailureFromError(Error::NotOpen))};
            if (Buffer.empty()) co_return Prism::IoResult{};
            if (!WriteProtector_)
                co_return co_await NextLayer_->WriteSome(Buffer);
            const auto Count = (std::min)(Buffer.size(), MaxTlsPlaintext);
            std::vector<std::uint8_t> Payload(Count);
            std::memcpy(Payload.data(), Buffer.data(), Count);
            std::vector<std::uint8_t> Record;
            const auto EncodeError = WriteProtector_->Encode(Payload, Record);
            if (EncodeError != Error::None)
                co_return Prism::IoResult{0, ToFaultFailure(FailureFromError(EncodeError))};
            auto Sent = co_await Io::SendBytes(NextLayer_, Record);
            if (!Sent) co_return Prism::IoResult{0, ToFaultFailure(Sent.error())};
            co_return Prism::IoResult{Count, {}};
        }

    public:
        /** @brief 握手后的真实部分读；结果与借用沿正式前门交付一次。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<ShadowReadWork>(ShadowRead{std::static_pointer_cast<Conn>(Transmission::shared_from_this()), Buffer}, std::move(Handler));
        }

        /** @brief 握手后的真实部分写；短写与保护记录语义保持不变。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<ShadowWriteWork>(ShadowWrite{std::static_pointer_cast<Conn>(Transmission::shared_from_this()), Buffer}, std::move(Handler));
        }

        /** @brief 真实写半关闭转交底层载体；读取方向保持可用。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Prism::Transmission::PostResult(Executor(), std::move(Handler), Prism::IoResult{0, {Prism::Fault::Code::IoError}});
                return;
            }
            NextLayer_->WriteShutdown(std::move(Handler));
        }

        /**
         * @brief 关闭底层传输
         */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            if (NextLayer_)
            {
                return NextLayer_->Close();
            }
            return {};
        }

        /**
         * @brief 取消挂起操作
         */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            if (NextLayer_)
            {
                return NextLayer_->Cancel();
            }
            return {};
        }

        struct ShadowRead final { std::shared_ptr<Conn> Owner; std::span<std::byte> Buffer; };
        struct ShadowWrite final { std::shared_ptr<Conn> Owner; std::span<const std::byte> Buffer; };
        struct ShadowReadWork final
        {
            template<class State>
            auto operator()(State Operation, ShadowRead Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadPartial(Input.Buffer), Net::deferred);
                co_return std::tuple{std::move(Result)};
            }
        };
        struct ShadowWriteWork final
        {
            template<class State>
            auto operator()(State Operation, ShadowWrite Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer), Net::deferred);
                co_return std::tuple{std::move(Result)};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()), Handler, std::move(Value));
        }

        /**
         * @brief 获取底层传输（装饰器链导航）
         */
        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Prism::Transmission * override
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

    private:
        /** @brief 同步验证拥有型上游；不创建空执行域或隐含替代执行器。 */
        [[nodiscard]] static auto RequireExecutor(const SharedTransmission &Upstream)
            -> Net::any_io_executor
        {
            if (!Upstream) throw std::invalid_argument("ShadowTLS 上游不能为空");
            return Upstream->Executor();
        }

        SharedTransmission NextLayer_;      ///< 底层传输（独占所有权）
        std::string Password_;                ///< 认证密码
        Memory Mem_;                          ///< 会话内存策略（Arena，热路径零释放分配）
        /// 服务端随机数（握手后，Arena 分配）
        typename Memory::template Buffer<std::uint8_t> ServerRandom_{Mem_.Arena()};
        bool Handshaken_{false};              ///< 握手完成标志
        std::vector<std::uint8_t> ClientHelloWire_;
        std::optional<RecordProtector> WriteProtector_;
        std::optional<RecordProtector> ReadProtector_;
        std::vector<std::uint8_t> PendingReadPayload_;
        std::size_t PendingReadOffset_{0};
        std::optional<Failure> PendingReadFailure_;
    };

    /// 流连接共享指针（默认内存策略）
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Prism::TransmissionLike<Conn<>>);

} // namespace Prism::Shadowtls::Detail
