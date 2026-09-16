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

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Shadowtls/Codec.hpp>
#include <Preview/Protocols/Shadowtls/Types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace Preview::Shadowtls
{

    namespace Net = boost::asio;

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
         * @param Upstream 底层传输（所有权移交）
         * @param Password 认证密码
         */
        explicit Conn(SharedTransmission Upstream, std::string Password)
            : NextLayer_(std::move(Upstream)), Password_(std::move(Password))
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
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
            -> Net::awaitable<Error>
        {
            if (!NextLayer_ || ServerRandom.size() != TlsRndSize || ClientRandom.size() != TlsRndSize)
            {
                co_return Error::BadLength;
            }
            Handshaken_ = false;
            WriteProtector_.reset();
            ReadProtector_.reset();
            PendingReadPayload_.clear();
            PendingReadOffset_ = 0;
            ServerRandom_.clear();
            ClientHelloWire_.clear();
            std::vector<std::uint8_t> Hello = BuildClientHello(ClientRandom);

            // 构造 SessionId：前 28 字节固定模式 + 末尾 4 字节 HMAC
            std::array<std::uint8_t, TlsSessionIdSz> SessionId{};
            for (std::size_t I = 0; I < TlsSessionIdSz - HmacSize; ++I)
                SessionId[I] = static_cast<std::uint8_t>(I * 7 + 3);

            const auto HmacHello = std::span<const std::uint8_t>(Hello).subspan(TlsHdrsize);
            auto Err = GenerateSessionId(SessionIdInput{Password_, HmacHello, SessionId});
            if (Err != Error::None)
            {
                co_return Err;
            }
            std::memcpy(Hello.data() + TlsHdrsize + SessionIdStart, SessionId.data(),
                        TlsSessionIdSz);

            if (co_await SendBytes(Hello))
            {
                co_return Error::IoError;
            }

            // 保存会话状态
            ServerRandom_.assign(ServerRandom.begin(), ServerRandom.end());
            Handshaken_ = true;
            co_return Error::None;
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
            -> Net::awaitable<Error>
        {
            ClientHelloWire_.clear();
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
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
                co_return Err;
            }
            auto SessionId = std::span<std::uint8_t, TlsSessionIdSz>(
                Wire.data() + Parsed.SessionIdOffset, TlsSessionIdSz);
            std::fill(SessionId.begin() + TlsSessionIdSz - HmacSize, SessionId.end(), 0);
            Err = GenerateSessionId(
                SessionIdInput{Password_, std::span<const std::uint8_t>(Wire).subspan(TlsHdrsize), SessionId});
            if (Err != Error::None)
            {
                co_return Err;
            }
            if (co_await SendBytes(Wire))
            {
                co_return Error::IoError;
            }
            ClientHelloWire_ = Wire;
            Handshaken_ = true;
            co_return Error::None;
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
        [[nodiscard]] auto EnableRecordProtection(std::span<const std::uint8_t> ServerRandom,
                                                   char WriteDirection = TagClient,
                                                   char ReadDirection = TagServer) -> Error
        {
            if (!Handshaken_ || ServerRandom.size() != TlsRndSize)
            {
                return Error::BadLength;
            }
            RecordProtector Write(Password_, ServerRandom, WriteDirection);
            RecordProtector Read(Password_, ServerRandom, ReadDirection);
            if (!Write.IsValid() || !Read.IsValid())
            {
                return Error::IoError;
            }
            WriteProtector_ = std::move(Write);
            ReadProtector_ = std::move(Read);
            PendingReadPayload_.clear();
            PendingReadOffset_ = 0;
            return Error::None;
        }

        /**
         * @brief 接管已推进的双向 record 保护状态
         * @param Write 已初始化的本端写方向保护器
         * @param Read 已初始化且可包含首帧推进的本端读方向保护器
         * @param PendingPayload 已认证但尚未交给内层协议的首帧载荷
         * @return 接管结果
         * @note 供标准 carrier relay 在消费首个客户端 application-data 后
         *       将连接交给内层 handler；不会重新计算或回放该首帧。
         */
        [[nodiscard]] auto AdoptRecordProtection(RecordProtector Write, RecordProtector Read,
                                                  std::vector<std::uint8_t> PendingPayload) -> Error
        {
            if (!Handshaken_ || !Write.IsValid() || !Read.IsValid())
            {
                return Error::BadLength;
            }
            WriteProtector_ = std::move(Write);
            ReadProtector_ = std::move(Read);
            PendingReadPayload_ = std::move(PendingPayload);
            PendingReadOffset_ = 0;
            return Error::None;
        }

        /**
         * @brief 服务端握手：读取并校验 ClientHello SessionId HMAC
         * @return 错误码
         */
        [[nodiscard]] auto ReadHandshake()
            -> Net::awaitable<Error>
        {
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
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
            if (co_await ReadExact(Hello))
            {
                co_return Error::UnexpectedEof;
            }
            const auto HelloSpan = AsBytesSpan(Hello);
            if (!VerifyClientHello(Password_, HelloSpan))
            {
                co_return Error::BadAuth;
            }
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 读取并校验标准 TLS ClientHello record
         * @return 错误码；成功后可通过 TakeClientHelloWire() 取得完整首包
         * @note 与兼容用的简化 ReadHandshake() 分开，标准 carrier 不会丢失
         *       ClientHello 的扩展、SNI 或后续 relay 所需的原始字节。
         */
        [[nodiscard]] auto ReadStandardHandshake() -> Net::awaitable<Error>
        {
            ClientHelloWire_.clear();
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            Handshaken_ = false;
            WriteProtector_.reset();
            ReadProtector_.reset();
            PendingReadPayload_.clear();
            PendingReadOffset_ = 0;
            ServerRandom_.clear();
            std::array<std::uint8_t, TlsHdrsize> Header{};
            if (co_await ReadExact(Header))
            {
                co_return Error::UnexpectedEof;
            }
            const auto Length = (static_cast<std::size_t>(Header[3]) << 8) | Header[4];
            if (Length > MaxTlsPlaintext)
            {
                co_return Error::BadLength;
            }
            ClientHelloWire_.resize(TlsHdrsize + Length);
            std::copy(Header.begin(), Header.end(), ClientHelloWire_.begin());
            if (co_await ReadExact(std::span<std::uint8_t>(ClientHelloWire_).subspan(TlsHdrsize)))
            {
                ClientHelloWire_.clear();
                co_return Error::UnexpectedEof;
            }
            ClientHelloRecord Parsed;
            const auto ParseError = ParseClientHelloRecord(ClientHelloWire_, Parsed);
            if (ParseError != Error::None)
            {
                ClientHelloWire_.clear();
                co_return ParseError;
            }
            if (!VerifyClientHello(Password_, AsBytesSpan(ClientHelloWire_)))
            {
                ClientHelloWire_.clear();
                co_return Error::BadAuth;
            }
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 取出已校验的标准 ClientHello 原始 wire
         * @return 完整 TLS record；调用后 Conn 不再持有该首包
         */
        [[nodiscard]] auto TakeClientHelloWire() -> std::vector<std::uint8_t>
        {
            return std::move(ClientHelloWire_);
        }

        /**
         * @brief 透传读取（握手后数据面为裸流）
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
            if (!ReadProtector_)
            {
                co_return co_await NextLayer_->async_read_some(Buffer, ErrorCode);
            }
            if (Buffer.empty())
            {
                co_return 0;
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
                    co_return Count;
                }

                std::array<std::uint8_t, TlsHdrsize> Header{};
                if (co_await ReadExact(Header))
                {
                    ErrorCode = make_error_code(Error::UnexpectedEof);
                    co_return 0;
                }
                const auto Length = (static_cast<std::size_t>(Header[3]) << 8) | Header[4];
                if (Length < HmacSize || Length > HmacSize + MaxTlsPlaintext)
                {
                    ErrorCode = make_error_code(Error::BadLength);
                    co_return 0;
                }
                std::vector<std::uint8_t> Record(TlsHdrsize + Length);
                std::copy(Header.begin(), Header.end(), Record.begin());
                if (co_await ReadExact(std::span<std::uint8_t>(Record).subspan(TlsHdrsize)))
                {
                    ErrorCode = make_error_code(Error::UnexpectedEof);
                    co_return 0;
                }
                std::vector<std::uint8_t> Payload;
                const auto Err = ReadProtector_->Decode(Record, Payload);
                if (Err != Error::None)
                {
                    ErrorCode = make_error_code(Err);
                    co_return 0;
                }
                PendingReadPayload_ = std::move(Payload);
            }
        }

        /**
         * @brief 透传写入（握手后数据面为裸流）
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
            if (!WriteProtector_)
            {
                co_return co_await NextLayer_->async_write_some(Buffer, ErrorCode);
            }
            if (Buffer.empty())
            {
                co_return 0;
            }
            const auto Count = (std::min)(Buffer.size(), MaxTlsPlaintext);
            std::vector<std::uint8_t> Payload(Count);
            std::memcpy(Payload.data(), Buffer.data(), Count);
            std::vector<std::uint8_t> Record;
            const auto EncodeError = WriteProtector_->Encode(Payload, Record);
            if (EncodeError != Error::None)
            {
                ErrorCode = make_error_code(EncodeError);
                co_return 0;
            }
            if (co_await SendBytes(Record))
            {
                ErrorCode = make_error_code(Error::BrokenPipe);
                co_return 0;
            }
            co_return Count;
        }

        /**
         * @brief 关闭底层传输
         */
        auto Close() -> void override
        {
            if (NextLayer_)
            {
                NextLayer_->Close();
            }
        }

        /**
         * @brief 取消挂起操作
         */
        auto Cancel() -> void override
        {
            if (NextLayer_)
            {
                NextLayer_->Cancel();
            }
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

    private:
        /**
         * @brief 构造简化 ClientHello（无 TLS 头版本的握手数据）
         * @param ClientRandom 32 字节客户端随机数
         * @return 完整 ClientHello（含 TLS 记录头 5 字节）
         */
        [[nodiscard]] auto BuildClientHello(std::span<const std::uint8_t> ClientRandom)
          -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> Hello(TlsHdrsize + SessionIdStart + TlsSessionIdSz + 16, 0);
            Hello[0] = 0x16; // content_handshake
            Hello[TlsHdrsize] = HsTypeClienthello;
            Hello[TlsHdrsize + SessionIdStart - 1] = TlsSessionIdSz;
            if (ClientRandom.size() >= TlsRndSize)
            {
                std::memcpy(Hello.data() + TlsHdrsize + 1 + 3 + 2, ClientRandom.data(),
                            TlsRndSize);
            }
            return Hello;
        }

        /**
         * @brief 精确读取指定字节数
         * @param Buffer 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> Buffer)
            -> Net::awaitable<bool>
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
                if (ErrorCode || N == 0 || N > Buffer.size() - Done)
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
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_write_some(
                    AsBytes(Data.subspan(Done)),
                    ErrorCode);
                if (ErrorCode)
                {
                    co_return true;
                }
                if (N == 0 || N > Data.size() - Done)
                {
                    co_return true;
                }
                Done += N;
            }
            co_return false;
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
    };

    /// 流连接共享指针（默认内存策略）
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Shadowtls
