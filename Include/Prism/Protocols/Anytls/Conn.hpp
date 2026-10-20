/**
 * @file Conn.hpp
 * @brief AnyTLS 会话连接对象（Transmission 装饰器）
 * @details 将底层传输包装为 AnyTLS 连接（对齐 mihomo transport/anytls）：
 * 1. WriteHandshake：发送认证帧 [SHA-256(password)][padlen][padding]
 * 2. ReadHandshake：服务端读取认证帧并校验密码哈希
 * 3. 数据面：内部多路复用（Session 帧），测试库简化透传
 * @note 与 anytls.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once
#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Anytls/Codec.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Anytls
{

    namespace Net = boost::asio;

    /**
     * @class Conn
     * @brief AnyTLS 会话连接（Transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后数据面透传。
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
         */
        explicit Conn(SharedTransmission Upstream, std::string Password)
            : Prism::Transmission(Upstream ? Upstream->Executor() : Net::any_io_executor{}),
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
         * @brief 客户端握手：发送认证帧
         * @param PadLen Padding 长度（默认 16）
         * @return 失败类别与原生 I/O cause；成功表示完整认证帧已写出
         * @details Password 与帧只在本次协程内借用；partial write 按实际字节推进，失败时
         *          保留首个 Fault::Failure。取消仍由底层 Transmission 交付，最终关闭由工厂 owner 负责。
         */
        [[nodiscard]] auto WriteHandshake(std::uint16_t PadLen = 16)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!NextLayer_)
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError});
            }
            Handshaken_ = false;
            std::string Frame;
            try
            {
                const auto Err = BuildAuthFrame(Password_, PadLen, Frame);
                if (Err != Error::None)
                {
                    co_return std::unexpected(ProtocolFailure(Err));
                }
            }
            catch (const std::bad_alloc &)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
            }
            const auto Sent = co_await SendBytes(AsU8Span(Frame));
            if (!Sent) co_return std::unexpected(Sent.error());
            Handshaken_ = true;
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        /**
         * @brief 服务端握手：读取并校验认证帧
         * @return 失败类别与原生 I/O cause；成功表示密码哈希通过
         * @details 每次 partial read 按实际字节推进；EOF、取消和底层原生错误保持独立。
         *          失败帧由外层工厂的唯一 retirement owner 取消、关闭并等待真实 Activity 退栈。
         */
        [[nodiscard]] auto ReadHandshake()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!NextLayer_)
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError});
            }
            Handshaken_ = false;
            // 头：Hash(32) + PadLen(2 BE)
            std::array<std::uint8_t, AuthFrameHdrlen> Header{};
            const auto HeaderRead = co_await ReadExact(std::span<std::uint8_t>(Header));
            if (!HeaderRead) co_return std::unexpected(HeaderRead.error());
            std::array<std::uint8_t, PasswordHashLen> Hash{};
            std::memcpy(Hash.data(), Header.data(), PasswordHashLen);
            const auto PadLen = static_cast<std::uint16_t>(Header[PasswordHashLen]) << 8 |
                                 Header[PasswordHashLen + 1];
            if (PadLen > 0)
            {
                try
                {
                    std::vector<std::uint8_t> Padding(PadLen);
                    const auto PaddingRead = co_await ReadExact(Padding);
                    if (!PaddingRead) co_return std::unexpected(PaddingRead.error());
                }
                catch (const std::bad_alloc &)
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
                }
            }
            if (!VerifyAuth(Password_, Hash))
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::AuthFailed});
            }
            Handshaken_ = true;
            co_return std::expected<void, Prism::Fault::Failure>{};
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
                Prism::Transmission::PostResult(
                    Executor(),
                    std::move(Handler),
                    Prism::IoResult{0, Prism::Fault::FromNative(make_error_code(Error::NotOpen))});
                return;
            }
            if (ReadTerminal_)
            {
                Prism::Transmission::PostResult(
                    Executor(), std::move(Handler), Prism::IoResult{0, *ReadTerminal_});
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
                Prism::Transmission::PostResult(
                    Executor(),
                    std::move(Handler),
                    Prism::IoResult{0, Prism::Fault::FromNative(make_error_code(Error::NotOpen))});
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
                Prism::Transmission::PostResult(
                    Executor(),
                    std::move(Handler),
                    Prism::IoResult{0, Prism::Fault::FromNative(make_error_code(Error::NotOpen))});
                return;
            }
            NextLayer_->WriteShutdown(std::move(Handler));
        }

        /**
         * @brief 封止并交付底层关闭
         * @return 命令接管成功；实际退出由 Activity()->Drain() 另行等待。
         */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
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
        /** @brief 按实际字节推进精确读取，失败保留 typed/native cause。 */
        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> Buffer)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (ReadTerminal_)
            {
                co_return std::unexpected(*ReadTerminal_);
            }
            if (!NextLayer_)
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError});
            }
            std::size_t Done = 0;
            while (Done < Buffer.size())
            {
                const auto Part = co_await NextLayer_->ReadSome(
                    AsBytes(Buffer.subspan(Done)));
                const auto N = Part.Bytes;
                if (N > Buffer.size() - Done)
                {
                    co_return std::unexpected(Prism::Fault::Failure{
                        Prism::Fault::Code::InvalidArgument, Part.Failure.Native});
                }
                Done += N;
                if (Part.Failure.Failed())
                {
                    ReadTerminal_ = Part.Failure;
                    if (Done == Buffer.size())
                    {
                        co_return std::expected<void, Prism::Fault::Failure>{};
                    }
                    co_return std::unexpected(*ReadTerminal_);
                }
                if (N == 0)
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
                }
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        /** @brief 按实际字节推进完整发送，partial write 失败保留 typed/native cause。 */
        [[nodiscard]] auto SendBytes(std::span<const std::uint8_t> Data) const
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!NextLayer_)
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError});
            }
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                const auto Part = co_await NextLayer_->WriteSome(
                    AsBytes(Data.subspan(Done)));
                const auto N = Part.Bytes;
                if (N > Data.size() - Done)
                {
                    co_return std::unexpected(Prism::Fault::Failure{
                        Prism::Fault::Code::InvalidArgument, Part.Failure.Native});
                }
                Done += N;
                if (Part.Failure.Failed())
                {
                    co_return std::unexpected(Part.Failure);
                }
                if (N == 0)
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
                }
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        /** @brief 把旧 codec 错误在唯一 AnyTLS 握手边界投影到正式 Fault 值。 */
        [[nodiscard]] static auto ProtocolFailure(const Error Value) noexcept
            -> Prism::Fault::Failure
        {
            const auto Native = static_cast<std::error_code>(Prism::make_error_code(Value));
            return {Prism::Fault::ToCode(Native), {}};
        }

        SharedTransmission NextLayer_;  ///< 底层传输（独占所有权）
        std::string Password_;            ///< 认证密码
        bool Handshaken_{false};          ///< 握手完成标志
        std::optional<Prism::Fault::Failure> ReadTerminal_{}; ///< 握手字节后的 sticky 读终态
    };

    /// 流连接共享指针（默认内存策略）
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Prism::TransmissionLike<Conn<>>);

} // namespace Prism::Anytls
