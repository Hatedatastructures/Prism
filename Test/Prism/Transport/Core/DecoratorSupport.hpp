/**
 * @file DecoratorSupport.hpp
 * @brief TransportDecoratorCoverage.cpp 拆分后的模块共享测试夹具与构造辅助。
 */
#pragma once

/**
 * @file TransportDecoratorCoverage.cpp
 * @brief Prism/Transport/ 装饰器模块覆盖率测试
 * @details 覆盖八个传输装饰器/叶子模块：
 * - PadTransport：填充启用/禁用、最小/最大边界、数据透传、大块透传兜底、
 *   随机填充确定性（不破坏数据）、StopAfter 透传
 * - PreviewTransport：预读字节优先返回、耗尽后透传底层、EOF、WrapWithPreview
 * - Snapshot：捕获/回滚重放、回滚后继续读取、写入后禁止回滚
 * - Reliable：真实 TCP 读满/写满、EOF、对端关闭写错误、错误中断返回已读字节
 * - Encrypted：内存管道上的真实 TLS 握手 + 加解密往返、握手失败恢复、
 *   null 入站、访问器/关闭/取消
 * - Connector：预读注入、委托底层、移动语义、Release、成员 AsyncRead/Write
 * - Unreliable：UDP 往返、未设远程写错误、来源过滤、访问器
 * - Unreliable：往返、未打开写/读错误、Close/Cancel
 * @note 底层一律使用 MemoryStream（MakeMemoryPair）或真实 loopback socket。
 */

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <Prism/Transport/Transmission.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <future>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Transport/Connector.hpp>
#include <Prism/Transport/Encrypted.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Pad.hpp>
#include <Prism/Transport/Preview.hpp>
#include <Prism/Transport/Reliable.hpp>
#include <Prism/Transport/Replay.hpp>
#include <Prism/Transport/Unreliable.hpp>
#include <TestSupport/Prism/MockTransport.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Ssl = Net::ssl;
    using Encrypted = Prism::Transport::Encrypted;
    using boost::asio::experimental::awaitable_operators::operator&&;

    /**
     * @brief 驱动协程运行，异常透传
     * @param ioc io_context
     * @param coro 协程
     */
    template <typename A>
    auto RunCoro(Net::io_context &Ioc, A Coro) -> void
    {
        Ioc.restart();
        std::exception_ptr Exception;
        Net::co_spawn(Ioc, std::move(Coro),
                      [&](std::exception_ptr Error)
                      {
                          Exception = Error;

                      });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    class InlineWriteTransport final : public Prism::Transmission
    {
    public:
        explicit InlineWriteTransport(Net::any_io_executor Ex) : Prism::Transmission(Ex), Ex_(std::move(Ex))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Ex_;
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_;
        }

        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            std::error_code Ec;
            Ec = std::make_error_code(std::errc::operation_canceled);
            { std::move(Handler)(Prism::IoResult{0, Prism::Fault::FromNative(Ec)}); return; }
        }



        auto StartWrite(
            std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            ++CurrentDepth_;
            MaxDepth = std::max(MaxDepth, CurrentDepth_);
            std::size_t Count = 1;
            if (Buffer.empty())
            {
                Count = 0;
            }
            std::move(Handler)(Prism::IoResult{Count, {}});
            --CurrentDepth_;
        }

        auto OnClose() -> ControlResult override
        {
            Closed_ = true;

            return {};
        }

        auto OnCancel() -> ControlResult override
        {

            return {};
        }

        std::size_t MaxDepth{0};

    private:
        Net::any_io_executor Ex_;
        std::size_t CurrentDepth_{0};
        bool Closed_{false};

        /** @brief 测试替身显式兑现半关闭；装饰器沿实际inner转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer()) { Inner->WriteShutdown(std::move(Handler)); return; }
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {});
        }
    };

    /**
     * @brief 捕获写入字节的内存 sink（pad 测试用）
     */
    class FakeSink final : public Prism::Transmission
    {
    public:
        explicit FakeSink(Net::any_io_executor Ex) : Prism::Transmission(Ex), Ex_(std::move(Ex))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            std::error_code OperationFailure;
            OperationFailure.clear();
            { std::move(Handler)(Prism::IoResult{0, Prism::Fault::FromNative(OperationFailure)}); return; }
        }

        auto StartWrite(std::span<const std::byte> IoBuffer, Completion Handler) -> void override
        {
            std::error_code OperationFailure;
            OperationFailure.clear();
            Written_.insert(Written_.end(), IoBuffer.begin(), IoBuffer.end());
            { std::move(Handler)(Prism::IoResult{IoBuffer.size(), Prism::Fault::FromNative(OperationFailure)}); return; }
        }

        auto OnClose() -> ControlResult override
        {

            return {};
        }

        auto OnCancel() -> ControlResult override
        {

            return {};
        }

        std::vector<std::byte> Written_; ///< 捕获的写入字节

    private:
        Net::any_io_executor Ex_;

        /** @brief 测试替身显式兑现半关闭；装饰器沿实际inner转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer()) { Inner->WriteShutdown(std::move(Handler)); return; }
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {});
        }
    };

    /**
     * @brief 可编程行为 mock（Reliable 组合操作错误路径用）
     */
    class ProgrammableMock final : public Prism::Transmission
    {
    public:
        explicit ProgrammableMock(Net::any_io_executor Ex) : Prism::Transmission(Ex), Ex_(std::move(Ex))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            std::error_code OperationFailure;
            if (ReadCalls_++ == 0)
            {
                OperationFailure.clear();
                { std::move(Handler)(Prism::IoResult{ReadFirstN_, Prism::Fault::FromNative(OperationFailure)}); return; }
            }
            OperationFailure = ReadEc_;
            { std::move(Handler)(Prism::IoResult{0, Prism::Fault::FromNative(OperationFailure)}); return; }
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            std::error_code OperationFailure;
            OperationFailure.clear();
            { std::move(Handler)(Prism::IoResult{WriteN_, Prism::Fault::FromNative(OperationFailure)}); return; }
        }

        auto OnClose() -> ControlResult override
        {

            return {};
        }

        auto OnCancel() -> ControlResult override
        {

            return {};
        }

        std::size_t ReadFirstN_{0};  ///< 首次读返回字节数
        std::error_code ReadEc_{};    ///< 后续读错误
        std::size_t WriteN_{0};       ///< 每次写返回字节数

    private:
        Net::any_io_executor Ex_;
        std::size_t ReadCalls_{0};

        /** @brief 测试替身显式兑现半关闭；装饰器沿实际inner转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer()) { Inner->WriteShutdown(std::move(Handler)); return; }
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {});
        }
    };

    class PartialErrorMock final : public Prism::Transmission
    {
    public:
        explicit PartialErrorMock(Net::any_io_executor Ex) : Prism::Transmission(Ex), Ex_(std::move(Ex)) {}

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            std::error_code Error;
            if (Read_)
            {
                Error = std::make_error_code(std::errc::connection_reset);
                { std::move(Handler)(Prism::IoResult{0, Prism::Fault::FromNative(Error)}); return; }
            }
            Read_ = true;
            const auto Count = (std::min)(Buffer.size(), Payload_.size());
            std::copy(Payload_.begin(), Payload_.begin() + static_cast<std::ptrdiff_t>(Count), Buffer.begin());
            Error = std::make_error_code(std::errc::connection_reset);
            { std::move(Handler)(Prism::IoResult{Count, Prism::Fault::FromNative(Error)}); return; }
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            std::error_code Error;
            Error.clear();
            { std::move(Handler)(Prism::IoResult{Buffer.size(), Prism::Fault::FromNative(Error)}); return; }
        }

        auto OnClose() -> ControlResult override
        {
            return {};
        }
        auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        Net::any_io_executor Ex_;
        std::array<std::byte, 3> Payload_{std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
        bool Read_{false};

        /** @brief 测试替身显式兑现半关闭；装饰器沿实际inner转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer()) { Inner->WriteShutdown(std::move(Handler)); return; }
            Prism::Transmission::PostResult(Executor(), std::move(Handler), {});
        }
    };

    /**
     * @brief 生成自签名证书并加载到服务端 SSL 上下文
     * @details RSA 2048 而非 Ed25519，避免 BoringSSL TLS 1.3
     * "NO_COMMON_SIGNATURE_ALGORITHMS" 错误
     * @param ctx 目标上下文
     */
    auto LoadSelfSignedCert(Ssl::context &Context) -> void
    {
        auto *PrivateKey = EVP_PKEY_new();
        auto *Exponent = BN_new();
        BN_set_word(Exponent, RSA_F4);
        auto *RsaKey = RSA_new();
        RSA_generate_key_ex(RsaKey, 2048, Exponent, nullptr);
        EVP_PKEY_assign_RSA(PrivateKey, RsaKey);
        BN_free(Exponent);

        auto *Certificate = X509_new();
        X509_set_version(Certificate, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(Certificate), 1);
        X509_gmtime_adj(X509_get_notBefore(Certificate), 0);
        X509_gmtime_adj(X509_get_notAfter(Certificate), 3600 * 24);

        auto *Name = X509_NAME_new();
        X509_NAME_add_entry_by_txt(Name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("Test"),
                                   -1, -1, 0);
        X509_set_subject_name(Certificate, Name);
        X509_set_issuer_name(Certificate, Name);
        X509_NAME_free(Name);

        X509_set_pubkey(Certificate, PrivateKey);
        X509_sign(Certificate, PrivateKey, EVP_sha256());

        SSL_CTX_use_certificate(Context.native_handle(), Certificate);
        SSL_CTX_use_PrivateKey(Context.native_handle(), PrivateKey);

        X509_free(Certificate);
        EVP_PKEY_free(PrivateKey);
    }

    /**
     * @brief 将 string_view 转为 byte span
     * @param s 源数据
     * @return byte span
     */
    [[nodiscard]] auto SvBytes(std::string_view Data) -> std::span<const std::byte>
    {
        return Prism::AsBytesSpan(Data);
    }

    // ══════════════════════ PadTransport ══════════════════════









    // ══════════════════════ PreviewTransport ══════════════════════






    // ══════════════════════ Snapshot ══════════════════════







    // ══════════════════════ Encrypted ══════════════════════





    // ══════════════════════ Connector ══════════════════════









    // ══════════════════════ Reliable ══════════════════════







    // ══════════════════════ Unreliable ══════════════════════






    // ══════════════════════ Unreliable ══════════════════════




} // namespace

