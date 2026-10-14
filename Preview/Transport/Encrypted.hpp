/** @file Encrypted.hpp @brief TLS读和有界完整writer，共享唯一engine与真实完成源。 */
#pragma once
#include <Preview/Transport/Writer.hpp>
#include <Preview/Transport/Detail/TlsWriteDriver.hpp>
#include <Preview/Transport/Detail/ActivityGroup.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <boost/asio/ssl/error.hpp>
#include <openssl/ssl.h>
#include <cstdint>
#include <string>
namespace Preview::Transport
{
    /**
     * @brief 拥有 TLS engine 视图与有界完整 writer 的传输装饰层，读直连 engine、写经唯一 writer 串行。
     * @details 输入所有权：构造移交 SharedStream 的共享所有权并把 BytePool 移交给内部 Writer；
     *          读 span 借用到 completion 由 engine 直接消费，写 span 借用到 Writer 的 completion（其间
     *          Writer 只额外拥有自己的 64KiB 块）。ReleaseStream() 成功后本层不再拥有任何实物。
     *          HandshakeRequest 中 Inbound 与 Bytes 为移交所有权，Context 只是引用包装——调用方必须
     *          保活 ssl::context 到握手返回，engine 不拥有 SSL_CTX；Deadline 是绝对期限而非新的完整超时。
     *          输出与错误：SslHandshake 返回 HandshakeResult，成功只填 Stream 与 Bytes，失败填 Failure 并
     *          按情况交回 Recovered 或 Stream；TLS 类别折叠为 TlsHsfail、证书校验失败为 Verifyfail、
     *          deadline 到期为 Timeout（保留 native）、其余底层错误由 FromNative 保留 Native，取消仍由
     *          前门以 Canceled 交付，EOF 与底层错误四类互不折叠。
     *          取消：OnCancel 转交 Writer 的取消，封止整个写序列并只取消当前 active 原生写，pending 请求
     *          各自完成一次；重复 Cancel 由 Writer/Transmission 的命令预约保证不产生第二份完成。
     *          半关闭：StartWriteShutdown 经 Writer 排在所有先前 ticket 之后，只发送本端 close_notify 并
     *          保留反向读取能力，不下发裸 TCP FIN，也不等待对端 shutdown。
     *          最终关闭者：OnClose 返回 Writer::Close()，Writer 在全部 native 写回调真正退出后才向 driver
     *          下发 Close，driver 再转交底层 Transmission；裸描述符的最终关闭者始终是 leaf 载体，本层 Close
     *          成功只证明命令已被接管，实际退出须等待 Activity()->Drain()（先本层，再 Writer 与 engine）。
     *          executor：冷构造固定 Stream->get_executor() 为原域；engine（stream_core）状态只在 TlsStream
     *          自身 strand 上变更，Writer 的 ticket 序列在其上另建的 strand 上执行，两者同属一个 io_context
     *          但为不同 strand 对象，要求单一执行域装配；握手协程在调用方 executor 上恢复。
     * @note 未定义：超时并不证明原生操作已消失，Blocked 时 HandshakeResult 仍保留实物；严格墙钟关闭上限
     *       与跨 strand 并发排他性均无可指出的证明，留待 M13 之后的构建与运行验收决定。
     */
    class Encrypted final : public Transmission
    {
    public:
        using StreamType = Detail::TlsStream;
        using SharedStream = std::shared_ptr<StreamType>;
        static constexpr auto DefaultHandshakeTimeout = std::chrono::seconds(30);
        struct NegotiatedTlsInfo final
        {
            std::string ServerName;
            std::string Alpn;
            std::string Version;
            bool EchAccepted{false};
        };
        enum class HandshakeRole : std::uint8_t
        {
            Server,
            Client,
        };
        struct HandshakeResult final
        {
            Fault::Failure Failure;
            SharedStream Stream;
            SharedTransmission Recovered;
            std::shared_ptr<Memory::BytePool> Bytes;
            NegotiatedTlsInfo Negotiated;
        };
        struct HandshakeRequest final
        {
            SharedTransmission Inbound;
            std::reference_wrapper<Net::ssl::context> Context;
            std::chrono::steady_clock::time_point Deadline{std::chrono::steady_clock::now() + DefaultHandshakeTimeout};
            std::shared_ptr<Memory::BytePool> Bytes;
            HandshakeRole Role{HandshakeRole::Server};
            std::string ServerName;
        };
        /** @brief 冷构造显式使用worker真实池；不建每连接4MiB池或隐式全局回退。 */
        Encrypted(SharedStream Stream, std::shared_ptr<Memory::BytePool> Bytes)
            : Transmission(Stream->get_executor()), Stream_(std::move(Stream)),
              Writer_(std::make_shared<Writer>(std::move(Bytes), std::make_shared<Detail::TlsWriteDriver>(Stream_))),
              Activity_(std::make_shared<Detail::ActivityGroup>(Transmission::Activity(),
                  std::vector<std::shared_ptr<Contract::CarrierActivity>>{Writer_->Activity(), Stream_->Activity()})) {}
        [[nodiscard]] auto Activity() const noexcept -> std::shared_ptr<Contract::CarrierActivity> override { if (Activity_) return Activity_; return Transmission::Activity(); }
        [[nodiscard]] auto NextLayer() noexcept -> Transmission* override { if (!Stream_) return nullptr; return Stream_->next_layer().NextLayer(); }
        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission* override { if (!Stream_) return nullptr; return Stream_->next_layer().NextLayer(); }
        [[nodiscard]] auto Stream() noexcept -> StreamType& { return *Stream_; }
        [[nodiscard]] auto Stream() const noexcept -> const StreamType& { return *Stream_; }
        /** @brief 原域停止全部发起者后的排他冷移交；任何真实预约未退出时拒绝且保留实物。 */
        [[nodiscard]] auto ReleaseStream() -> std::expected<SharedStream, Fault::Failure>
        {
            if (!Stream_) return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
            if (!IoIdle() || !Writer_->IsIdle() || !Stream_->IsIdle())
                return std::unexpected(Fault::Failure{Fault::Code::WouldBlock});
            auto Result = std::move(Stream_);
            Writer_.reset(); Activity_.reset();
            return Result;
        }
        [[nodiscard]] static auto SslHandshake(HandshakeRequest Request) -> Net::awaitable<HandshakeResult>;
    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        { if (!Stream_) { Detail::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
          Stream_->ReadSome(Buffer, std::move(Handler)); }
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        { if (!Stream_) { Detail::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
          Writer_->Write(Buffer, std::move(Handler)); }
        auto StartWriteShutdown(Completion Handler) -> void override
        { if (!Stream_) { Detail::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
          Writer_->WriteShutdown(std::move(Handler)); }
        [[nodiscard]] auto OnClose() -> ControlResult override { if (!Stream_) return {}; return Writer_->Close(); }
        [[nodiscard]] auto OnCancel() -> ControlResult override { if (!Stream_) return {}; return Writer_->Cancel(); }
    private:
        [[nodiscard]] static auto HandshakeFailure(const SharedStream& Stream, boost::system::error_code Error) -> Fault::Failure
        {
            auto Failure = Fault::FromNative(static_cast<std::error_code>(Error));
            if (Error.category() == Net::error::get_ssl_category() || Error.category() == Net::ssl::error::get_stream_category())
            {
                Failure.Code = Fault::Code::TlsHsfail;
                if (SSL_get_verify_result(Stream->native_handle()) != X509_V_OK) Failure.Code = Fault::Code::Verifyfail;
            }
            return Failure;
        }
        [[nodiscard]] static auto ReadNegotiatedTlsInfo(const SharedStream& Stream)
            -> NegotiatedTlsInfo
        {
            NegotiatedTlsInfo Result;
            const auto* Tls = Stream->native_handle();
            if (const auto* ServerName = SSL_get_servername(Tls, TLSEXT_NAMETYPE_host_name))
            {
                Result.ServerName = ServerName;
            }
            const std::uint8_t* Alpn = nullptr;
            unsigned AlpnLength = 0;
            SSL_get0_alpn_selected(Tls, &Alpn, &AlpnLength);
            if (Alpn && AlpnLength != 0)
            {
                Result.Alpn.assign(reinterpret_cast<const char*>(Alpn), AlpnLength);
            }
            if (const auto* Version = SSL_get_version(Tls))
            {
                Result.Version = Version;
            }
            Result.EchAccepted = SSL_ech_accepted(Tls) == 1;
            return Result;
        }
        SharedStream Stream_;
        std::shared_ptr<Writer> Writer_;
        std::shared_ptr<Detail::ActivityGroup> Activity_;
    };
    [[nodiscard]] inline auto MakeEncrypted(Encrypted::SharedStream Stream, std::shared_ptr<Memory::BytePool> Bytes) -> SharedTransmission
    { return std::make_shared<Encrypted>(std::move(Stream), std::move(Bytes)); }
    inline auto Encrypted::SslHandshake(HandshakeRequest Request) -> Net::awaitable<HandshakeResult>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        HandshakeResult Result;
        Result.Bytes = std::move(Request.Bytes);
        if (!Request.Inbound || !Result.Bytes)
        { Result.Failure = {Fault::Code::InvalidArgument}; Result.Recovered = std::move(Request.Inbound); co_return Result; }
        if (Request.Deadline <= std::chrono::steady_clock::now())
        { Result.Failure = {Fault::Code::Timeout}; Result.Recovered = std::move(Request.Inbound); co_return Result; }
        auto Stream = std::make_shared<StreamType>(Connector(std::move(Request.Inbound)), Request.Context.get());
        if (Request.Role == HandshakeRole::Client && !Request.ServerName.empty() &&
            SSL_set_tlsext_host_name(Stream->native_handle(), Request.ServerName.c_str()) != 1)
        {
            Result.Failure = {Fault::Code::InvalidArgument};
            Result.Recovered = Stream->next_layer().Release();
            co_return Result;
        }
        if (Request.Role == HandshakeRole::Server && !Request.ServerName.empty())
        {
            Result.Failure = {Fault::Code::InvalidArgument};
            Result.Recovered = Stream->next_layer().Release();
            co_return Result;
        }
        Net::steady_timer Deadline(Stream->get_executor());
        Deadline.expires_at(Request.Deadline);
        const auto HandshakeType = Request.Role == HandshakeRole::Server
                                       ? Net::ssl::stream_base::server
                                       : Net::ssl::stream_base::client;
        auto [Order, Error, TimerError] = co_await Net::experimental::make_parallel_group(
            Stream->async_handshake(HandshakeType, Net::deferred), Deadline.async_wait(Net::deferred))
            .async_wait(Net::experimental::wait_for_one(), Net::use_awaitable);
        if (Error) Result.Failure = HandshakeFailure(Stream, Error);
        if (Order[0] == 1 && !TimerError) Result.Failure.Code = Fault::Code::Timeout;
        if (Result.Failure.Succeeded())
        {
            Result.Negotiated = ReadNegotiatedTlsInfo(Stream);
            Result.Stream = std::move(Stream);
            co_return Result;
        }
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        const auto Drained = co_await Stream->Activity()->Drain();
        if (!Drained)
        { Result.Failure = Drained.error(); Result.Stream = std::move(Stream); co_return Result; }
        Result.Recovered = Stream->next_layer().Release();
        co_return Result;
    }
}
