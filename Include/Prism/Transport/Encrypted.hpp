/** @file Encrypted.hpp @brief TLS读和有界完整writer，共享唯一engine与真实完成源。 */
#pragma once
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Transport/TlsStream.hpp>
#include <Prism/Transport/Writer.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <string>

#include <boost/asio/ssl/context.hpp>
#include <boost/system/error_code.hpp>

namespace Prism::Transport
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
        using StreamType = Prism::Transport::TlsStream;
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
        Encrypted(SharedStream Stream, std::shared_ptr<Memory::BytePool> Bytes);
        [[nodiscard]] auto Activity() const noexcept -> std::shared_ptr<Contract::CarrierActivity> override;
        [[nodiscard]] auto NextLayer() noexcept -> Transmission* override;
        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission* override;
        [[nodiscard]] auto Stream() noexcept -> StreamType&;
        [[nodiscard]] auto Stream() const noexcept -> const StreamType&;
        /** @brief 原域停止全部发起者后的排他冷移交；任何真实预约未退出时拒绝且保留实物。 */
        [[nodiscard]] auto ReleaseStream() -> std::expected<SharedStream, Fault::Failure>;
        [[nodiscard]] static auto SslHandshake(HandshakeRequest Request) -> Net::awaitable<HandshakeResult>;
    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override;
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override;
        auto StartWriteShutdown(Completion Handler) -> void override;
        [[nodiscard]] auto OnClose() -> ControlResult override;
        [[nodiscard]] auto OnCancel() -> ControlResult override;
    private:
        [[nodiscard]] static auto HandshakeFailure(
            const SharedStream &Stream, boost::system::error_code Error) -> Fault::Failure;
        [[nodiscard]] static auto ReadNegotiatedTlsInfo(const SharedStream &Stream)
            -> NegotiatedTlsInfo;
        SharedStream Stream_;
        std::shared_ptr<Writer> Writer_;
        std::shared_ptr<Contract::CarrierActivity> Activity_;
    };
    [[nodiscard]] auto MakeEncrypted(Encrypted::SharedStream Stream,
                                     std::shared_ptr<Memory::BytePool> Bytes)
        -> SharedTransmission;
}
