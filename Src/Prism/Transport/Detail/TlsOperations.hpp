/** @file TlsOperations.hpp @brief 固定Asio 1.89 SSL engine操作；保留字节并只发送本端close_notify。 */
#pragma once
#include <boost/asio/ssl/detail/engine.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/detail/buffer_sequence_adapter.hpp>
#include <openssl/err.h>
namespace Prism::Transport::Detail
{
    namespace SslDetail = boost::asio::ssl::detail;
    /**
     * @brief Asio ssl::detail 的数据面操作：保留 engine 实际写入用户缓冲的字节计数。
     * @details 输入所有权：构造把 buffer 序列按值移入 Buffers_（:28，成员 :50），只拥有序列对象本身，
     *          不拥有它指向的字节，因此借用止于本次 completion；Bytes_（:51）保存 engine 报告的计数（:43）。
     *          输出与错误：call_handler（:47-:48）交付的是自己保存的 Bytes_，而不是 io_op 归零后的 Count，
     *          因此错误时已写入/已读出的字节不丢失；Reading 是编译期开关，选择 Engine.read 或
     *          Engine.write（:35-:36、:40-:41）。
     *          取消：本类型无取消入口，也不持有 cancellation slot；取消由发起它的 TlsStream 状态机处理。
     *          半关闭：不适用，数据面操作不改变任何传输方向；写半关闭由 TlsWriteShutdownOperation 执行。
     *          最终关闭者：不适用，本类型只借用传入的 engine 引用（:30），既不拥有 engine 也不拥有 socket。
     *          executor：本类型不声明执行域；执行域由发起 async_io 的 TlsEngine strand 固定。
     * @note 未定义：读写都只取序列的第一个 buffer（:35、:40 的 buffer_sequence_adapter::first），其余
     *       缓冲区被静默忽略；该形状限制是代码事实，是否允许整段序列须由契约收口卡决定，本卡不改代码。
     */
    template<class Buffers, bool Reading>
    class TlsDataOperation final
    {
    public:
        explicit TlsDataOperation(Buffers Input) : Buffers_(std::move(Input)) {}
        [[nodiscard]] static constexpr auto tracking_name() -> const char* { return "Prism::TlsDataOperation"; }
        auto operator()(SslDetail::engine& Engine, boost::system::error_code& Error, std::size_t& Count) -> SslDetail::engine::want
        {
            SslDetail::engine::want Want;
            if constexpr (Reading)
            {
                auto Buffer = boost::asio::detail::buffer_sequence_adapter<boost::asio::mutable_buffer, Buffers>::first(Buffers_);
                Want = Engine.read(Buffer, Error, Count);
            }
            else
            {
                auto Buffer = boost::asio::detail::buffer_sequence_adapter<boost::asio::const_buffer, Buffers>::first(Buffers_);
                Want = Engine.write(Buffer, Error, Count);
            }
            Bytes_ = Count;
            return Want;
        }
        template<class Handler>
        auto call_handler(Handler& Callback, const boost::system::error_code& Error, const std::size_t&) const -> void
        { std::move(Callback)(Error, Bytes_); }
    private:
        Buffers Buffers_;
        std::size_t Bytes_{0};
    };
    /**
     * @brief 只发送本端 close_notify 的 SSL 写半关闭操作，无状态且可重复判定。
     * @details 输入所有权：无数据成员，operator() 为 const（:73），只借用传入的 engine 取其裸 SSL*（:76），
     *          不拥有 engine、不拥有 socket，也不接管任何 buffer。
     *          输出与错误：Bytes 先归零（:75）；错误只在终态分支写入（:88-:92），依次是原生 ERR_get_error、
     *          ZERO_RETURN→eof、SYSCALL→unspecified_system_error、其余 unexpected_result；
     *          call_handler（:96-:97）只交付 error_code，与 async_write_shutdown 的单参数签名一致。
     *          取消：本类型无取消入口；已发送过 close_notify 时直接 want_nothing（:77），故重复请求幂等。
     *          半关闭：本类型就是写半关闭的实现点——SSL_shutdown（:79）后要求 flush 本端输出（:80），
     *          WANT_WRITE 时重试输出（:82）；读方向不在本类型里关闭。
     *          最终关闭者：不适用，本类型只发通知，描述符的最终 close 属于 leaf 载体（Reliable.hpp:80）。
     *          executor：不声明执行域，由 TlsEngine 的 strand 上的 async_io 推进（TlsEngine 的 Launch）。
     * @note 未定义：SSL_ERROR_WANT_READ 分支在尚未 SENT_SHUTDOWN 时返回 want_input_and_retry（:85-:86），
     *       即把「继续读取对端」交回 Asio，与本文件 :1 的文件级 @brief「绝不等待 peer FIN」的措辞并不等价；
     *       调用方不喂入输入时该操作停在 engine 队列，此差异须由后续卡判定，本卡不改代码。
     */
    class TlsWriteShutdownOperation final
    {
    public:
        [[nodiscard]] static constexpr auto tracking_name() -> const char* { return "Prism::TlsWriteShutdown"; }
        auto operator()(SslDetail::engine& Engine, boost::system::error_code& Error, std::size_t& Bytes) const -> SslDetail::engine::want
        {
            Bytes = 0;
            auto* Ssl = Engine.native_handle();
            if ((SSL_get_shutdown(Ssl) & SSL_SENT_SHUTDOWN) != 0) return SslDetail::engine::want_nothing;
            ERR_clear_error();
            const auto Result = SSL_shutdown(Ssl);
            if (Result >= 0) return SslDetail::engine::want_output;
            const auto Reason = SSL_get_error(Ssl, Result);
            if (Reason == SSL_ERROR_WANT_WRITE) return SslDetail::engine::want_output_and_retry;
            if (Reason == SSL_ERROR_WANT_READ)
            {
                if ((SSL_get_shutdown(Ssl) & SSL_SENT_SHUTDOWN) != 0) return SslDetail::engine::want_output;
                return SslDetail::engine::want_input_and_retry;
            }
            const auto Native = ERR_get_error();
            if (Native != 0) Error = {static_cast<int>(Native), boost::asio::error::get_ssl_category()};
            else if (Reason == SSL_ERROR_ZERO_RETURN) Error = boost::asio::error::eof;
            else if (Reason == SSL_ERROR_SYSCALL) Error = boost::asio::ssl::error::unspecified_system_error;
            else Error = boost::asio::ssl::error::unexpected_result;
            return SslDetail::engine::want_nothing;
        }
        template<class Handler>
        auto call_handler(Handler& Callback, const boost::system::error_code& Error, const std::size_t&) const -> void
        { std::move(Callback)(Error); }
    };
}
