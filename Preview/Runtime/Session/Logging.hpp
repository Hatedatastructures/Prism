/** @file Logging.hpp
 * @brief 会话观察使用的无分配文本与 metadata helper。
 */
#pragma once
#include <Preview/Runtime/Session/LogState.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Runtime/Recognition/Recognition.hpp>
#include <Preview/Transport/NativeTls.hpp>
#include <Preview/Foundation/Utility/Text/FixedText.hpp>
#include <boost/asio/ssl/error.hpp>
#include <openssl/err.h>
#include <string_view>
#include <system_error>
#include <type_traits>

namespace Preview::Runtime::SessionSupport
{
    /** @brief 从稳定错误事实分类，不在请求线程创建 Native message 字符串。 */
    template <typename NativeCode>
        requires(std::is_same_v<NativeCode, boost::system::error_code> || std::is_same_v<NativeCode, std::error_code>)
    [[nodiscard]] inline auto ClassifyCarrierFailure(const Preview::Fault::Code Code,
        const NativeCode& NativeError) noexcept -> std::string_view
    {
        if (Code == Preview::Fault::Code::Timeout) { return "tls_handshake_timeout"; }
        if (Code == Preview::Fault::Code::Canceled) { return "cancelled"; }
        if (Code == Preview::Fault::Code::Verifyfail || Code == Preview::Fault::Code::Certfail)
        {
            return "certificate_error";
        }
        if (Code == Preview::Fault::Code::AuthFailed) { return "carrier_auth_failed"; }
        if (Code == Preview::Fault::Code::NotSupported) { return "wire_unavailable"; }
        if (Code == Preview::Fault::Code::TlsHsfail) { return "tls_alert"; }
        if constexpr (std::is_same_v<NativeCode, boost::system::error_code>)
        {
            if (&NativeError.category() != &boost::asio::error::get_ssl_category()) { return "carrier_commit_failed"; }
        }
        else
        {
            // 正式 TLS producer 已把 SSL/验证失败映射到上述领域码；Native 只保留原生原因。
            // 不在观察热路径再创建 Boost→std category adapter 或猜测分类。
            return "carrier_commit_failed";
        }
        if (const auto* Text = ERR_reason_error_string(static_cast<unsigned long>(NativeError.value())))
        {
            const std::string_view Reason(Text);
            if (Reason.find("certificate") != Reason.npos || Reason.find("CERTIFICATE") != Reason.npos ||
                Reason.find("unknown ca") != Reason.npos || Reason.find("UNKNOWN_CA") != Reason.npos)
            {
                return "certificate_error";
            }
        }
        return "tls_alert";
    }
    [[nodiscard]] inline auto ClassifyNativeTlsFailure(const Preview::Transport::NativeTlsResult& Result)
        noexcept -> std::string_view
    {
        return ClassifyCarrierFailure(Result.Failure.Code, Result.Failure.Native);
    }
    /** @brief 按固定 owner 保存最后一份 carrier metadata，更新不保留旧文本历史。 */
    inline auto RecordCarrierMetadata(Preview::Diagnose::ContextState& Trace,
        const Preview::Recognition::CarrierMetadata& Metadata) noexcept -> void
    {
        if (!Metadata.Carrier.empty())
        {
            const auto Carrier = Preview::Text::PascalCaseValue(Metadata.Carrier);
            Trace = Trace.With(Preview::Diagnose::Fields::Carrier, Carrier.View());
        }
        if (!Metadata.Sni.empty()) { Trace = Trace.With(Preview::Diagnose::Fields::Sni, Metadata.Sni); }
        if (!Metadata.Alpn.empty()) { Trace = Trace.With(Preview::Diagnose::Fields::Alpn, Metadata.Alpn); }
        if (!Metadata.TlsVersion.empty()) { Trace = Trace.With(Preview::Diagnose::Fields::TlsVersion, Metadata.TlsVersion); }
    }
    inline auto RecordClientHello(Preview::Diagnose::ContextState& Trace,
        const Preview::Recognition::ClientHelloFeatures& Features) noexcept -> void
    {
        Trace = Trace.With(Preview::Diagnose::Fields::Carrier, std::string_view{"Native"});
        if (!Features.ServerName.empty())
        {
            Trace = Trace.With(Preview::Diagnose::Fields::Sni, std::string_view(Features.ServerName));
        }
    }
    inline auto RecordTlsNegotiation(Preview::Diagnose::ContextState& Trace,
        const Preview::SharedTransmission& Transport) noexcept -> void
    {
        if (!Transport) { return; }
        auto* Encrypted = dynamic_cast<Preview::Transport::Encrypted*>(Transport.get());
        if (!Encrypted) { return; }
        auto* Ssl = Encrypted->Stream().native_handle();
        if (!Ssl) { return; }
        if (const auto* Version = SSL_get_version(Ssl))
        {
            Trace = Trace.With(Preview::Diagnose::Fields::TlsVersion, std::string_view(Version));
        }
        const unsigned char* Alpn = nullptr;
        unsigned int Length = 0U;
        SSL_get0_alpn_selected(Ssl, &Alpn, &Length);
        if (Alpn && Length != 0U)
        {
            const auto Value = std::string_view(reinterpret_cast<const char*>(Alpn), Length);
            Trace = Trace.With(Preview::Diagnose::Fields::Alpn, Value);
        }
    }
    [[nodiscard]] inline auto SanitizeCandidateName(const std::string_view Value) noexcept -> Preview::Text::FixedText<64U>
    {
        Preview::Text::FixedText<64U> Result;
        for (const auto Character : Value)
        {
            const auto Byte = static_cast<unsigned char>(Character);
            if (Byte >= 0x21U && Byte <= 0x7EU && Character != '=' && Character != '[' && Character != ']' && Character != ';')
            {
                Result.PushBack(Character);
            }
            else { Result.PushBack('_'); }
        }
        if (Result.Empty()) { Result.Append("none"); }
        return Result;
    }
    /** @brief 保留 category/value，避免系统错误描述的动态分配。 */
    template <typename ErrorCode>
    [[nodiscard]] auto FormatErrorCode(const ErrorCode& Error) noexcept -> Preview::Text::FixedText<128U>
    {
        Preview::Text::FixedText<128U> Result;
        if (!Error) { Result.Append("None"); return Result; }
        const auto Category = Preview::Text::PascalCaseValue(Error.category().name());
        Result.Append(Category.View());
        Result.PushBack(':');
        Result.AppendNumber(Error.value());
        return Result;
    }
    [[nodiscard]] inline auto FormatFirstByte(const Preview::Recognition::RecognizeResult& Result) noexcept
        -> Preview::Text::FixedText<8U>
    {
        Preview::Text::FixedText<8U> Value;
        if (Result.preread.empty()) { Value.Append("None"); return Value; }
        constexpr char Hex[] = "0123456789ABCDEF";
        const auto Byte = std::to_integer<unsigned int>(Result.preread.front());
        Value.Append("0x");
        Value.PushBack(Hex[(Byte >> 4U) & 0x0FU]);
        Value.PushBack(Hex[Byte & 0x0FU]);
        return Value;
    }
    /** @brief 只读取当前已认证身份，数值 fallback 不分配。 */
    [[nodiscard]] inline auto UserLogValue(const Preview::Middleware::Context& Context) noexcept
        -> Preview::Text::FixedText<256U>
    {
        Preview::Text::FixedText<256U> Result;
        if (!Context.DisplayIdentity().empty()) { Result.Append(Context.DisplayIdentity()); }
        else if (Context.AccountId()) { Result.AppendNumber(Context.AccountId().Value()); }
        return Result;
    }
}
