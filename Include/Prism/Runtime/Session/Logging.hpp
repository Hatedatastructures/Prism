/** @file Logging.hpp
 * @brief 会话观察使用的无分配文本与 metadata helper。
 */
#pragma once
#include <Prism/Runtime/Session/LogState.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Runtime/Recognition/Recognition.hpp>
#include <Prism/Transport/NativeTls.hpp>
#include <Prism/Foundation/Utility/Text/FixedText.hpp>
#include <boost/asio/ssl/error.hpp>
#include <openssl/err.h>
#include <string_view>
#include <system_error>
#include <type_traits>

namespace Prism::Recognition
{
    struct ClientHelloFeatures;
}

namespace Prism::Runtime::SessionSupport
{
    /** @brief 从稳定错误事实分类，不在请求线程创建 Native message 字符串。 */
    template <typename NativeCode>
        requires(std::is_same_v<NativeCode, boost::system::error_code> || std::is_same_v<NativeCode, std::error_code>)
    [[nodiscard]] inline auto ClassifyCarrierFailure(const Prism::Fault::Code Code,
        const NativeCode& NativeError) noexcept -> std::string_view
    {
        if (Code == Prism::Fault::Code::Timeout) { return "tls_handshake_timeout"; }
        if (Code == Prism::Fault::Code::Canceled) { return "cancelled"; }
        if (Code == Prism::Fault::Code::Verifyfail || Code == Prism::Fault::Code::Certfail)
        {
            return "certificate_error";
        }
        if (Code == Prism::Fault::Code::AuthFailed) { return "carrier_auth_failed"; }
        if (Code == Prism::Fault::Code::NotSupported) { return "wire_unavailable"; }
        if (Code == Prism::Fault::Code::TlsHsfail) { return "tls_alert"; }
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
    [[nodiscard]] inline auto ClassifyNativeTlsFailure(const Prism::Transport::NativeTlsResult& Result)
        noexcept -> std::string_view
    {
        return ClassifyCarrierFailure(Result.Failure.Code, Result.Failure.Native);
    }
    /** @brief 按固定 owner 保存最后一份 carrier metadata，更新不保留旧文本历史。 */
    auto RecordCarrierMetadata(Prism::Diagnose::ContextState& Trace,
        const Prism::Recognition::CarrierMetadata& Metadata) noexcept -> void;
    auto RecordClientHello(Prism::Diagnose::ContextState& Trace,
        const Prism::Recognition::ClientHelloFeatures& Features) noexcept -> void;
    auto RecordTlsNegotiation(Prism::Diagnose::ContextState& Trace,
        const Prism::SharedTransmission& Transport) noexcept -> void;
    [[nodiscard]] auto SanitizeCandidateName(const std::string_view Value) noexcept
        -> Prism::Text::FixedText<64U>;
    /** @brief 保留 category/value，避免系统错误描述的动态分配。 */
    template <typename ErrorCode>
    [[nodiscard]] auto FormatErrorCode(const ErrorCode& Error) noexcept -> Prism::Text::FixedText<128U>
    {
        Prism::Text::FixedText<128U> Result;
        if (!Error) { Result.Append("None"); return Result; }
        const auto Category = Prism::Text::PascalCaseValue(Error.category().name());
        Result.Append(Category.View());
        Result.PushBack(':');
        Result.AppendNumber(Error.value());
        return Result;
    }
    [[nodiscard]] auto FormatFirstByte(const Prism::Recognition::RecognizeResult& Result) noexcept
        -> Prism::Text::FixedText<8U>;
    /** @brief 只读取当前已认证身份，数值 fallback 不分配。 */
    [[nodiscard]] auto UserLogValue(const Prism::Middleware::Context& Context) noexcept
        -> Prism::Text::FixedText<256U>;
}
