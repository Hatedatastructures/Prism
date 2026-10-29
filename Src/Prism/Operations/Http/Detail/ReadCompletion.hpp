/**
 * @file ReadCompletion.hpp
 * @brief Operations HTTP socket read completion 与请求解析的私有边界。
 */
#pragma once

#include <Prism/Operations/Http/Limits.hpp>
#include <Prism/Operations/HttpRequest.hpp>
#include <Prism/Operations/Routes/RequestParser.hpp>

#include <boost/system/error_code.hpp>

#include <cstddef>
#include <span>
#include <string>

namespace Prism::Operations::HttpConnection::Detail
{

    struct RequestReadState final
    {
        std::string Bytes;
        HttpRequest Parsed;
        RequestParserDetail::ParseStatus Status{RequestParserDetail::ParseStatus::Incomplete};
    };

    struct ReadCompletion final
    {
        std::span<const char> Bytes;
        boost::system::error_code Error;
    };

    enum class ReadAction
    {
        Continue,
        Parsed,
        Oversized,
        Terminal,
        NoProgress,
    };

    struct ReadCompletionResult final
    {
        ReadAction Action{ReadAction::NoProgress};
        RequestParserDetail::ParseStatus Status{RequestParserDetail::ParseStatus::Incomplete};
        boost::system::error_code Terminal;
    };

    /**
     * @brief 先提交同次读取字节并解析，再按解析状态与 native terminal 选择 owner 动作。
     * @param State 借用并更新的请求缓冲与解析结果；字符串视图仅在下一次调用前有效。
     * @param Completion 单次 socket completion 携带的字节和 terminal；字节在返回前复制到 State。
     * @return Complete/invalid parse 为 Parsed；未完成且 terminal 为 Terminal；无进展为 NoProgress。
     */
    [[nodiscard]] auto ApplyReadCompletion(
        RequestReadState &State,
        ReadCompletion Completion) -> ReadCompletionResult;

} // namespace Prism::Operations::HttpConnection::Detail
