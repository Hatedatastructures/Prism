/**
 * @file ReadRequestResult.hpp
 * @brief HTTP 请求读入与解析结果的私有 owner 边界。
 */
#pragma once

#include <Prism/Operations/Http/ReadCompletion.hpp>
#include <Prism/Operations/HttpRequestBudget.hpp>

#include <boost/system/error_code.hpp>

#include <string>
#include <utility>

namespace Prism::Operations::HttpConnection
{

    /** @brief 保存请求头原文；借用视图仅在拥有该字符串的协程帧内生成。 */
    struct RequestReadResult final
    {
        bool Ready{false};
        std::string Bytes;
        RequestByteLease Budget;
        boost::system::error_code Terminal;
    };

    /** @brief 仅将已解析请求的字节、预算租约和同次终态交给连接 owner。 */
    [[nodiscard]] inline auto MakeRequestReadResult(
        Detail::RequestReadState ReadState,
        RequestByteLease Budget,
        boost::system::error_code Terminal) -> RequestReadResult
    {
        if (ReadState.Status == RequestParserDetail::ParseStatus::Incomplete ||
            ReadState.Status == RequestParserDetail::ParseStatus::Oversized)
        {
            return {};
        }
        return {true, std::move(ReadState.Bytes), std::move(Budget), std::move(Terminal)};
    }

} // namespace Prism::Operations::HttpConnection
