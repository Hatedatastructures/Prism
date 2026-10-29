/** @file ReadCompletion.cpp @brief Operations HTTP read completion 解析与终态决策。 */

#include <Prism/Operations/Http/Detail/ReadCompletion.hpp>

#include <algorithm>
#include <utility>

namespace Prism::Operations::HttpConnection::Detail
{

    auto ApplyReadCompletion(RequestReadState &State, ReadCompletion Completion)
        -> ReadCompletionResult
    {
        if (Completion.Bytes.size() > MaxRequestBytes -
                std::min(State.Bytes.size(), MaxRequestBytes))
        {
            State.Status = RequestParserDetail::ParseStatus::Oversized;
            return {ReadAction::Oversized, State.Status, std::move(Completion.Error)};
        }
        if (!Completion.Bytes.empty())
        {
            State.Bytes.append(Completion.Bytes.data(), Completion.Bytes.size());
        }

        State.Parsed = HttpRequest{};
        State.Status = RequestParserDetail::ParseRequest(State.Bytes, State.Parsed);
        if (State.Status == RequestParserDetail::ParseStatus::Oversized)
        {
            return {ReadAction::Oversized, State.Status, std::move(Completion.Error)};
        }
        if (State.Status != RequestParserDetail::ParseStatus::Incomplete)
        {
            return {ReadAction::Parsed, State.Status, std::move(Completion.Error)};
        }
        if (Completion.Error)
        {
            return {ReadAction::Terminal, State.Status, std::move(Completion.Error)};
        }
        if (Completion.Bytes.empty())
        {
            return {ReadAction::NoProgress, State.Status, {}};
        }
        return {ReadAction::Continue, State.Status, {}};
    }

} // namespace Prism::Operations::HttpConnection::Detail
