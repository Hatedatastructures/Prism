/**
 * @file stage_chain.hpp
 * @brief 协议 Stage 链编排器
 * @details 按配置顺序执行 Stage，直到某个 Stage 返回 success。
 * 新增伪装方案只需 push_back 新 Stage，无需修改 session 代码。
 */
#pragma once

#include <vector>
#include <prism/agent/pipeline/stage.hpp>
#include <prism/protocol/probe.hpp>

namespace psm::agent::pipeline
{
    class stage_chain
    {
    public:
        void push_back(shared_stage stage);

        [[nodiscard]] auto execute(agent::session_context &ctx, protocol::detection_result &detect_result,
                                   std::span<const std::byte> &span)
            -> net::awaitable<stage_result>;

    private:
        std::vector<shared_stage> stages_;
    };
} // namespace psm::agent::pipeline
