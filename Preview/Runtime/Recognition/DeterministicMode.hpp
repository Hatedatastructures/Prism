/**
 * @file DeterministicMode.hpp
 * @brief 确定性多候选识别协调器入口
 * @details 复用 MixedTrial 的预读、Snapshot 和提交生命周期，但由其严格模式
 *          保证结构歧义在认证前终止；结构唯一后只对 winner 做一次认证，
 *          不对其他候选执行密码学试探。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <memory>
#include <utility>

#include <Preview/Runtime/Recognition/MixedTrialMode.hpp>

    namespace Preview::Recognition
    {

    namespace Net = boost::asio;

    /**
     * @class DeterministicMode
     * @brief 仅接受唯一结构候选的识别入口
     */
    class DeterministicMode
    {
    public:
        explicit DeterministicMode(SharedProfile Profile) : Profile_(std::move(Profile)), Coordinator_(Profile_) {}

        [[nodiscard]] auto Recognize(SharedTransmission Inbound, ProbeBuffer &Buffer,
                                     RecognitionControl Control = {}) -> Net::awaitable<RecognizeResult>
        {
            if (!Profile_ || Profile_->Mode() != RecognitionMode::DeterministicRoute)
            {
                co_return RecognizeResult{};
            }
            co_return co_await Coordinator_.Recognize(std::move(Inbound), Buffer, std::move(Control));
        }

        [[nodiscard]] auto Recognize(ProbeBuffer &Buffer, SharedTransmission Inbound,
                                     RecognitionControl Control = {}) -> Net::awaitable<RecognizeResult>
        {
            co_return co_await Recognize(std::move(Inbound), Buffer, std::move(Control));
        }

    private:
        SharedProfile Profile_;
        MixedTrialMode Coordinator_;
    };

} // namespace Preview::Recognition
