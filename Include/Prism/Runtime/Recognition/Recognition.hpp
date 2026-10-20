/**
 * @file Recognition.hpp
 * @brief 基于已编译 Profile 的正式协议识别流水线。
 */
#pragma once

#include <Prism/Runtime/Recognition/RecognitionConfig.hpp>
#include <Prism/Runtime/Recognition/MixedTrialMode.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>
#include <Prism/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <utility>

namespace Prism::Recognition
{
    namespace Net = boost::asio;

    /**
     * @brief 仅接受唯一结构候选的识别入口。
     * @details 复用 MixedTrial 的预读与提交生命周期；结构歧义在认证前终止。
     */
    class DeterministicMode
    {
    public:
        explicit DeterministicMode(SharedProfile Profile,
            Prism::Diagnose::ContextState Trace = Prism::Diagnose::CaptureCurrentContext())
            : Profile_(std::move(Profile)), Coordinator_(Profile_, std::move(Trace))
        {
        }

        [[nodiscard]] auto Recognize(SharedTransmission Inbound, ProbeBuffer& Buffer,
            RecognitionControl Control = {}) -> Net::awaitable<RecognizeResult>;

    private:
        SharedProfile Profile_;
        MixedTrialMode Coordinator_;
    };

    /**
     * @brief 持有不可变 Profile，按其正式识别模式执行。
     * @details 接管入站共享所有权；成功结果包含候选和可继续读取的传输，
     *          拒绝、取消及期限状态由结果表达。所有操作在入站 executor 执行，
     *          预读按模式回放，最终关闭归 Session；识别阶段不执行半关闭。
     */
    class Pipeline final
    {
    public:
        explicit Pipeline(SharedProfile Profile,
                          std::shared_ptr<Prism::Memory::BytePool> Bytes,
                          Prism::Diagnose::ContextState Trace =
                              Prism::Diagnose::CaptureCurrentContext())
            : Profile_(std::move(Profile)), Bytes_(std::move(Bytes)), Trace_(std::move(Trace)) {}

        [[nodiscard]] auto Recognize(SharedTransmission Transport) -> Net::awaitable<RecognizeResult>;

        /**
         * @brief 在连接级预读 owner 与调用方期限上执行已编译识别。
         * @details Buffer 借用到协程返回；Control 持有取消状态，取消传播到在途读操作。
         */
        [[nodiscard]] auto Recognize(SharedTransmission Transport, ProbeBuffer& Buffer,
            RecognitionControl Control = {}) -> Net::awaitable<RecognizeResult>;

    private:
        SharedProfile Profile_;
        std::shared_ptr<Prism::Memory::BytePool> Bytes_;
        Prism::Diagnose::ContextState Trace_;
    };
}
