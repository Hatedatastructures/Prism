/**
 * @file Recognition.hpp
 * @brief 基于已编译 Profile 的正式协议识别流水线。
 */
#pragma once

#include <Preview/Runtime/Recognition/ConfiguredMode.hpp>
#include <Preview/Runtime/Recognition/DeterministicMode.hpp>
#include <Preview/Runtime/Recognition/MixedTrialMode.hpp>
#include <Preview/Runtime/Recognition/ProbeBuffer.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <utility>

namespace Preview::Recognition
{
    namespace Net = boost::asio;

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
                          std::shared_ptr<Preview::Memory::BytePool> Bytes,
                          Preview::Diagnose::ContextState Trace =
                              Preview::Diagnose::CaptureCurrentContext())
            : Profile_(std::move(Profile)), Bytes_(std::move(Bytes)), Trace_(std::move(Trace)) {}

        [[nodiscard]] auto Recognize(SharedTransmission Transport) -> Net::awaitable<RecognizeResult>
        {
            if (!Profile_ || !Transport || !Bytes_)
            {
                if (Transport && !Bytes_)
                {
                    (void)Transport->Close();
                }
                RecognizeResult Result;
                Result.Status = RecognitionStatus::IoError;
                Result.FaultCode = Preview::Fault::Code::InvalidArgument;
                co_return Result;
            }
            ProbeBuffer Buffer(Profile_->Budget().MaxProbeBytes, Bytes_);
            co_return co_await Recognize(std::move(Transport), Buffer, {});
        }

        /**
         * @brief 在连接级预读 owner 与调用方期限上执行已编译识别。
         * @details Buffer 借用到协程返回；Control 持有取消状态，取消传播到在途读操作。
         */
        [[nodiscard]] auto Recognize(SharedTransmission Transport, ProbeBuffer& Buffer,
                                    RecognitionControl Control = {}) -> Net::awaitable<RecognizeResult>
        {
            if (!Profile_ || !Transport || !Buffer.Bytes())
            {
                if (Transport && !Buffer.Bytes())
                {
                    (void)Transport->Close();
                }
                RecognizeResult Result;
                Result.Status = RecognitionStatus::IoError;
                Result.FaultCode = Preview::Fault::Code::InvalidArgument;
                co_return Result;
            }
            if (Profile_->Mode() == RecognitionMode::Configured)
            {
                ConfiguredMode Mode(Profile_, Trace_);
                co_return co_await Mode.Recognize(std::move(Transport), Buffer, std::move(Control));
            }
            if (Profile_->Mode() == RecognitionMode::Deterministic)
            {
                DeterministicMode Mode(Profile_, Trace_);
                co_return co_await Mode.Recognize(std::move(Transport), Buffer, std::move(Control));
            }
            MixedTrialMode Mode(Profile_, Trace_);
            co_return co_await Mode.Recognize(std::move(Transport), Buffer, std::move(Control));
        }

    private:
        SharedProfile Profile_;
        std::shared_ptr<Preview::Memory::BytePool> Bytes_;
        Preview::Diagnose::ContextState Trace_;
    };
}
