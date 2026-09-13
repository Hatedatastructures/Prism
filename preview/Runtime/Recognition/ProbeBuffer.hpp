/**
 * @file ProbeBuffer.hpp
 * @brief 增量预读缓冲
 * @details 连接级唯一预读所有者。Ensure 只读取到指定边界，Snapshot 使用共享所有权，
 *          Snapshot 活跃期间增长自动执行 copy-on-write，Replay 通过 PreviewTransport 回放。
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Fault/Handling.hpp>
#include <preview/Runtime/Recognition/Types.hpp>
#include <preview/Transport/Preview.hpp>
#include <preview/Transport/Transmission.hpp>

namespace Preview::Recognition
{

    namespace Net = boost::asio;

    /**
     * @class ProbeBuffer
     * @brief 单连接增量预读缓冲
     * @details 仅由连接 executor 上的 coordinator 访问，不提供并发接口，也不使用锁。
     */
    class ProbeBuffer
    {
    public:
        static constexpr std::size_t MaxSupportedBytes = 64 * 1024;

        /**
         * @brief 构造缓冲
         * @param MaxBytes 本连接允许捕获的最大字节数
         */
        explicit ProbeBuffer(std::size_t MaxBytes)
            : MaxBytes_((std::min)(MaxBytes, MaxSupportedBytes)),
              Storage_(std::make_shared<std::vector<std::byte>>())
        {
            Storage_->reserve(MaxBytes_);
        }

        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return Storage_->size();
        }

        [[nodiscard]] auto Data() const noexcept -> std::span<const std::byte>
        {
            return std::span<const std::byte>(*Storage_);
        }

        [[nodiscard]] auto Empty() const noexcept -> bool
        {
            return Storage_->empty();
        }

        /**
         * @brief 将已由调用方消费的前缀植入缓冲
         * @param Data 需要保留的前缀
         * @return 数据未超出连接预算时返回 true
         * @details Seed 使用 copy-on-write，不修改已有 snapshot 的内容。
         */
        [[nodiscard]] auto Seed(std::span<const std::byte> Data) -> bool
        {
            if (Data.size() > MaxBytes_ || Size() > MaxBytes_ - Data.size())
            {
                return false;
            }
            EnsureWritable();
            Storage_->insert(Storage_->end(), Data.begin(), Data.end());
            return true;
        }

        /**
         * @brief 增量读取至最小边界
         * @param Transport 底层传输
         * @param Minimum 期望的最小捕获字节数
         * @return 填充结果
         * @details N>0 且同时带错误时先保留 N 字节再返回 IoError；零进展直接终止，
         *          防止在异常传输上忙等。
         */
        [[nodiscard]] auto Ensure(Preview::Transmission &Transport, std::size_t Minimum)
            -> Net::awaitable<ProbeFillResult>
        {
            ProbeFillResult Result;
            if (Minimum <= Size())
            {
                co_return Result;
            }
            if (Minimum > MaxBytes_)
            {
                Result.Status = RecognitionStatus::BudgetExceeded;
                co_return Result;
            }

            while (Size() < Minimum)
            {
                EnsureWritable();
                const auto OriginalSize = Storage_->size();
                const auto Need = Minimum - OriginalSize;
                Storage_->resize(Minimum);

                std::error_code Error;
                const auto Read = co_await Transport.async_read_some(
                    std::span<std::byte>(Storage_->data() + OriginalSize, Need), Error);
                if (Read > Need)
                {
                    Storage_->resize(OriginalSize);
                    Result.Status = RecognitionStatus::IoError;
                    if (Error)
                    {
                        Result.Error = Error;
                    }
                    else
                    {
                        Result.Error = std::make_error_code(std::errc::value_too_large);
                    }
                    co_return Result;
                }

                Storage_->resize(OriginalSize + Read);
                Result.Added += Read;
                if (Error)
                {
                    Result.Status = RecognitionStatus::IoError;
                    if (Read == 0 && Preview::Fault::ToCode(Error) == Preview::Fault::Code::Eof)
                    {
                        Result.Status = RecognitionStatus::EndOfStream;
                    }
                    Result.Error = Error;
                    co_return Result;
                }
                if (Read == 0)
                {
                    Result.Status = RecognitionStatus::EndOfStream;
                    co_return Result;
                }
            }

            co_return Result;
        }

        /**
         * @brief 从底层一次读取一个可用探测窗口
         * @param Transport 底层传输
         * @param Maximum 本次最多读取的字节数
         * @return 填充结果
         * @details 与 Ensure 不同，本函数只发起一次 async_read_some，允许底层
         *          返回少于 Maximum 的字节后立即交还调用方。legacy Probe 使用
         *          该原语保留部分读取，同时避免把首包退化为逐字节读取。
         */
        [[nodiscard]] auto ReadSome(Preview::Transmission &Transport, std::size_t Maximum)
            -> Net::awaitable<ProbeFillResult>
        {
            ProbeFillResult Result;
            if (Maximum == 0)
            {
                co_return Result;
            }
            if (Size() >= MaxBytes_)
            {
                Result.Status = RecognitionStatus::BudgetExceeded;
                co_return Result;
            }

            EnsureWritable();
            const auto OriginalSize = Storage_->size();
            const auto ReadSize = (std::min)(Maximum, MaxBytes_ - OriginalSize);
            Storage_->resize(OriginalSize + ReadSize);

            std::error_code Error;
            const auto Read = co_await Transport.async_read_some(
                std::span<std::byte>(Storage_->data() + OriginalSize, ReadSize), Error);
            if (Read > ReadSize)
            {
                Storage_->resize(OriginalSize);
                Result.Status = RecognitionStatus::IoError;
                if (Error)
                {
                    Result.Error = Error;
                }
                else
                {
                    Result.Error = std::make_error_code(std::errc::value_too_large);
                }
                co_return Result;
            }

            Storage_->resize(OriginalSize + Read);
            Result.Added = Read;
            if (Error)
            {
                Result.Status = RecognitionStatus::IoError;
                if (Read == 0 && Preview::Fault::ToCode(Error) == Preview::Fault::Code::Eof)
                {
                    Result.Status = RecognitionStatus::EndOfStream;
                }
                Result.Error = Error;
                co_return Result;
            }
            if (Read == 0)
            {
                Result.Status = RecognitionStatus::EndOfStream;
            }
            co_return Result;
        }

        /**
         * @brief 获取稳定快照
         * @return 共享所有权的只读快照
         */
        [[nodiscard]] auto Snapshot() const -> ProbeSnapshot
        {
            return ProbeSnapshot{Storage_};
        }

        /**
         * @brief 创建预读回放传输
         * @param Transport 被回放包装的底层传输
         * @return 预读优先的传输；无预读时返回原对象
         */
        [[nodiscard]] auto Replay(Preview::SharedTransmission Transport) const
            -> Preview::SharedTransmission
        {
            return Preview::Transport::WrapWithPreview(std::move(Transport), Data());
        }

    private:
        auto EnsureWritable() -> void
        {
            if (Storage_.use_count() > 1)
            {
                Storage_ = std::make_shared<std::vector<std::byte>>(*Storage_);
                Storage_->reserve(MaxBytes_);
            }
        }

        std::size_t MaxBytes_{0};
        std::shared_ptr<std::vector<std::byte>> Storage_;
    };

} // namespace Preview::Recognition
