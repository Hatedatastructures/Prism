/**
 * @file ProbeBuffer.hpp
 * @brief 增量预读缓冲
 * @details 连接级唯一预读所有者。Ensure 只读取到指定边界，Snapshot 使用共享所有权，
 *          Snapshot 活跃期间增长自动执行 copy-on-write，Replay 通过 PreviewTransport 回放。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Runtime/Recognition/Types.hpp>
#include <Prism/Transport/Preview.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Recognition
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
         * @param Bytes 连接级共享有界池；为空表示调用方没有完成资源注入
         * @details 池只在构造时取得；Replay 需要跨越异步边界保活前缀存储。
         */
        explicit ProbeBuffer(std::size_t MaxBytes,
                             std::shared_ptr<Prism::Memory::BytePool> Bytes);

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

        [[nodiscard]] auto Bytes() const noexcept
            -> const std::shared_ptr<Prism::Memory::BytePool>&
        {
            return Bytes_;
        }

        /**
         * @brief 将已由调用方消费的前缀植入缓冲
         * @param Data 需要保留的前缀
         * @return 数据未超出连接预算时返回 true
         * @details Seed 使用 copy-on-write，不修改已有 snapshot 的内容。
         */
        [[nodiscard]] auto Seed(std::span<const std::byte> Data) -> bool;

        /**
         * @brief 增量读取至最小边界
         * @param Transport 底层传输
         * @param Minimum 期望的最小捕获字节数
         * @return 填充结果
         * @details 同次读取返回字节与失败时先保留字节，并把 typed terminal 绑定到本缓冲；
         *          Replay 在完整前缀之后交付该 terminal。零进展直接终止，防止异常传输上忙等。
         */
        [[nodiscard]] auto Ensure(Prism::Transmission &Transport, std::size_t Minimum)
            -> Net::awaitable<ProbeFillResult>;

        /**
         * @brief 从底层一次读取一个可用探测窗口
         * @param Transport 底层传输
         * @param Maximum 本次最多读取的字节数
         * @return 填充结果
         * @details 与 Ensure 不同，本函数只发起一次 async_read_some，允许底层
         *          返回少于 Maximum 的字节后立即交还调用方。legacy Probe 使用
         *          该原语保留部分读取，同时避免把首包退化为逐字节读取。
         */
        [[nodiscard]] auto ReadSome(Prism::Transmission &Transport, std::size_t Maximum)
            -> Net::awaitable<ProbeFillResult>;

        /**
         * @brief 单次读取一个窗口并按值保留原始终止失败。
         * @param Transport 仅在本次协程读取期间借用的底层传输。
         * @param Maximum 本次读取的最大字节数。
         * @return 已提交的字节数与原始 typed terminal，不复制或重读同次输入。
         * @details 连接 executor 上由唯一缓冲 owner 消费读取结果；本缓冲保留 terminal，Replay 在
         *          前缀之后交付该 terminal；空 span 不消费终态。
         */
        [[nodiscard]] auto ReadSomeWithTerminal(
            Prism::Transmission &Transport,
            std::size_t Maximum)
            -> Net::awaitable<ProbeReadResult>;

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
         * @return 预读优先的传输；无预读时返回原对象；池额度耗尽或载体非法返回空 owner
         * @details 前缀真实块由 PreviewTransport 持有至前缀耗尽；Ensure/ReadSomeWithTerminal 捕获的
         *          terminal 随前缀一起回放。空返回表示未创建回放层，调用者按失败处理，不执行半关闭或最终关闭。
         */
        [[nodiscard]] auto Replay(Prism::SharedTransmission Transport) const
            -> Prism::SharedTransmission;

        /**
         * @brief 回放缓冲字节，并在末段字节的同一次读取中交付原始终止失败。
         * @param Transport 由回放层共享持有的原始传输。
         * @param Terminal 与缓冲前缀同时完成的领域失败及原生错误；缓冲已有终态时优先使用缓冲终态。
         * @return 回放传输或无法构造回放层的原始失败；终止失败只归回放 owner 一次。
         */
        [[nodiscard]] auto Replay(
            Prism::SharedTransmission Transport,
            Prism::Fault::Failure Terminal) const
            -> std::expected<Prism::SharedTransmission, Prism::Fault::Failure>;

    private:
        auto EnsureWritable() -> void;

        std::size_t MaxBytes_{0};
        std::shared_ptr<std::vector<std::byte>> Storage_;
        std::shared_ptr<Prism::Memory::BytePool> Bytes_;
        Prism::Fault::Failure Terminal_{};
    };

} // namespace Prism::Recognition
