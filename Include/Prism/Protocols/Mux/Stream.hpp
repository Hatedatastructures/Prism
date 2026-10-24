/**
 * @file Stream.hpp
 * @brief 多路复用流传输适配器（StreamHandle → Transmission）
 * @details 包装 mux 虚拟流句柄，将其暴露为唯一 typed 传输前门，作为上层协议
 * Server/Client（vless/trojan/socks5/...）的挂载点。流无底层链，
 * NextLayer() 返回 nullptr（叶子节点）。
 * @note StreamHandle::Close() / Reset() 为协程，适配器经 tracked engine scope
 *       投递到句柄 executor，并以 shared_ptr 捕获句柄保活。
 * @note 读返回 0 时先检查已保存的对端非 EOF 终态，再检查 FIN；未知关闭才映射
 *       Error::UnexpectedEof，不再用零字节成功暗示 EOF。
 */

#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/async_result.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_composed.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <system_error>
#include <utility>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Compatible.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Mux/Session.hpp>
#include <tuple>

namespace Prism::Mux
{

    /**
     * @class StreamTransmission
     * @brief 流传输适配器（StreamHandle → Transmission）
     * @details 将 mux 虚拟流句柄包装为 Transmission 接口，供上层协议
     * 会话直接挂载（装饰器链叶子节点）。
     */
    class StreamTransmission : public Transmission
    {
    public:
        /**
         * @brief 构造
         * @param Handle 按值接管的非空 mux 虚拟流句柄 owner
         * @throws std::invalid_argument Handle、TaskRegistry 或 Reclaimer 为空时抛出；
         *         检查发生在访问成员和分配 DrainBarrier 之前。
         * @details Handle 是本适配器的必需 owner；Session/TaskRegistry 持有 executor，适配器只借用
         *          其 Reclaimer 提供的执行域，不创建默认 executor 或第二套关闭事实。构造不启动 I/O。
         */
        explicit StreamTransmission(std::shared_ptr<StreamHandle<>> Handle);

        /**
         * @brief 获取执行器
         * @return 由非空 StreamHandle 提供的流执行器
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override;

        /**
         * @brief 部分读取；结果与借用沿正式前门交付一次。
         * @details 转调 StreamHandle::ReadSome；已保存的非 EOF 终态按原领域码和
         *          Native 返回，已确立 FIN 交付 Fault::Code::Eof，其余未知关闭交付
         *          Error::UnexpectedEof。已完成字节先交付再报失败。
         */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override;

        /**
         * @brief 部分写入；结果沿正式前门交付一次。
         * @details 转调 StreamHandle::WriteAll（内部完整写入），
         *          成功时交付 Buffer.size()，失败交付 0 与同次错误。
         */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override;

        /**
         * @brief 关闭流：先交付 tracked FIN 再关闭本地句柄。
         * @return 命令接管成功；实际 wire 完成由 DrainTerminations() 等待。
         */
        [[nodiscard]] auto OnClose() -> ControlResult override;

        /**
         * @brief 重置流（发 RST，对端读返回 0）
         * @details 与 OnClose() 同样经 tracked 任务投递执行；区别是向对端
         * 发送重置帧，对端挂起读被唤醒并返回 0。
         */
        auto Reset() -> void;

        /**
         * @brief 真实写半关闭：只发送当前 child 的 FIN。
         * @details 保持 Submit(Termination::Fin) 的原判定语义——FIN 先交付已排队
         *          数据再发布 EOF；反向读取和兄弟流保持可用。本前门不把 Close
         *          当半关闭，实际 FIN 写入完成由 DrainTerminations() 等待。
         * @param Handler 完成交付；借用结束于 handler 返回。
         */
        auto StartWriteShutdown(Completion Handler) -> void override;

        /** @brief 等待本 child 的 FIN/reset/最终关闭写入完成；复用 engine reclaimer，无额外回收队列。 */
        [[nodiscard]] auto DrainTerminations()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /**
         * @brief 取消挂起操作；不改变已经确立的本地流状态。
         * @return 命令接管成功；取消请求排入句柄 executor 后返回。
         */
        [[nodiscard]] auto OnCancel() -> ControlResult override;

        /**
         * @brief 流是否打开
         * @return true = 句柄存活且未关闭
         */
        [[nodiscard]] auto IsOpen() const -> bool;

        /**
         * @brief 获取底层流句柄
         * @return mux 虚拟流句柄
         */
        [[nodiscard]] auto Handle() const noexcept -> std::shared_ptr<StreamHandle<>>;

    private:
        /** @brief 构造任何异步 owner 前检查必需句柄，禁止补默认执行域。 */
        [[nodiscard]] static auto RequireExecutor(const std::shared_ptr<StreamHandle<>> &Handle)
            -> Net::any_io_executor;

        enum class Termination { Close, Reset, Fin };
        struct FinishRequest final
        {
            std::shared_ptr<StreamHandle<>> Handle;
            std::shared_ptr<Prism::Lifecycle::DrainBarrier> Barrier;
            Termination Action;
        };
        static auto Finish(FinishRequest Request) -> Net::awaitable<void>;
        /** @brief 部分读取；保留对端半关与异常 EOF 的终态判定。 */
        [[nodiscard]] auto ReadPartial(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t>;
        /** @brief 部分写入；底层错误保留 StreamHandle::WriteAll 的语义。 */
        [[nodiscard]] auto WritePartial(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t>;
        struct StreamRead final
        {
            std::shared_ptr<StreamTransmission> Owner;
            std::span<std::byte> Buffer;
        };
        struct StreamWrite final
        {
            std::shared_ptr<StreamTransmission> Owner;
            std::span<const std::byte> Buffer;
        };
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, StreamRead Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                std::error_code ErrorCode;
                const auto Count = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadPartial(Input.Buffer, ErrorCode), Net::deferred);
                co_return std::tuple{Prism::IoResult{Count, Prism::Fault::FromNative(ErrorCode)}};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, StreamWrite Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                std::error_code ErrorCode;
                const auto Count = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer, ErrorCode), Net::deferred);
                co_return std::tuple{Prism::IoResult{Count, Prism::Fault::FromNative(ErrorCode)}};
            }
        };
        /** @brief 在 owner executor 上启动一次部分 I/O；结果经正式前门恰好交付一次。 */
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()), Handler, std::move(Value));
        }
        /** @brief 终止写保活句柄；会话已退场时只幂等关闭本地句柄，不再发布任务或 wire。 */
        auto Submit(Termination Action) -> void;
        std::shared_ptr<StreamHandle<>> Handle_; ///< mux 虚拟流句柄
        std::shared_ptr<Prism::Lifecycle::DrainBarrier> Terminations_;
    };

    /// 流传输共享指针
    using SharedStream = std::shared_ptr<StreamTransmission>;

} // namespace Prism::Mux
