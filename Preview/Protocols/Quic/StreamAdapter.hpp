/**
 * @file StreamAdapter.hpp
 * @brief QUIC 流传输适配器（接口骨架）
 * @details 将 QUIC 流（ngtcp2/nghttp3 上层）适配为统一的
 * Transmission 抽象。设计目标：
 * 1. 测试库不直接依赖 ngtcp2 —— 通过 StreamProvider 接口注入
 * 2. 生产者（QUIC 服务器）实现 StreamProvider，适配器包装为
 *    Transmission 供协议层（hysteria2/tuic handler）使用
 * 3. 与生产库 net/transport/quic/Server.hpp 的 Quic::Stream 对应，
 *    后续可直接替换为生产实现
 * @note 本文件仅定义接口契约，不包含 ngtcp2 具体实现。
 *       完整 ngtcp2 封装见生产库 net/transport/quic/Server.hpp。
 */

#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <stdexcept>
#include <system_error>

#include <Preview/Contract/Io/CarrierActivity.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Protocols/Common/IoBridge.hpp>
#include <Preview/Protocols/Quic/Detail/StreamAdapterActivity.hpp>
#include <Preview/Transport/Detail/IoCompletion.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Quic
{

    namespace Net = boost::asio;

    /**
     * @class StreamProvider
     * @brief QUIC 流提供者（生产者接口）
     * @details 由底层 QUIC 会话实现：提供流级读写、流 ID 查询、
     * 打开新流、单流关闭。测试可注入内存实现（无 ngtcp2 依赖）。
     */
    class StreamProvider
    {
    public:
        virtual ~StreamProvider() = default;

        /**
         * @brief 获取流操作执行器
         * @details provider 必须返回其状态所属的真实 executor；适配器不创建隐式执行域。
         */
        [[nodiscard]] virtual auto Executor() const -> Net::any_io_executor = 0;

        /**
         * @brief 异步读取流数据
         * @param Buffer 接收缓冲区
         * @param ErrorCode 错误码输出
         * @return 实际读取字节数
         */
        [[nodiscard]] virtual auto Read(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> = 0;

        /**
         * @brief 异步写入流数据
         * @param Buffer 待写数据
         * @param ErrorCode 错误码输出
         * @return 实际写入字节数
         */
        [[nodiscard]] virtual auto Write(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> = 0;

        /**
         * @brief 请求终止整条流的读写两侧。
         * @details Native provider 使用 ngtcp2_conn_shutdown_stream 中止流；该操作不等价于有序 FIN 半关闭。
         */
        using ControlResult = std::expected<void, Preview::Fault::Failure>;
        [[nodiscard]] virtual auto Close() -> ControlResult = 0;

        /** @brief 返回该 stream provider 的真实操作与 native terminal 回执。 */
        [[nodiscard]] virtual auto Activity() const noexcept
            -> std::shared_ptr<Preview::Contract::CarrierActivity> = 0;

        /**
         * @brief 只关闭写方向并保留读方向。
         * @details awaitable 持有实际 provider 至 FIN 入包及 UDP sender 完成发送；成功只确认本地提交。
         *          失败按原 Fault::Failure 返回，不能退化为完整 Close。
         */
        using ShutdownResult = std::expected<void, Preview::Fault::Failure>;
        [[nodiscard]] virtual auto ShutdownWrite() -> Net::awaitable<ShutdownResult> = 0;

        /**
         * @brief 等待对端对已提交 FIN 的 QUIC transport acknowledgement。
         * @details 必须先成功完成 ShutdownWrite；UDP sender 完成不代表收到对端 ACK。
         */
        [[nodiscard]] virtual auto WaitForWriteAcknowledgement()
            -> Net::awaitable<ShutdownResult> = 0;

        /**
         * @brief 获取流 ID
         * @return 流标识符
         */
        [[nodiscard]] virtual auto StreamId() const noexcept -> std::int64_t = 0;

        /**
         * @brief 流是否已关闭
         * @return 关闭返回 true
         */
        [[nodiscard]] virtual auto IsClosed() const noexcept -> bool = 0;
    };

    /// 流提供者共享指针
    using SharedStreamProvider = std::shared_ptr<StreamProvider>;

    /**
     * @class StreamAdapter
     * @brief 将 StreamProvider 适配为 Transmission
     * @details 持有提供者的独占所有权，对外暴露 Transmission 接口。
     * 协议层（hysteria2/tuic）通过本适配器把 QUIC 流当作普通
     * 字节流处理，屏蔽 QUIC 细节。
     */
    class StreamAdapter final : public Transmission
    {
        [[nodiscard]] static auto ResolveExecutor(
            const Net::any_io_executor &Executor,
            const SharedStreamProvider &Provider) -> Net::any_io_executor
        {
            if (Provider)
            {
                const auto ProviderExecutor = Provider->Executor();
                if (ProviderExecutor) return ProviderExecutor;
            }
            if (Executor) return Executor;
            throw std::invalid_argument("StreamAdapter requires an executor");
        }

    public:
        /**
         * @brief 构造函数
         * @param Executor 执行器
         * @param Provider 流提供者（所有权移交）
         */
        StreamAdapter(Net::any_io_executor Executor, SharedStreamProvider Provider)
            : Preview::Transmission(ResolveExecutor(Executor, Provider)),
              Ex_(ResolveExecutor(Executor, Provider)),
              Provider_(std::move(Provider)),
              Activity_(MakeActivity(Preview::Transmission::Activity(), Provider_))
        {
        }

        /**
         * @brief 获取执行器
         */
        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        /**
         * @brief 获取被适配的 QUIC 流提供者
         * @return 共享提供者；front 用它追踪 close/drain 生命周期
         */
        [[nodiscard]] auto Provider() const noexcept -> SharedStreamProvider
        {
            return Provider_;
        }

        /**
         * @brief 异步读取（委托提供者）
         * @details 结果与借用沿正式前门交付一次；提供者缺失时交付确定失败。
         */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Preview::Protocols::StartPartialRead(
                Preview::Protocols::PartialReadInput<StreamAdapter>{Owner(), Buffer, Executor()},
                std::move(Handler));
        }

        /**
         * @brief 异步写入（委托提供者）
         */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Preview::Protocols::StartPartialWrite(
                Preview::Protocols::PartialWriteInput<StreamAdapter>{Owner(), Buffer, Executor()},
                std::move(Handler));
        }

        /**
         * @brief 真实写半关闭：委托提供者的 ShutdownWrite 并交付一次结果。
         */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Net::co_spawn(
                Ex_,
                CompleteWriteShutdown(Owner(), std::move(Handler)),
                Net::detached);
        }

        /**
         * @brief 关闭流
         * @return 命令交付成功；实际退出由 Activity()->Drain() 另行等待。
         */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            return Provider_->Close();
        }

        /**
         * @brief 取消挂起操作：与关闭同一提供者路径，不宣称已经关闭。
         */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return Provider_->Close();
        }

        /** @brief 数据面部分读取实现，由正式前门复用。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer)
            -> Net::awaitable<Preview::IoResult>
        {
            if (!Provider_)
            {
                co_return Preview::IoResult{
                    0, Preview::Fault::FromNative(std::make_error_code(std::errc::bad_file_descriptor))};
            }
            std::error_code ErrorCode;
            const auto Read = co_await Provider_->Read(Buffer, ErrorCode);
            if (Read > Buffer.size())
            {
                co_return Preview::IoResult{
                    0, Preview::Fault::FromNative(make_error_code(Error::BadLength))};
            }
            if (ErrorCode)
            {
                co_return Preview::IoResult{Read, Preview::Fault::FromNative(ErrorCode)};
            }
            co_return Preview::IoResult{Read, {}};
        }

        /** @brief 数据面部分写入实现，由正式前门复用；保留提供者短写事实。 */
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<Preview::IoResult>
        {
            if (!Provider_)
            {
                co_return Preview::IoResult{
                    0, Preview::Fault::FromNative(std::make_error_code(std::errc::bad_file_descriptor))};
            }
            std::error_code ErrorCode;
            const auto Written = co_await Provider_->Write(Buffer, ErrorCode);
            if (Written > Buffer.size())
            {
                co_return Preview::IoResult{
                    0, Preview::Fault::FromNative(make_error_code(Error::BadLength))};
            }
            if (ErrorCode)
            {
                co_return Preview::IoResult{Written, Preview::Fault::FromNative(ErrorCode)};
            }
            co_return Preview::IoResult{Written, {}};
        }

        /**
         * @brief 传输类型：可靠流（QUIC 流语义等同 TCP）
         */
        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Tcp;
        }

        /**
         * @brief 查询 QUIC 流是否仍然可用
         * @details Transmission 叶节点默认没有 NextLayer，必须由该适配器
         *          把 provider 的关闭状态传播给 front 的 drain/budget 追踪。
         */
        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Provider_ && !Provider_->IsClosed();
        }

    private:
        [[nodiscard]] static auto MakeActivity(
            std::shared_ptr<Preview::Contract::CarrierActivity> Parent,
            const SharedStreamProvider &Provider) -> std::shared_ptr<Detail::StreamAdapterActivity>
        {
            if (!Provider)
            {
                throw std::invalid_argument("QUIC stream adapter requires a provider");
            }
            const auto ProviderActivity = Provider->Activity();
            if (!ProviderActivity)
            {
                throw std::invalid_argument("QUIC stream provider requires an activity owner");
            }
            return std::make_shared<Detail::StreamAdapterActivity>(
                std::move(Parent), ProviderActivity);
        }

        /** @brief 等待真实 FIN 结果并只交付一次 typed completion。 */
        [[nodiscard]] static auto CompleteWriteShutdown(
            std::shared_ptr<StreamAdapter> Owner,
            Completion Handler) -> Net::awaitable<void>
        {
            Preview::IoResult Result;
            if (!Owner->Provider_)
            {
                Result.Failure = Preview::Fault::FromNative(
                    std::make_error_code(std::errc::bad_file_descriptor));
            }
            else
            {
                try
                {
                    const auto Shutdown = co_await Owner->Provider_->ShutdownWrite();
                    if (!Shutdown)
                    {
                        Result.Failure = Shutdown.error();
                    }
                }
                catch (const std::system_error &Error)
                {
                    Result.Failure = Preview::Fault::FromNative(Error.code());
                }
                catch (const std::bad_alloc &)
                {
                    Result.Failure = {Preview::Fault::Code::ResourceUnavailable};
                }
                catch (...)
                {
                    Result.Failure = {Preview::Fault::Code::IoError};
                }
            }
            Preview::Transport::Detail::PostResult(
                Owner->Executor(), std::move(Handler), std::move(Result));
        }

        /** @brief 完成交付前的 owner 借用；存活由本次传输预约与调用者共同保证。 */
        [[nodiscard]] auto Owner() -> std::shared_ptr<StreamAdapter>
        {
            return std::static_pointer_cast<StreamAdapter>(Transmission::shared_from_this());
        }

        Net::any_io_executor Ex_;       ///< 执行器
        SharedStreamProvider Provider_; ///< 流提供者（独占所有权）
        std::shared_ptr<Detail::StreamAdapterActivity> Activity_; ///< 聚合前门与 stream provider 实物回执
    };

    /// 适配器共享指针
    using SharedStreamAdapter = std::shared_ptr<StreamAdapter>;

} // namespace Preview::Quic
