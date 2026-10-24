/**
 * @file Session.hpp
 * @brief HTTP/2 会话唯一公共 owner。
 * @details 本 facade 只公开连接与 stream 操作；帧、HPACK、接收 credit 和 native
 *          dispatch 状态由 Detail::SessionState 独占。构造时复制执行器与服务端角色，
 *          同步 Feed/Collect/提交调用必须由该执行器串行驱动；AwaitWritable 在同一执行器
 *          挂起并可取消。Session 不拥有底层传输，也不启动后台协程。连接 owner 停止驱动、
 *          收集待发数据并排空传输活动后销毁 Session 和关闭底层传输。
 */

#pragma once

#include <Prism/Protocols/Http2/Types.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <cstddef>
#include <expected>
#include <cstdint>
#include <memory>
#include <span>
#include <system_error>
#include <vector>

namespace Prism::Http2
{

    namespace Detail
    {
        class SessionState;
    }

    /**
     * @class Session
     * @brief 可直接消费的 HTTP/2 会话 facade。
     * @details 不可复制或移动，避免 Detail owner 保存的回调目标失效。输入 span 和头字段
     *          仅借用到同步调用返回；被接受的发送字节由内部 frame queue 拥有。
     */
    class Session final : public H2Session
    {
    public:
        /**
         * @brief 创建 HTTP/2 会话。
         * @param Executor 会话保存的 Asio 执行器。
         * @param IsServer 是否为服务端角色。
         * @details 调用者拥有 Session 与底层传输，并在 Executor 上串行驱动会话。同步状态
         *          操作没有取消点；AwaitWritable 的取消只结束该等待，不销毁 Session。
         *          Session 仅释放协议状态，不负责底层传输最终关闭；连接 owner 在停止
         *          Feed/Collect 并排空传输活动后完成销毁和关闭。
         */
        explicit Session(Net::any_io_executor Executor, bool IsServer);

        ~Session() override;

        Session(const Session &) = delete;
        auto operator=(const Session &) -> Session & = delete;
        Session(Session &&) = delete;
        auto operator=(Session &&) -> Session & = delete;

        [[nodiscard]] auto Feed(
            std::span<const std::byte> Data,
            std::error_code &ErrorCode) -> bool override;

        [[nodiscard]] auto Collect(std::vector<std::byte> &Output) -> bool override;

        [[nodiscard]] auto OpenStream(
            const HeaderList &Headers,
            bool EndStream) -> std::expected<std::int32_t, Prism::Fault::Failure> override;

        [[nodiscard]] auto SubmitHeaders(
            std::int32_t StreamId,
            const HeaderList &Headers,
            bool EndStream) -> std::expected<void, Prism::Fault::Failure> override;

        [[nodiscard]] auto SubmitData(
            std::int32_t StreamId,
            std::span<const std::byte> Data,
            bool EndStream) -> SubmitDataStatus override;

        [[nodiscard]] auto AwaitWritable(
            std::int32_t StreamId,
            std::size_t RequiredBytes)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override;

        auto ConsumeData(std::int32_t StreamId, std::size_t Bytes) -> void override;

        [[nodiscard]] auto ResetStream(
            std::int32_t StreamId,
            std::uint32_t ErrorCode) -> std::expected<void, Prism::Fault::Failure> override;

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override;

        /** @brief 把 SETTINGS 编码进会话自有发送队列。 */
        auto SendSettings(std::span<const SettingsEntry> Entries = {}) -> void;

        /** @brief 把 PING 编码进会话自有发送队列。 */
        auto SendPing(std::span<const std::byte, 8> Opaque) -> void;

        /** @brief 把 GOAWAY 编码进会话自有发送队列。 */
        auto SendGoaway(std::uint32_t LastStreamId, std::uint32_t ErrorCode) -> void;

    private:
        std::unique_ptr<Detail::SessionState> State_;
    };

} // namespace Prism::Http2
