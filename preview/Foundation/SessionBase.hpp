/**
 * @file SessionBase.hpp
 * @brief 会话抽象基类（统一生命周期接口）
 * @details 借鉴 Boost.Beast Stream 概念：所有协议会话继承本基类，
 *          上层（转发层 / 测试框架）通过基类指针切换协议零成本。
 *          基类定义统一的生命周期接口，派生协议实现具体编解码。
 * @note 与 Transport::Stream concept 保持同构，SessionBase 满足 Stream。
 */

#pragma once

// DEPRECATED: 旧骨架（Beast 模板方法模式），新协议 Conn 统一使用 Preview::Transmission
// （preview/Transport/Transmission.hpp）。当前仅 protocols/mux/Session.hpp 的 StreamHandle 使用
// （经 StreamTransmission 适配器桥接上层）；迁移 TODO：StreamHandle 直连 Transmission 后删除本文件。
// 勿在新代码中使用。

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>

#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Stream.hpp>

namespace Preview
{

    /// 会话抽象基类
    class SessionBase
    {
    public:
        virtual ~SessionBase() = default;

        /**
         * @brief 读取最多 buf.size() 字节（解包后的明文数据）
         * @return 实际读取字节数；0 = 对端关闭
         */
        virtual auto ReadSome(std::span<std::uint8_t> buf) -> net::awaitable<std::size_t> = 0;

        /**
         * @brief 写入全部 buf 字节（加密封包后发送）
         * @return 错误码（成功 = 空）
         */
        virtual auto WriteAll(std::span<const std::uint8_t> buf) -> net::awaitable<ProtocolEc> = 0;

        /**
         * @brief 优雅半关（发送 FIN，仍可读对端数据）
         */
        virtual auto Shutdown() -> net::awaitable<void> = 0;

        /**
         * @brief 立即关闭（读写均不可用）
         */
        virtual auto Close() -> net::awaitable<void> = 0;

        /**
         * @brief 取消挂起操作
         */
        virtual auto Cancel() -> void = 0;

        /**
         * @brief 设置读超时（0 = 禁用）
         */
        virtual auto SetTimeout(std::chrono::milliseconds ms) -> void = 0;

        /**
         * @brief 流是否打开
         * @return 打开返回 true
         */
        [[nodiscard]] virtual auto IsOpen() const -> bool = 0;

        /**
         * @brief 获取执行器
         * @return 关联的执行器
         */
        [[nodiscard]] virtual auto Executor() const -> net::any_io_executor = 0;
    };

} // namespace Preview
