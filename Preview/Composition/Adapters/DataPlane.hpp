/**
 * @file DataPlane.hpp
 * @brief 协议接入的类型化数据面结果。
 * @details 该类型只依赖统一 Transmission；它不保存协议对象、不做
 *          dynamic_cast，也不把生产实现作为 Preview fallback。
 */

#pragma once

#include <Preview/Foundation/Error.hpp>
#include <Preview/Runtime/Contract/DataPlane.hpp>

namespace Preview::Composition::Adapters
{

    struct DataPlaneResult
    {
        Preview::Error Status{Preview::Error::None};
        Preview::Runtime::ProtocolDataPlane Data{};

        [[nodiscard]] static auto Stream(Preview::SharedTransmission Transport)
            -> DataPlaneResult
        {
            DataPlaneResult Result;
            Result.Data.Root = Preview::Runtime::StreamDataPlane{std::move(Transport)};
            return Result;
        }

        [[nodiscard]] static auto Datagram(Preview::SharedTransmission Transport)
            -> DataPlaneResult
        {
            DataPlaneResult Result;
            Result.Data.Root = Preview::Runtime::DatagramDataPlane{std::move(Transport), {}};
            return Result;
        }

        [[nodiscard]] static auto Mux(Preview::SharedTransmission Transport,
                                      std::string Mode = "auto") -> DataPlaneResult
        {
            DataPlaneResult Result;
            Result.Data.Root = Preview::Runtime::MuxRootDataPlane{
                std::move(Transport), std::move(Mode)};
            return Result;
        }

        [[nodiscard]] static auto Failure(Preview::Error ErrorCode) -> DataPlaneResult
        {
            DataPlaneResult Result;
            Result.Status = ErrorCode;
            return Result;
        }

        [[nodiscard]] auto IsStream() const noexcept -> bool
        {
            return Status == Preview::Error::None && Data.IsStream();
        }

        [[nodiscard]] auto IsDatagram() const noexcept -> bool
        {
            return Status == Preview::Error::None && Data.IsDatagram();
        }

        [[nodiscard]] auto IsMux() const noexcept -> bool
        {
            return Status == Preview::Error::None && Data.IsMux();
        }

        [[nodiscard]] auto Mux() noexcept -> Preview::Runtime::MuxRootDataPlane *
        {
            return Data.Mux();
        }

        [[nodiscard]] auto Mux() const noexcept -> const Preview::Runtime::MuxRootDataPlane *
        {
            return Data.Mux();
        }

        [[nodiscard]] auto HasTransport() const noexcept -> bool
        {
            return IsValid();
        }

        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return Status == Preview::Error::None && static_cast<bool>(Transport());
        }

        /**
         * @brief 判断 typed 数据面当前是否仍可用
         * @return 状态成功且底层传输保持打开返回 true
         */
        [[nodiscard]] auto IsOpen() const noexcept -> bool
        {
            const auto Current = Transport();
            return IsValid() && Current && Current->IsOpen();
        }

        /**
         * @brief 取消并关闭数据面
         * @details front drain/close 使用该入口收口 provider，避免只删除
         *          registry 条目而遗留仍可读写的传输对象。
         */
        auto Close() noexcept -> void
        {
            if (const auto Current = Transport())
            {
                Current->Cancel();
                Current->Close();
            }
        }

        [[nodiscard]] auto Transport() const noexcept -> Preview::SharedTransmission
        {
            return Data.Transport();
        }
    };

} // namespace Preview::Composition::Adapters
