/**
 * @file OwnedBytes.hpp
 * @brief 跨异步边界保活真实存储的可移动字节租约。
 */
#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Memory/Detail/BytePoolState.hpp>

#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <utility>

namespace Preview::Memory
{
    class BytePool;

    /**
     * @brief 独占一个可回收块，并共享保活该块所属的真实存储。
     * @details 不绑定 executor，可跨线程移动；同一对象及其借用 span 必须串行访问。
     *          移动不分配控制块，析构或 Release 是唯一最终归还操作。
     *          取消与半关闭由业务 owner 处理；异步操作完成前必须保留此租约。
     *          零长度租约仍占整块；默认构造、移出或释放后的对象不拥有块。
     */
    class OwnedBytes final
    {
    public:
        /** @brief 创建不占池容量的空 owner。 */
        OwnedBytes() noexcept = default;

        /** @brief 析构归还整块，最后一个存储 owner 同时释放冷路径分配。 */
        ~OwnedBytes() noexcept
        {
            Release();
        }

        OwnedBytes(const OwnedBytes&) = delete;
        auto operator=(const OwnedBytes&) -> OwnedBytes& = delete;

        /** @brief 转移唯一块租约；源变为空 owner，所有 span 的责任随之转移。 */
        OwnedBytes(OwnedBytes&& Other) noexcept
            : State_(std::move(Other.State_)), Index_(std::exchange(Other.Index_, 0)),
              Size_(std::exchange(Other.Size_, 0))
        {
        }

        /** @brief 先归还本对象旧块，再转移源租约；自移动不改变拥有关系。 */
        auto operator=(OwnedBytes&& Other) noexcept -> OwnedBytes&
        {
            if (this != &Other)
            {
                Release();
                State_ = std::move(Other.State_);
                Index_ = std::exchange(Other.Index_, 0);
                Size_ = std::exchange(Other.Size_, 0);
            }
            return *this;
        }

        /**
         * @brief 借用逻辑长度内的只读字节，不转移所有权。
         * @details 调用者必须先初始化数据；块复用和 Resize 不清零历史内容。
         *          Release、析构及覆盖赋值使借用失效；异步读者须保活实际租约。
         */
        [[nodiscard]] auto Bytes() const noexcept -> std::span<const std::byte>
        {
            if (!State_)
            {
                return {};
            }
            return State_->Block(Index_).first(Size_);
        }

        /** @brief 借用逻辑长度内可写范围；禁止与任何其他读写并发访问相同字节。 */
        [[nodiscard]] auto WritableBytes() noexcept -> std::span<std::byte>
        {
            if (!State_)
            {
                return {};
            }
            return State_->Block(Index_).first(Size_);
        }

        /** @brief 返回逻辑字节数；零长度不代表块已归还。 */
        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return Size_;
        }

        /** @brief 返回实际预约的整块容量；不拥有块时为零。 */
        [[nodiscard]] auto Capacity() const noexcept -> std::size_t
        {
            if (!State_)
            {
                return 0;
            }
            return State_->BlockSize();
        }

        /**
         * @brief 在已有预约内修改逻辑长度，不分配、复制或清零字节。
         * @param Size 新逻辑长度，允许零；增长后调用者须写入新增范围再读取。
         * @return 超容量返回 OversizedMsg，原长度和租约不变；成功返回空值。
         */
        [[nodiscard]] auto Resize(const std::size_t Size) noexcept -> std::expected<void, Fault::Failure>
        {
            if (Size > Capacity())
            {
                return std::unexpected(Fault::Failure{Fault::Code::OversizedMsg, {}});
            }
            Size_ = Size;
            return {};
        }

        /**
         * @brief 无分配归还整块并解除存储保活；重复调用安全。
         * @details 调用者先结束所有借用和异步访问；敏感内容须在归还前主动擦除。
         *          不执行取消或网络关闭，可在任意线程调用；不与同一 owner 并发。
         */
        auto Release() noexcept -> void
        {
            if (State_)
            {
                State_->Release(Index_);
                State_.reset();
            }
            Index_ = 0;
            Size_ = 0;
        }

    private:
        friend class BytePool;

        OwnedBytes(std::shared_ptr<Detail::BytePoolState> State, const std::size_t Index) noexcept
            : State_(std::move(State)), Index_(Index)
        {
        }

        std::shared_ptr<Detail::BytePoolState> State_;
        std::size_t Index_{0};
        std::size_t Size_{0};
    };
}
