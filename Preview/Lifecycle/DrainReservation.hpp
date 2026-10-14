/** @file DrainReservation.hpp @brief 已进入 drain 屏障的真实 move-only 预约，覆盖调度和构造异常。 */
#pragma once
#include <Preview/Lifecycle/DrainBarrier.hpp>
namespace Preview::Lifecycle
{
    /** @brief 接管一次成功 Enter 的计数；barrier owner 必须保活到本预约退出。
     * @details move 后源为空；转交活动 owner 时 Transfer，一条路径只能归还一次。
     * 无 I/O/半关闭，析构仅 Leave，实际资源关闭由其 executor owner 负责。
     */
    class DrainReservation final
    {
    public:
        explicit DrainReservation(DrainBarrier& Barrier):Barrier_(&Barrier){}
        DrainReservation(DrainReservation&& Other) noexcept:Barrier_(std::exchange(Other.Barrier_,nullptr)){}
        DrainReservation(const DrainReservation&)=delete;
        ~DrainReservation(){if(Barrier_)Barrier_->Leave();}
        auto Transfer() noexcept -> void {Barrier_=nullptr;}
    private:
        DrainBarrier* Barrier_;
    };
}
