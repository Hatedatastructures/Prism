import type { AdminDataSource } from '../Services/AdminDataSource';

/** @brief 页面只依赖稳定的前端视图数据端口，不认识后端 DTO。 */
export type AdminMode = 'demo' | 'live';
export type AdminServices = Readonly<{ Data: AdminDataSource; Mode: AdminMode }>;
