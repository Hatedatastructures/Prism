import type { ApiClient } from '../Api/ApiClient';
import type { Bootstrap } from '../Api/Bootstrap';

/** @brief 路由页面只消费同源 API client 与当前进程身份。 */
export type AdminServices = Readonly<{ Client: ApiClient; Bootstrap: Bootstrap }>;
