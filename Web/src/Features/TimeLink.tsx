import type { ReactNode } from 'react';
import { Link, useSearchParams } from 'react-router';
import type { LinkProps } from 'react-router';
import { ResourceDestination } from '../Api/ResourceNavigation';

/** @brief 显式资源链接保持当前时间上下文，不拦截点击或修改外部地址。 */
export function TimeLink({ to, ...Props }: LinkProps): ReactNode {
    const [Params] = useSearchParams();
    return <Link {...Props} to={ResourceDestination(to, Params)} />;
}
