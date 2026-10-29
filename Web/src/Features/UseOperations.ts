import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query';
import { useOutletContext, useSearchParams } from 'react-router';
import type { AdminServices } from '../App/AdminServices';
import type { AdminDataSource, BootstrapSnapshot, CursorPage, PageRequest } from '../Services/AdminDataSource';

export const BootstrapIdentityQueryKey = ['operations', 'bootstrap-identity'] as const;

export function useAdminServices(): AdminServices {
    return useOutletContext<AdminServices>();
}

export function useBootstrapIdentity(): UseQueryResult<BootstrapSnapshot, Error> {
    const Services = useAdminServices();
    return useQuery({ queryKey: [...BootstrapIdentityQueryKey, Services.Mode], queryFn: () => Services.Data.GetBootstrap({ Fresh: true }),
        retry: false, staleTime: 0, refetchInterval: Services.Mode === 'live' ? 5_000 : false,
        refetchIntervalInBackground: false, refetchOnWindowFocus: true });
}

export function useAdminQuery<Value>(
    Name: string,
    Load: (Source: AdminDataSource) => Promise<Value>,
    Options: Readonly<{ Enabled?: boolean; Scope?: readonly unknown[] }> = {},
): UseQueryResult<Value, Error> {
    const Services = useAdminServices();
    return useQuery({ queryKey: ['operations', Name, ...(Options.Scope ?? [])], queryFn: () => Load(Services.Data),
        enabled: Options.Enabled ?? true, retry: false, staleTime: 2_000,
        refetchInterval: Services.Mode === 'live' ? 5_000 : false, refetchIntervalInBackground: false,
        refetchOnWindowFocus: true });
}

export function useAdminInfiniteQuery<Page extends CursorPage<unknown>>(
    Name: string,
    Load: (Source: AdminDataSource, PageRequestValue: PageRequest) => Promise<Page>,
    Scope: readonly unknown[] = [],
    Options: Readonly<{ Refresh?: boolean }> = {},
) {
    const Services = useAdminServices();
    const [Params] = useSearchParams();
    const FilteredCollection = ['accounts', 'workers', 'sessions', 'groups', 'ingresses', 'protocols'].includes(Name);
    const Filter = FilteredCollection ? { Query: Params.get('q') ?? '', State: Params.get('state') ?? '',
        WorkerId: Name === 'sessions' ? Params.get('worker') ?? '' : '', AccountId: Name === 'sessions' ? Params.get('account') ?? '' : '',
        ProcessId: Name === 'sessions' ? Params.get('process') ?? '' : '', GenerationId: Name === 'sessions' ? Params.get('generation') ?? '' : '',
        Protocol: Name === 'sessions' ? Params.get('protocol') ?? '' : '', Sort: Params.get('sort') ?? '',
        GroupId: Name === 'accounts' ? Params.get('group') ?? '' : '' } : {};
    return useInfiniteQuery({
        queryKey: ['operations', Name, ...Scope, Filter],
        initialPageParam: '0',
        queryFn: ({ pageParam }) => Load(Services.Data, { Cursor: pageParam, Limit: 50, ...Filter }),
        getNextPageParam: PageValue => PageValue.HasMore ? PageValue.NextCursor : undefined,
        retry: false,
        staleTime: 2_000,
        refetchInterval: Services.Mode === 'live' && Options.Refresh !== false ? 5_000 : false,
        refetchIntervalInBackground: false,
        refetchOnWindowFocus: Options.Refresh !== false,
    });
}

export function useAdminMutation<Input, Value>(
    Run: (Source: AdminDataSource, Input: Input) => Promise<Value>,
): UseMutationResult<Value, Error, Input> {
    const Services = useAdminServices();
    const QueryClient = useQueryClient();
    return useMutation({
        mutationFn: (InputValue: Input) => Run(Services.Data, InputValue),
        onSuccess: () => QueryClient.invalidateQueries({ queryKey: ['operations'] }),
        retry: false,
    });
}
