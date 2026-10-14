import { useMutation } from '@tanstack/react-query';
import { useOutletContext } from 'react-router';
import type { AdminServices } from '../App/AdminServices';
import type { CommandEnvelope } from '../Api/OperationsApi';
import { DecodeCommandResponse, VerifyCommandProcess } from '../Api/OperationsApi';
import { Fail } from '../Api/Result';
import type { ApiFailure, Result } from '../Api/Result';
import { Add } from './Operations/OperationStore';

export type CommandInput = Readonly<{
    Path: string; Body: unknown; Label: string; Target: string;
}>;

export function useAdminServices(): AdminServices {
    return useOutletContext<AdminServices>();
}

export function HasCapability(Services: AdminServices, Capability: string): boolean {
    return Services.Bootstrap.Capabilities.includes(Capability);
}

export function useCommandRunner(): Readonly<{
    IsPending: boolean;
    Submit: (Input: CommandInput) => Promise<Result<CommandEnvelope>>;
    Result: Result<CommandEnvelope> | null;
}> {
    const Services = useAdminServices();
    const Mutation = useMutation<Result<CommandEnvelope>, unknown, CommandInput>({
        mutationFn: async Input => {
            const ResultValue = await Services.Client.Command({
                Path: Input.Path, Bootstrap: Services.Bootstrap, Body: Input.Body,
                Decode: DecodeCommandResponse,
            });
            return VerifyCommandProcess(ResultValue, Services.Bootstrap.Process, true);
        },
        retry: false,
        onSuccess: (ResultValue, Input) => RecordAccepted(ResultValue, Input, Services),
    });
    async function Submit(Input: CommandInput): Promise<Result<CommandEnvelope>> {
        try {
            return await Mutation.mutateAsync(Input);
        } catch {
            const Failure: ApiFailure = { Kind: 'network',
                Message: '命令请求异常；服务端是否接收无法确认，请勿重复提交',
                HttpStatus: null, MayHaveExecuted: true };
            return Fail(Failure);
        }
    }
    return { IsPending: Mutation.isPending, Submit, Result: Mutation.data || null };
}

function RecordAccepted(
    ResultValue: Result<CommandEnvelope>, Input: CommandInput, Services: AdminServices,
): void {
    if (!ResultValue.Ok || ResultValue.Value.Status !== 'accepted' ||
        ResultValue.Value.Operation === '0') return;
    Add({ Process: Services.Bootstrap.Process,
        Incarnation: Services.Bootstrap.Incarnation,
        Operation: ResultValue.Value.Operation, Label: Input.Label,
        Target: Input.Target, RecordedAt: new Date().toISOString() });
}
