export type WorkerIdentity = Readonly<{
    Id: string;
    ProcessId: string;
    GenerationId: string;
}>;

export type ExpectedWorkerIdentity = Readonly<{
    Id: string;
    ProcessId: string | null;
    GenerationId: string | null;
}>;

export type WorkerIdentityStatus = 'verified' | 'scope-missing' | 'changed' | 'unavailable';

export type WorkerDestination = 'workers' | 'sessions' | 'events';

/** @brief 只在 Worker ID、Process 与 Generation 都一致时验证当前 slot 目标。 */
export function CheckWorkerIdentity(
    Expected: ExpectedWorkerIdentity,
    Current: WorkerIdentity | null,
): WorkerIdentityStatus {
    if (!Expected.ProcessId || !Expected.GenerationId) return 'scope-missing';
    if (Current === null) return 'unavailable';
    return Expected.Id === Current.Id && Expected.ProcessId === Current.ProcessId &&
        Expected.GenerationId === Current.GenerationId ? 'verified' : 'changed';
}

/** @brief 为 Worker 来源链接保留 slot、process 与 generation 身份。 */
export function WorkerTargetPath(
    Destination: WorkerDestination,
    Worker: WorkerIdentity,
): string {
    const Scope = new URLSearchParams({
        worker: Worker.Id,
        process: Worker.ProcessId,
        generation: Worker.GenerationId,
    });
    return `/${Destination}?${Scope}`;
}
