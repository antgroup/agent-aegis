import type { ProbeEvent, Verdict } from "../channel/event.js";

/**
 * A judge inspects a ProbeEvent and decides what to do about it.
 *
 * Returning `null` means "no opinion" — the judge does not apply to this
 * event class. The aggregator simply drops null contributions.
 */
export interface Judge {
  readonly id: string;
  /**
   * Optional weight used by the `weighted` aggregator strategy. Defaults to
   * 1. Strictest aggregator ignores this field.
   */
  readonly weight?: number;
  judge(event: ProbeEvent): Promise<Verdict | null>;
}

export class JudgeRegistry {
  private readonly judges = new Map<string, Judge>();

  register(judge: Judge): () => void {
    if (this.judges.has(judge.id)) {
      throw new Error(`Judge id already registered: ${judge.id}`);
    }
    this.judges.set(judge.id, judge);
    return () => {
      this.judges.delete(judge.id);
    };
  }

  unregister(id: string): boolean {
    return this.judges.delete(id);
  }

  list(): Judge[] {
    return Array.from(this.judges.values());
  }

  size(): number {
    return this.judges.size;
  }
}
