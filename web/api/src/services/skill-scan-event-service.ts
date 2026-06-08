import type { SkillScanEvent } from "@agent-aegis-web/shared";

const MAX_EVENTS = 1000;

export class SkillScanEventService {
  private readonly events: SkillScanEvent[] = [];
  private nextId = 1;

  addEvent(event: Omit<SkillScanEvent, "id">): SkillScanEvent {
    const full: SkillScanEvent = {
      ...event,
      id: String(this.nextId++),
    };
    this.events.push(full);
    if (this.events.length > MAX_EVENTS) {
      this.events.splice(0, this.events.length - MAX_EVENTS);
    }
    return full;
  }

  getEvents(params?: {
    limit?: number;
    offset?: number;
    trusted?: string;
  }): { events: SkillScanEvent[]; total: number } {
    let filtered = this.events;

    if (params?.trusted === "true") {
      filtered = filtered.filter((e) => e.trusted);
    } else if (params?.trusted === "false") {
      filtered = filtered.filter((e) => !e.trusted);
    }

    const total = filtered.length;
    const offset = params?.offset ?? 0;
    const limit = params?.limit ?? 50;

    const sorted = [...filtered].reverse();
    const sliced = sorted.slice(offset, offset + limit);

    return { events: sliced, total };
  }
}
