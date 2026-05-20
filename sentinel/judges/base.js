export class JudgeRegistry {
    judges = new Map();
    register(judge) {
        if (this.judges.has(judge.id)) {
            throw new Error(`Judge id already registered: ${judge.id}`);
        }
        this.judges.set(judge.id, judge);
        return () => {
            this.judges.delete(judge.id);
        };
    }
    unregister(id) {
        return this.judges.delete(id);
    }
    list() {
        return Array.from(this.judges.values());
    }
    size() {
        return this.judges.size;
    }
}
