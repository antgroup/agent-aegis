function resolvePluginConfigSchema(configSchema) {
    if (!configSchema) {
        return undefined;
    }
    return typeof configSchema === "function" ? configSchema() : configSchema;
}
// Keep the plugin entry helper local so third-party installs do not depend on
// specific OpenClaw SDK subpaths being present at runtime.
export function definePluginEntry({ id, name, description, kind, configSchema, register, }) {
    const resolvedConfigSchema = resolvePluginConfigSchema(configSchema);
    return {
        id,
        name,
        description,
        ...(kind ? { kind } : {}),
        ...(resolvedConfigSchema ? { configSchema: resolvedConfigSchema } : {}),
        register,
    };
}
