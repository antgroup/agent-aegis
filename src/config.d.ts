import type { OpenClawPluginApi } from "../runtime-api.js";
export declare const AGENT_AEGIS_PLUGIN_ID = "agent-aegis";
export declare const DEFENSE_MODES: readonly ["off", "observe", "enforce"];
export declare const TURN_STATE_TTL_MS: number;
export declare const LOOP_GUARD_TTL_MS: number;
export declare const LOOP_GUARD_ALLOW_COUNT = 3;
export declare const STARTUP_SCAN_BUDGET_MS = 200;
export declare const INLINE_EXEC_TEXT_MAX_CHARS: number;
export declare const MEMORY_WRITE_MAX_CHARS: number;
export declare const MEMORY_WRITE_MAX_LINES = 200;
export declare const TOOL_RESULT_CHAR_BUDGET: number;
export declare const TOOL_RESULT_MAX_DEPTH = 4;
export declare const TOOL_RESULT_MAX_ARRAY_ITEMS = 200;
export declare const SKILL_SCAN_QUEUE_MAX = 16;
export declare const SKILL_SCAN_TIMEOUT_MS = 3000;
export declare const SKILL_SCAN_COOLDOWN_MS: number;
export declare const SKILL_SCAN_FAILURE_WINDOW_MS = 60000;
export declare const SKILL_SCAN_FAILURE_THRESHOLD = 3;
export declare const SKILL_SCAN_FILE_MAX_BYTES: number;
export declare const SKILL_SCAN_TARGET_FILENAME = "SKILL.md";
export declare const SKILL_SCAN_ALLOWED_EXTENSIONS: string[];
export declare const TRUSTED_SKILLS_FILENAME = "trusted-skills.json";
export declare const SELF_INTEGRITY_FILENAME = "self-integrity.json";
export declare const DEFENSE_EVENTS_FILENAME = "defense-events.jsonl";
export declare const SKILL_SCAN_EVENTS_FILENAME = "skill-scan-events.jsonl";
export declare const BLOCK_REASON_PROTECTED_PATH = "\u5B89\u5168\u9650\u5236\uFF1A\u7981\u6B62\u8BBF\u95EE\u3001\u67E5\u8BE2\u3001\u4FEE\u6539\u3001\u5220\u9664\u3001\u5173\u95ED\u6216\u7ED5\u8FC7\u53D7\u4FDD\u62A4\u7684\u654F\u611F\u8DEF\u5F84\u3001\u914D\u7F6E\u3001\u91CD\u8981 skill \u6216 agent-aegis \u63D2\u4EF6\u76EE\u5F55\u3002";
export declare const BLOCK_REASON_WORKSPACE_DELETE = "\u5B89\u5168\u9650\u5236\uFF1A\u7981\u6B62\u5220\u9664 workspace \u4E4B\u5916\u7684\u8DEF\u5F84\u3002";
export declare const BLOCK_REASON_OPENCLAW_COMMAND = "\u5B89\u5168\u9650\u5236\uFF1A\u7981\u6B62\u6267\u884C openclaw CLI \u6216\u63A7\u5236\u547D\u4EE4\u3002";
export declare const BLOCK_REASON_HIGH_RISK_OPERATION = "\u5B89\u5168\u9650\u5236\uFF1A\u5DF2\u963B\u6B62\u672C\u6B21\u9AD8\u98CE\u9669\u64CD\u4F5C\u8BF7\u6C42\u3002";
export declare const BLOCK_REASON_MEMORY_WRITE = "\u5B89\u5168\u9650\u5236\uFF1A\u5DF2\u62D2\u7EDD\u672C\u6B21\u9AD8\u98CE\u9669\u8BB0\u5FC6\u5199\u5165\u3002";
export declare const BLOCK_REASON_LOOP = "\u5B89\u5168\u9650\u5236\uFF1A\u68C0\u6D4B\u5230\u91CD\u590D\u9AD8\u98CE\u9669\u5DE5\u5177\u8C03\u7528\uFF0C\u5DF2\u505C\u6B62\u672C\u6B21\u64CD\u4F5C\u3002";
export declare const BLOCK_REASON_EXFILTRATION_CHAIN = "\u5B89\u5168\u9650\u5236\uFF1A\u68C0\u6D4B\u5230\u7591\u4F3C SSRF \u6216\u6570\u636E\u5916\u6CC4\u5DE5\u5177\u8C03\u7528\u94FE\uFF0C\u5DF2\u963B\u6B62\u672C\u6B21\u51FA\u7AD9\u8BF7\u6C42\u3002";
export declare const BLOCK_REASON_DISPATCH_GUARD = "\u5B89\u5168\u9650\u5236\uFF1A\u68C0\u6D4B\u5230\u9488\u5BF9\u53D7\u4FDD\u62A4\u8D44\u6E90\u7684\u5371\u9669\u64CD\u4F5C\u8BF7\u6C42\uFF0C\u5DF2\u62E6\u622A\u3002\u6240\u6709\u7834\u574F\u6027\u64CD\u4F5C\u5FC5\u987B\u901A\u8FC7\u6807\u51C6 tool call \u6267\u884C\u3002";
export type DefenseMode = (typeof DEFENSE_MODES)[number];
export type AgentAegisPluginConfig = {
    allDefensesEnabled: boolean;
    defaultBlockingMode: DefenseMode;
    selfProtectionEnabled: boolean;
    selfProtectionMode: DefenseMode;
    commandBlockEnabled: boolean;
    commandBlockMode: DefenseMode;
    encodingGuardEnabled: boolean;
    encodingGuardMode: DefenseMode;
    scriptProvenanceGuardEnabled: boolean;
    scriptProvenanceGuardMode: DefenseMode;
    memoryGuardEnabled: boolean;
    memoryGuardMode: DefenseMode;
    userRiskScanEnabled: boolean;
    skillScanEnabled: boolean;
    toolResultScanEnabled: boolean;
    outputRedactionEnabled: boolean;
    promptGuardEnabled: boolean;
    loopGuardEnabled: boolean;
    loopGuardMode: DefenseMode;
    exfiltrationGuardEnabled: boolean;
    exfiltrationGuardMode: DefenseMode;
    toolCallEnforcementEnabled: boolean;
    dispatchGuardEnabled: boolean;
    dispatchGuardMode: DefenseMode;
    protectedPaths: string[];
    protectedSkills: string[];
    protectedPlugins: string[];
    skillRoots: string[];
    extraProtectedRoots: string[];
    startupSkillScan: boolean;
};
export declare const agentAegisPluginConfigSchema: {
    type: string;
    additionalProperties: boolean;
    properties: {
        allDefensesEnabled: {
            readonly type: "boolean";
            readonly default: true;
        };
        defaultBlockingMode: {
            readonly type: "string";
            readonly enum: readonly ["off", "observe", "enforce"];
            readonly default: "enforce";
        };
        selfProtectionEnabled: {
            readonly type: "boolean";
            readonly default: true;
        };
        selfProtectionMode: {
            readonly type: "string";
            readonly enum: readonly ["off", "observe", "enforce"];
            readonly default: "enforce";
        };
        commandBlockEnabled: {
            readonly type: "boolean";
            readonly default: true;
        };
        commandBlockMode: {
            readonly type: "string";
            readonly enum: readonly ["off", "observe", "enforce"];
            readonly default: "enforce";
        };
        encodingGuardEnabled: {
            readonly type: "boolean";
            readonly default: true;
        };
        encodingGuardMode: {
            readonly type: "string";
            readonly enum: readonly ["off", "observe", "enforce"];
            readonly default: "enforce";
        };
        scriptProvenanceGuardEnabled: {
            readonly type: "boolean";
            readonly default: true;
        };
        scriptProvenanceGuardMode: {
            readonly type: "string";
            readonly enum: readonly ["off", "observe", "enforce"];
            readonly default: "enforce";
        };
        memoryGuardEnabled: {
            readonly type: "boolean";
            readonly default: true;
        };
        memoryGuardMode: {
            readonly type: "string";
            readonly enum: readonly ["off", "observe", "enforce"];
            readonly default: "enforce";
        };
        userRiskScanEnabled: {
            readonly type: "boolean";
            readonly default: true;
        };
        skillScanEnabled: {
            readonly type: "boolean";
            readonly default: true;
        };
        toolResultScanEnabled: {
            readonly type: "boolean";
            readonly default: true;
        };
        outputRedactionEnabled: {
            readonly type: "boolean";
            readonly default: true;
        };
        promptGuardEnabled: {
            readonly type: "boolean";
            readonly default: true;
        };
        loopGuardEnabled: {
            readonly type: "boolean";
            readonly default: true;
        };
        loopGuardMode: {
            readonly type: "string";
            readonly enum: readonly ["off", "observe", "enforce"];
            readonly default: "enforce";
        };
        exfiltrationGuardEnabled: {
            readonly type: "boolean";
            readonly default: true;
        };
        exfiltrationGuardMode: {
            readonly type: "string";
            readonly enum: readonly ["off", "observe", "enforce"];
            readonly default: "enforce";
        };
        toolCallEnforcementEnabled: {
            readonly type: "boolean";
            readonly default: true;
        };
        dispatchGuardEnabled: {
            readonly type: "boolean";
            readonly default: true;
        };
        dispatchGuardMode: {
            readonly type: "string";
            readonly enum: readonly ["off", "observe", "enforce"];
            readonly default: "enforce";
        };
        protectedPaths: {
            type: string;
            items: {
                type: string;
            };
        };
        protectedSkills: {
            type: string;
            items: {
                type: string;
            };
        };
        protectedPlugins: {
            type: string;
            items: {
                type: string;
            };
        };
        skillRoots: {
            type: string;
            items: {
                type: string;
            };
        };
        extraProtectedRoots: {
            type: string;
            items: {
                type: string;
            };
        };
        startupSkillScan: {
            type: string;
            default: boolean;
        };
    };
};
export declare const agentAegisPluginUiHints: {
    allDefensesEnabled: {
        label: string;
        help: string;
    };
    defaultBlockingMode: {
        label: string;
        help: string;
    };
    selfProtectionEnabled: {
        label: string;
        help: string;
    };
    selfProtectionMode: {
        label: string;
        help: string;
    };
    commandBlockEnabled: {
        label: string;
        help: string;
    };
    commandBlockMode: {
        label: string;
        help: string;
    };
    encodingGuardEnabled: {
        label: string;
        help: string;
    };
    encodingGuardMode: {
        label: string;
        help: string;
    };
    scriptProvenanceGuardEnabled: {
        label: string;
        help: string;
    };
    scriptProvenanceGuardMode: {
        label: string;
        help: string;
    };
    memoryGuardEnabled: {
        label: string;
        help: string;
    };
    memoryGuardMode: {
        label: string;
        help: string;
    };
    userRiskScanEnabled: {
        label: string;
        help: string;
    };
    skillScanEnabled: {
        label: string;
        help: string;
    };
    toolResultScanEnabled: {
        label: string;
        help: string;
    };
    outputRedactionEnabled: {
        label: string;
        help: string;
    };
    promptGuardEnabled: {
        label: string;
        help: string;
    };
    loopGuardEnabled: {
        label: string;
        help: string;
    };
    loopGuardMode: {
        label: string;
        help: string;
    };
    exfiltrationGuardEnabled: {
        label: string;
        help: string;
    };
    exfiltrationGuardMode: {
        label: string;
        help: string;
    };
    toolCallEnforcementEnabled: {
        label: string;
        help: string;
    };
    dispatchGuardEnabled: {
        label: string;
        help: string;
    };
    dispatchGuardMode: {
        label: string;
        help: string;
    };
    protectedPaths: {
        label: string;
        help: string;
        advanced: boolean;
        placeholder: string;
    };
    protectedSkills: {
        label: string;
        help: string;
        advanced: boolean;
        placeholder: string;
    };
    protectedPlugins: {
        label: string;
        help: string;
        advanced: boolean;
        placeholder: string;
    };
    startupSkillScan: {
        label: string;
        help: string;
        advanced: boolean;
    };
    skillRoots: {
        label: string;
        help: string;
        advanced: boolean;
        placeholder: string;
    };
    extraProtectedRoots: {
        label: string;
        help: string;
        advanced: boolean;
        placeholder: string;
    };
};
export declare const agentAegisPluginConfigDefinition: {
    jsonSchema: {
        type: string;
        additionalProperties: boolean;
        properties: {
            allDefensesEnabled: {
                readonly type: "boolean";
                readonly default: true;
            };
            defaultBlockingMode: {
                readonly type: "string";
                readonly enum: readonly ["off", "observe", "enforce"];
                readonly default: "enforce";
            };
            selfProtectionEnabled: {
                readonly type: "boolean";
                readonly default: true;
            };
            selfProtectionMode: {
                readonly type: "string";
                readonly enum: readonly ["off", "observe", "enforce"];
                readonly default: "enforce";
            };
            commandBlockEnabled: {
                readonly type: "boolean";
                readonly default: true;
            };
            commandBlockMode: {
                readonly type: "string";
                readonly enum: readonly ["off", "observe", "enforce"];
                readonly default: "enforce";
            };
            encodingGuardEnabled: {
                readonly type: "boolean";
                readonly default: true;
            };
            encodingGuardMode: {
                readonly type: "string";
                readonly enum: readonly ["off", "observe", "enforce"];
                readonly default: "enforce";
            };
            scriptProvenanceGuardEnabled: {
                readonly type: "boolean";
                readonly default: true;
            };
            scriptProvenanceGuardMode: {
                readonly type: "string";
                readonly enum: readonly ["off", "observe", "enforce"];
                readonly default: "enforce";
            };
            memoryGuardEnabled: {
                readonly type: "boolean";
                readonly default: true;
            };
            memoryGuardMode: {
                readonly type: "string";
                readonly enum: readonly ["off", "observe", "enforce"];
                readonly default: "enforce";
            };
            userRiskScanEnabled: {
                readonly type: "boolean";
                readonly default: true;
            };
            skillScanEnabled: {
                readonly type: "boolean";
                readonly default: true;
            };
            toolResultScanEnabled: {
                readonly type: "boolean";
                readonly default: true;
            };
            outputRedactionEnabled: {
                readonly type: "boolean";
                readonly default: true;
            };
            promptGuardEnabled: {
                readonly type: "boolean";
                readonly default: true;
            };
            loopGuardEnabled: {
                readonly type: "boolean";
                readonly default: true;
            };
            loopGuardMode: {
                readonly type: "string";
                readonly enum: readonly ["off", "observe", "enforce"];
                readonly default: "enforce";
            };
            exfiltrationGuardEnabled: {
                readonly type: "boolean";
                readonly default: true;
            };
            exfiltrationGuardMode: {
                readonly type: "string";
                readonly enum: readonly ["off", "observe", "enforce"];
                readonly default: "enforce";
            };
            toolCallEnforcementEnabled: {
                readonly type: "boolean";
                readonly default: true;
            };
            dispatchGuardEnabled: {
                readonly type: "boolean";
                readonly default: true;
            };
            dispatchGuardMode: {
                readonly type: "string";
                readonly enum: readonly ["off", "observe", "enforce"];
                readonly default: "enforce";
            };
            protectedPaths: {
                type: string;
                items: {
                    type: string;
                };
            };
            protectedSkills: {
                type: string;
                items: {
                    type: string;
                };
            };
            protectedPlugins: {
                type: string;
                items: {
                    type: string;
                };
            };
            skillRoots: {
                type: string;
                items: {
                    type: string;
                };
            };
            extraProtectedRoots: {
                type: string;
                items: {
                    type: string;
                };
            };
            startupSkillScan: {
                type: string;
                default: boolean;
            };
        };
    };
    uiHints: {
        allDefensesEnabled: {
            label: string;
            help: string;
        };
        defaultBlockingMode: {
            label: string;
            help: string;
        };
        selfProtectionEnabled: {
            label: string;
            help: string;
        };
        selfProtectionMode: {
            label: string;
            help: string;
        };
        commandBlockEnabled: {
            label: string;
            help: string;
        };
        commandBlockMode: {
            label: string;
            help: string;
        };
        encodingGuardEnabled: {
            label: string;
            help: string;
        };
        encodingGuardMode: {
            label: string;
            help: string;
        };
        scriptProvenanceGuardEnabled: {
            label: string;
            help: string;
        };
        scriptProvenanceGuardMode: {
            label: string;
            help: string;
        };
        memoryGuardEnabled: {
            label: string;
            help: string;
        };
        memoryGuardMode: {
            label: string;
            help: string;
        };
        userRiskScanEnabled: {
            label: string;
            help: string;
        };
        skillScanEnabled: {
            label: string;
            help: string;
        };
        toolResultScanEnabled: {
            label: string;
            help: string;
        };
        outputRedactionEnabled: {
            label: string;
            help: string;
        };
        promptGuardEnabled: {
            label: string;
            help: string;
        };
        loopGuardEnabled: {
            label: string;
            help: string;
        };
        loopGuardMode: {
            label: string;
            help: string;
        };
        exfiltrationGuardEnabled: {
            label: string;
            help: string;
        };
        exfiltrationGuardMode: {
            label: string;
            help: string;
        };
        toolCallEnforcementEnabled: {
            label: string;
            help: string;
        };
        dispatchGuardEnabled: {
            label: string;
            help: string;
        };
        dispatchGuardMode: {
            label: string;
            help: string;
        };
        protectedPaths: {
            label: string;
            help: string;
            advanced: boolean;
            placeholder: string;
        };
        protectedSkills: {
            label: string;
            help: string;
            advanced: boolean;
            placeholder: string;
        };
        protectedPlugins: {
            label: string;
            help: string;
            advanced: boolean;
            placeholder: string;
        };
        startupSkillScan: {
            label: string;
            help: string;
            advanced: boolean;
        };
        skillRoots: {
            label: string;
            help: string;
            advanced: boolean;
            placeholder: string;
        };
        extraProtectedRoots: {
            label: string;
            help: string;
            advanced: boolean;
            placeholder: string;
        };
    };
};
export declare function resolveAgentAegisPluginConfig(params: {
    pluginConfig?: Record<string, unknown>;
    resolvePath: (input: string) => string;
}): AgentAegisPluginConfig;
export declare function resolveAgentAegisPluginConfigFromApi(api: OpenClawPluginApi): AgentAegisPluginConfig;
export declare function resolveAgentAegisStateDir(api: OpenClawPluginApi): string;
export declare function resolveSkillScanRoots(api: OpenClawPluginApi): string[];
