/** Exec-time pulse shims (docs/PUSH.md "Shims"). */
export { BUILTIN_TOOLS, DEFAULT_COMMANDS, WORLD_WORDS, classify, specFor, parsePatterns, hasWorldWord, type ToolSpec, type Classification } from './rules.js';
export { posixShim, cmdShim, ps1Shim, decisionSh, SHIM_MARKER, type ShimParams } from './script.js';
export { pulse, ack, cursorAt, retractionLine, PULSE_DENY_EXIT, PULSE_UNAVAILABLE_EXIT, type PulseOptions, type PulseResult, type PulseDecision, type PulseMode, type AckResult } from './pulse.js';
export { install, uninstall, status, execShim, resolveReal, forbiddenDir, type InstallOptions, type InstallReport, type StatusReport, type ShimConfig } from './install.js';
