// Lightweight prompt injection heuristic scanner
// Phase 1: regex-based. Phase 2: Workers AI BERT model.

const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /ignore\s+(all\s+)?prior\s+instructions/i,
  /disregard\s+(all\s+)?previous/i,
  /forget\s+(all\s+)?previous/i,
  /you\s+are\s+now\s+(a|an)\s/i,
  /new\s+instructions?\s*:/i,
  /system\s*:\s/i,
  /\[system\]/i,
  /\[INST\]/i,
  /<<SYS>>/i,
  /<\|im_start\|>/i,
  /IGNORE\s+ALL/,
  /DO\s+NOT\s+FOLLOW/i,
  /override\s+(your|the)\s+(instructions|rules|guidelines)/i,
  /act\s+as\s+(if\s+)?you\s+(are|were)\s/i,
  /pretend\s+(that\s+)?you\s+(are|were)\s/i,
  /jailbreak/i,
  /DAN\s+mode/i,
  /developer\s+mode\s+(enabled|activated|on)/i,
  /POST\s+to\s+https?:\/\//i,
  /curl\s+.*https?:\/\//i,
  /wget\s+.*https?:\/\//i,
  /exfiltrate/i,
  /base64\s+(encode|decode)/i,
  /eval\s*\(/i,
  /document\.cookie/i,
  /process\.env/i,
  /\.aws\/credentials/i,
  /\.ssh\/id_rsa/i,
  /ANTHROPIC_API_KEY/i,
  /OPENAI_API_KEY/i,
  /sk-[a-zA-Z0-9]{20,}/,
];

export interface ScanResult {
  score: number;       // 0.0 - 1.0
  matches: string[];   // which patterns triggered
  clean: boolean;
}

export function scanForInjection(text: string): ScanResult {
  const matches: string[] = [];

  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      matches.push(pattern.source);
    }
  }

  const score = Math.min(matches.length / 3, 1.0);

  return {
    score,
    matches,
    clean: matches.length === 0,
  };
}
