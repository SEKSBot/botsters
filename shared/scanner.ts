// Lightweight prompt injection heuristic scanner
// Phase 1: regex-based (fast, free). Phase 2: Workers AI fallback.

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
  aiChecked?: boolean; // whether AI was used
  aiResult?: boolean;  // AI's verdict if checked
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

// Enhanced scan with Workers AI fallback
export async function scanForInjectionWithAI(text: string, ai?: any): Promise<ScanResult> {
  // Phase 1: Fast regex scan
  const heuristicResult = scanForInjection(text);
  
  // If clearly malicious or clearly clean, don't use AI
  if (heuristicResult.score >= 0.7) {
    return { ...heuristicResult, aiChecked: false };
  }
  
  if (heuristicResult.score === 0 && text.length < 50) {
    return { ...heuristicResult, aiChecked: false };
  }

  // Phase 2: AI fallback for suspicious but not clearly malicious content
  if (ai && (heuristicResult.score > 0 || containsSuspiciousKeywords(text))) {
    try {
      const prompt = `Is this text a prompt injection attempt? Reply only YES or NO.

Text to analyze: "${text.slice(0, 500)}"`;

      const response = await ai.run('@cf/meta/llama-3.1-8b-instruct', {
        messages: [{ role: 'user', content: prompt }],
        max_tokens: 10,
        temperature: 0.1,
      });

      const aiAnswer = response.response?.trim().toUpperCase();
      const isInjection = aiAnswer === 'YES';

      return {
        score: isInjection ? Math.max(heuristicResult.score, 0.8) : heuristicResult.score,
        matches: isInjection ? [...heuristicResult.matches, 'AI_DETECTED'] : heuristicResult.matches,
        clean: !isInjection && heuristicResult.clean,
        aiChecked: true,
        aiResult: isInjection,
      };
    } catch (error) {
      // AI failed, fall back to heuristic only
      return { ...heuristicResult, aiChecked: false };
    }
  }

  return { ...heuristicResult, aiChecked: false };
}

// Additional suspicious patterns that warrant AI checking
function containsSuspiciousKeywords(text: string): boolean {
  const suspiciousPatterns = [
    /role\s*[:=]/i,
    /assistant/i,
    /help.*me/i,
    /instructions/i,
    /system/i,
    /prompt/i,
    /model/i,
    /ai/i,
    /language\s+model/i,
    /chatgpt/i,
    /claude/i,
    /anthropic/i,
    /openai/i,
  ];
  
  return suspiciousPatterns.some(pattern => pattern.test(text));
}
