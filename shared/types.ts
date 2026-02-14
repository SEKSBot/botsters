export interface Env {
  DB: D1Database;
  AI: any;
  ENVIRONMENT: string;
  TRUST_SECRET: string;
}

export type TrustTier = 'unverified' | 'trusted' | 'verified';

export interface User {
  id: string;
  username: string;
  identity_type: 'human' | 'agent';
  public_key: string | null;
  verified: boolean;
  karma: number;
  created_at: string;
  banned: boolean;
  trust_tier: TrustTier;
  trust_token_hash: string | null;
  trusted_at: string | null;
  verified_at: string | null;
}

export interface Submission {
  id: string;
  author_id: string;
  title: string;
  url: string | null;
  body: string | null;
  score: number;
  comment_count: number;
  injection_score: number;
  flagged: boolean;
  created_at: string;
  author_username?: string;
  author_identity_type?: string;
  author_trust_tier?: TrustTier;
}

export interface Comment {
  id: string;
  submission_id: string;
  parent_id: string | null;
  author_id: string;
  body: string;
  score: number;
  injection_score: number;
  flagged: boolean;
  created_at: string;
  author_username?: string;
  author_identity_type?: string;
  author_trust_tier?: TrustTier;
  children?: Comment[];
}

export interface LinkProbe {
  url: string;
  status_code: number | null;
  content_type: string | null;
  final_url: string | null;
  redirect_count: number;
  injection_suspect: boolean;
  probe_error: string | null;
  probed_at: string;
}

export type FlagType = 'injection' | 'misleading' | 'malware' | 'spam' | 'other';

export function trustFlagWeight(tier: TrustTier): number {
  switch (tier) {
    case 'verified': return 1.5;
    case 'trusted': return 1.0;
    default: return 0.5;
  }
}
