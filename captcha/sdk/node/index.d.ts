export type ChallengeType =
  | 'text'
  | 'click_text'
  | 'click_icon'
  | 'slide'
  | 'scratch'
  | 'semantic'
  | 'rotate'
  | 'sms'
  | 'email';

export interface Point {
  x: number;
  y: number;
}

export interface TrackPoint extends Point {
  t: number;
  kind?: string;
}

export interface Track {
  started_at?: number;
  ended_at?: number;
  points?: TrackPoint[];
}

export interface Answer {
  text?: string;
  code?: string;
  points?: Point[];
  offset?: number;
  offset_y?: number;
  angle?: number;
  track?: Track;
}

export interface Signals {
  user_agent?: string;
  platform?: string;
  language?: string;
  languages?: string[];
  timezone?: string;
  screen_width?: number;
  screen_height?: number;
  color_depth?: number;
  device_memory?: number;
  hardware_concurrency?: number;
  touch?: boolean;
  webdriver?: boolean;
  headless?: boolean;
  canvas_hash?: string;
  webgl_hash?: string;
  audio_hash?: string;
  plugins?: number;
  cookie_enabled?: boolean;
  do_not_track?: string;
  mouse_entropy?: number;
  key_entropy?: number;
  visibility?: string;
  screen_capture?: boolean;
  screenshot_key?: boolean;
  print_attempt?: boolean;
  page_hidden?: boolean;
  focus_loss?: number;
}

export interface PoWChallenge {
  algorithm: string;
  seed: string;
  difficulty: number;
}

export interface PoWProof {
  nonce: number;
}

export interface ImageDescriptor {
  name: string;
  url: string;
  width: number;
  height: number;
  mime: string;
}

export interface Challenge {
  id: string;
  type: ChallengeType;
  action: string;
  locale: string;
  prompt: { text: string; hint?: string; count?: number };
  images?: ImageDescriptor[];
  pow?: PoWChallenge;
  channel?: 'sms' | 'email';
  target?: string;
  expires_in: number;
}

export interface VerifyResult {
  token: string;
  expires_in: number;
  action: string;
}

export interface TokenClaims {
  cid: string;
  act: string;
  sub?: string;
  iat: number;
  exp: number;
  risk: number;
  jti: string;
  iss?: string;
}

export interface ClientOptions {
  endpoint?: string;
  fetch?: typeof fetch;
  headers?: Record<string, string>;
  timeout?: number;
  secret?: string | Uint8Array;
  keys?: Record<string, string | Uint8Array>;
  issuer?: string;
}

export interface VerifyTokenOptions {
  secret?: string | Uint8Array;
  keys?: Record<string, string | Uint8Array>;
  issuer?: string;
}

export declare class CaptchaError extends Error {
  code: string;
  status: number;
  retryAfter: number;
}

export declare function solvePoW(pow: PoWChallenge): Promise<PoWProof>;
export declare function verifyToken(
  token: string,
  action: string,
  options?: VerifyTokenOptions
): TokenClaims;

export interface Client {
  endpoint: string;
  challenge(body?: Record<string, unknown>): Promise<Challenge>;
  verify(body: Record<string, unknown>): Promise<VerifyResult>;
  send(body: Record<string, unknown>): Promise<Challenge>;
  consume(body: { token: string; action: string }): Promise<TokenClaims>;
  verifyToken(token: string, action: string): TokenClaims;
  solvePoW: typeof solvePoW;
}

export declare function createClient(options?: ClientOptions): Client;
