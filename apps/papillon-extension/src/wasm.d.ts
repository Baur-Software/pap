/**
 * Type declarations for the @pap/sdk WASM module.
 *
 * These types mirror the wasm-bindgen exports from crates/pap-wasm/src/lib.rs.
 * The actual .wasm and .js files are build artifacts from `wasm-pack build`.
 */

declare module "pap-wasm" {
  export default function init(wasmUrl?: string | URL): Promise<void>;

  export class PrincipalKeypair {
    static generate(): PrincipalKeypair;
    static fromSecretBytes(bytes: Uint8Array): PrincipalKeypair;
    did(): string;
    publicKeyBytes(): Uint8Array;
    sign(message: Uint8Array): Uint8Array;
    free(): void;
  }

  export class SessionKeypair {
    static generate(): SessionKeypair;
    did(): string;
    publicKeyBytes(): Uint8Array;
    signing_key(): unknown;
    free(): void;
  }

  export class ScopeAction {
    static new(action: string): ScopeAction;
    static withObject(action: string, object: string): ScopeAction;
    action(): string;
    object(): string | undefined;
    free(): void;
  }

  export class Scope {
    static new(actions: ScopeAction[]): Scope;
    static denyAll(): Scope;
    permits(action: string): boolean;
    contains(child: Scope): boolean;
    free(): void;
  }

  export class DisclosureEntry {
    static new(
      schemaType: string,
      permitted: string[],
      prohibited: string[]
    ): DisclosureEntry;
    setSessionOnly(value: boolean): void;
    setNoRetention(value: boolean): void;
    free(): void;
  }

  export class DisclosureSet {
    static empty(): DisclosureSet;
    static new(entries: DisclosureEntry[]): DisclosureSet;
    free(): void;
  }

  export class Mandate {
    static issueRoot(
      principalDid: string,
      agentDid: string,
      scope: Scope,
      disclosureSet: DisclosureSet,
      ttlRfc3339: string
    ): Mandate;
    delegate(
      agentDid: string,
      scope: Scope,
      disclosureSet: DisclosureSet,
      ttlRfc3339: string
    ): Mandate;
    sign(keypair: PrincipalKeypair): void;
    signableBytes(): Uint8Array;
    setSignatureBytes(sig: Uint8Array): void;
    verify(publicKeyBytes: Uint8Array): void;
    toJson(): string;
    static fromJson(json: string): Mandate;
    hash(): string;
    decayState(): string;
    computeDecayState(decayWindowSecs: number): string;
    syncDecayState(decayWindowSecs: number): void;
    transitionDecay(nextState: string): void;
    isExpired(): boolean;
    principalDid(): string;
    agentDid(): string;
    issuerDid(): string;
    ttl(): string;
    free(): void;
  }

  export class CapabilityToken {
    static mint(
      targetDid: string,
      action: string,
      issuerDid: string,
      expiresAtRfc3339: string
    ): CapabilityToken;
    sign(keypair: PrincipalKeypair | SessionKeypair | unknown): void;
    signableBytes(): Uint8Array;
    setSignatureBytes(sig: Uint8Array): void;
    toJson(): string;
    static fromJson(json: string): CapabilityToken;
    free(): void;
  }

  export class Session {
    static initiate(
      token: CapabilityToken,
      receiverDid: string,
      issuerPublicKeyBytes: Uint8Array
    ): Session;
    open(
      initiatorSessionDid: string,
      receiverSessionDid: string
    ): void;
    execute(): void;
    close(): void;
    state(): string;
    id(): string;
    free(): void;
  }

  export function didToPublicKeyBytes(did: string): Uint8Array;
  export function publicKeyBytesToDid(bytes: Uint8Array): string;
}
