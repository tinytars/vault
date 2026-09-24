import { describe, it, expect } from "vitest";
import {
  encryptVault,
  decryptVault,
  generateAccountKeypair,
  deriveKekFromPassword,
  kekFromPrfSecret,
  wrapPrivateKey,
  unwrapPrivateKey,
  generateDEK,
  wrapDEKForPublicKey,
  unwrapDEKWithPrivateKey,
  encryptVaultV2,
  decryptVaultV2,
  deriveAuthHash,
  encryptBytes,
  decryptBytes,
  isHD1,
} from "../crypto";

const rand = (n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n));

// Any JSON-serializable payload works — the envelope functions are generic over it. This shape
// is arbitrary; it exists to give the roundtrip tests something with nested structure to compare.
interface Sample {
  clients: Record<
    string,
    {
      displayName: string;
      dob: string;
      gender: string;
      watchlist: string[];
      results: { marker: string; group: string; source: string; date: string; value: number; unit: string }[];
      factors: Record<string, string | number>;
    }
  >;
}

const sample: Sample = {
  clients: {
    Alice: {
      displayName: "Alice",
      dob: "1990-01-01",
      gender: "female",
      watchlist: ["ApoB", "Vitamin D"],
      results: [
        { marker: "ApoB", group: "Lipids", source: "Blood", date: "2026-01-01", value: 90, unit: "mg/dL" },
      ],
      factors: { height: "5ft 5in", bmi: 23 },
    },
  },
};

describe("crypto", () => {
  it("roundtrips a payload with the same passphrase", async () => {
    const blob = await encryptVault(sample, "secret");
    const back = await decryptVault(blob, "secret");
    expect(back).toEqual(sample);
  });

  it("rejects the wrong passphrase", async () => {
    const blob = await encryptVault(sample, "secret");
    await expect(decryptVault(blob, "WRONG")).rejects.toThrow(/wrong passphrase|corrupt/);
  });

  it("produces an HD1-prefixed blob", async () => {
    const blob = await encryptVault(sample, "x");
    expect(blob[0]).toBe(0x48); // H
    expect(blob[1]).toBe(0x44); // D
    expect(blob[2]).toBe(0x31); // 1
  });

  it("rejects a non-HD1 blob", async () => {
    const garbage = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]);
    await expect(decryptVault(garbage, "x")).rejects.toThrow();
  });

  it("produces a different ciphertext on each encryption (fresh salt + iv)", async () => {
    const a = await encryptVault(sample, "secret");
    const b = await encryptVault(sample, "secret");
    expect(a).not.toEqual(b);
  });
});

describe("crypto v2 (envelope encryption)", () => {
  it("roundtrips a payload under a random DEK", async () => {
    const dek = await generateDEK();
    const blob = await encryptVaultV2(sample, dek);
    expect(await decryptVaultV2<Sample>(blob, dek)).toEqual(sample);
  });

  it("writes an HD1 v2 header (magic + version byte 2, 32-byte header)", async () => {
    const blob = await encryptVaultV2(sample, await generateDEK());
    expect([blob[0], blob[1], blob[2]]).toEqual([0x48, 0x44, 0x31]);
    expect(blob[3]).toBe(2);
    expect(blob.length).toBeGreaterThanOrEqual(32);
  });

  it("keeps v1 and v2 paths separate (clear cross errors)", async () => {
    const v1 = await encryptVault(sample, "pw");
    const v2 = await encryptVaultV2(sample, await generateDEK());
    await expect(decryptVault(v2, "pw")).rejects.toThrow(/v2 envelope/);
    await expect(decryptVaultV2(v1, await generateDEK())).rejects.toThrow(/expected HD1 v2/);
  });

  it("owner can open the vault via their DEK envelope", async () => {
    const owner = await generateAccountKeypair();
    const dek = await generateDEK();
    const blob = await encryptVaultV2(sample, dek);
    const env = await wrapDEKForPublicKey(dek, owner.publicKeyJwk);
    const dek2 = await unwrapDEKWithPrivateKey(env.wrappedDEK, env.ephemeralPublicKeyJwk, owner.privateKey);
    expect(await decryptVaultV2<Sample>(blob, dek2)).toEqual(sample);
  });

  it("grants a second principal by re-wrapping the same DEK (escrow)", async () => {
    const owner = await generateAccountKeypair();
    const provider = await generateAccountKeypair();
    const dek = await generateDEK();
    const blob = await encryptVaultV2(sample, dek);
    const provEnv = await wrapDEKForPublicKey(dek, provider.publicKeyJwk);
    const provDek = await unwrapDEKWithPrivateKey(provEnv.wrappedDEK, provEnv.ephemeralPublicKeyJwk, provider.privateKey);
    expect(await decryptVaultV2<Sample>(blob, provDek)).toEqual(sample);
    // owner's key must NOT open the provider's envelope
    await expect(
      unwrapDEKWithPrivateKey(provEnv.wrappedDEK, provEnv.ephemeralPublicKeyJwk, owner.privateKey),
    ).rejects.toThrow(/cannot unwrap DEK/);
  });

  it("wraps/unwraps the private key under a password KEK, and re-derived DEK opens", async () => {
    const { publicKeyJwk, privateKey } = await generateAccountKeypair();
    const salt = rand(16);
    const wrapped = await wrapPrivateKey(privateKey, await deriveKekFromPassword("hunter2", salt));
    // fresh session: re-derive KEK from the same password+salt, unwrap, then use it
    const priv = await unwrapPrivateKey(wrapped, await deriveKekFromPassword("hunter2", salt));
    const dek = await generateDEK();
    const env = await wrapDEKForPublicKey(dek, publicKeyJwk);
    const dek2 = await unwrapDEKWithPrivateKey(env.wrappedDEK, env.ephemeralPublicKeyJwk, priv);
    expect(await decryptVaultV2<Sample>(await encryptVaultV2(sample, dek), dek2)).toEqual(sample);
  });

  it("an unwrapped private key can be RE-WRAPPED (add-method / recovery-regen path)", async () => {
    // Regression guard: unwrapPrivateKey must return an extractable key, else adding a login
    // method or regenerating a recovery code (both re-wrap a login-unwrapped key) throws "key is
    // not extractable".
    const { privateKey } = await generateAccountKeypair();
    const salt = rand(16);
    const unwrapped = await unwrapPrivateKey(await wrapPrivateKey(privateKey, await deriveKekFromPassword("pw", salt)), await deriveKekFromPassword("pw", salt));
    // re-wrap the UNWRAPPED key under a new KEK, then unwrap again — must round-trip
    const salt2 = rand(16);
    const rewrapped = await wrapPrivateKey(unwrapped, await deriveKekFromPassword("pw2", salt2));
    await expect(unwrapPrivateKey(rewrapped, await deriveKekFromPassword("pw2", salt2))).resolves.toBeDefined();
  });

  it("rejects the wrong password when unwrapping the private key", async () => {
    const { privateKey } = await generateAccountKeypair();
    const salt = rand(16);
    const wrapped = await wrapPrivateKey(privateKey, await deriveKekFromPassword("right", salt));
    await expect(
      unwrapPrivateKey(wrapped, await deriveKekFromPassword("wrong", salt)),
    ).rejects.toThrow(/cannot unwrap private key/);
  });

  it("wraps/unwraps the private key under a passkey PRF secret", async () => {
    const { privateKey } = await generateAccountKeypair();
    const prf = rand(32);
    const wrapped = await wrapPrivateKey(privateKey, await kekFromPrfSecret(prf));
    await expect(unwrapPrivateKey(wrapped, await kekFromPrfSecret(prf))).resolves.toBeDefined();
    await expect(unwrapPrivateKey(wrapped, await kekFromPrfSecret(rand(32)))).rejects.toThrow();
  });
});

describe("deriveAuthHash", () => {
  it("is deterministic for the same password and salt", async () => {
    const salt = rand(16);
    expect(await deriveAuthHash("hunter2", salt)).toBe(await deriveAuthHash("hunter2", salt));
  });

  it("differs for a different salt", async () => {
    const a = await deriveAuthHash("hunter2", rand(16));
    const b = await deriveAuthHash("hunter2", rand(16));
    expect(a).not.toBe(b);
  });

  it("returns a stable ~43-char base64url string, distinct from the KEK path", async () => {
    const hash = await deriveAuthHash("hunter2", rand(16));
    expect(hash).toMatch(/^[A-Za-z0-9_-]{40,44}$/);
  });
});

// ── v3: the same envelope over opaque bytes ──────────────────────────────────
// What the file-at-rest path needs from it: a PDF comes back byte-identical, a blob sealed to
// someone else's key does not open, and v2 and v3 are never mistaken for one another.
describe("HD1 v3 (bytes)", () => {
  const pdf = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37, ...rand(4096)]);

  it("round-trips arbitrary bytes unchanged", async () => {
    const dek = await generateDEK();
    expect(await decryptBytes(await encryptBytes(pdf, dek), dek)).toEqual(pdf);
  });

  it("round-trips an empty payload", async () => {
    const dek = await generateDEK();
    expect(await decryptBytes(await encryptBytes(new Uint8Array(0), dek), dek)).toEqual(new Uint8Array(0));
  });

  it("writes an HD1 v3 header and hides the plaintext", async () => {
    const blob = await encryptBytes(pdf, await generateDEK());
    expect([blob[0], blob[1], blob[2], blob[3]]).toEqual([0x48, 0x44, 0x31, 3]);
    // The decisive property for at-rest storage: the stored object is not the document.
    expect(blob.slice(32, 36)).not.toEqual(pdf.slice(0, 4));
    expect(blob.length).toBe(32 + pdf.length + 16); // header + ciphertext + GCM tag
  });

  it("refuses a wrong key rather than returning garbage", async () => {
    const blob = await encryptBytes(pdf, await generateDEK());
    await expect(decryptBytes(blob, await generateDEK())).rejects.toThrow(/wrong DEK or corrupt blob/);
  });

  it("refuses a tampered payload (the GCM tag is load-bearing)", async () => {
    const dek = await generateDEK();
    const blob = await encryptBytes(pdf, dek);
    blob[40] ^= 0xff;
    await expect(decryptBytes(blob, dek)).rejects.toThrow(/wrong DEK or corrupt blob/);
  });

  it("refuses a truncated blob and a non-HD1 blob", async () => {
    const dek = await generateDEK();
    await expect(decryptBytes(new Uint8Array(20), dek)).rejects.toThrow(/blob too short/);
    await expect(decryptBytes(new Uint8Array(64), dek)).rejects.toThrow(/not an HD1 blob/);
  });

  it("keeps v2 and v3 unconfusable in both directions", async () => {
    const dek = await generateDEK();
    const v2 = await encryptVaultV2(sample, dek);
    const v3 = await encryptBytes(pdf, dek);
    await expect(decryptBytes(v2, dek)).rejects.toThrow(/expected HD1 v3, got version 2/);
    await expect(decryptVaultV2(v3, dek)).rejects.toThrow(/expected HD1 v2, got version 3/);
    await expect(decryptVault(v3, "pw")).rejects.toThrow(/v3 bytes blob/);
  });

  it("isHD1 separates a sealed object from plaintext, for a store mid-migration", async () => {
    expect(isHD1(await encryptBytes(pdf, await generateDEK()))).toBe(true);
    expect(isHD1(await encryptVaultV2(sample, await generateDEK()))).toBe(true);
    expect(isHD1(pdf)).toBe(false);
    expect(isHD1(new Uint8Array(4))).toBe(false); // shorter than a header
  });
});
