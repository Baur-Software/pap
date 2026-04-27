/**
 * Docker Compose helpers for the federation E2E test suite.
 *
 * Manages a 4-registry cluster (A, B, C, D) using docker-compose.federation.yml.
 * Each Playwright worker gets its own port offset so clusters don't collide:
 *
 *   worker 0: A=7900, B=7901, C=7902, D=7903
 *   worker 1: A=7910, B=7911, C=7912, D=7913
 *   worker 2: A=7920, B=7921, C=7922, D=7923
 *   worker 3: A=7930, B=7931, C=7932, D=7933
 */

import { spawnSync } from "child_process";
import * as path from "path";

const COMPOSE_FILE = path.join(__dirname, "..", "docker-compose.federation.yml");
const BASE_PORT = 7900;
const PORT_STRIDE = 10;
const REGISTRY_NAMES = ["a", "b", "c", "d"] as const;
type RegistryName = (typeof REGISTRY_NAMES)[number];

/** Port for a given registry letter and Playwright worker index. */
export function registryPort(
  letter: RegistryName,
  workerIndex: number
): number {
  const offset = REGISTRY_NAMES.indexOf(letter);
  return BASE_PORT + workerIndex * PORT_STRIDE + offset;
}

/** Base URL for a given registry letter and worker index. */
export function registryUrl(
  letter: RegistryName,
  workerIndex: number
): string {
  return `https://localhost:${registryPort(letter, workerIndex)}`;
}

/** Docker container name for a given letter + worker. */
function containerName(letter: RegistryName, workerIndex: number): string {
  return `registry-${letter}-worker${workerIndex}`;
}

/** Build the env overrides for docker compose so ports don't collide between workers. */
function portEnv(workerIndex: number): Record<string, string> {
  return {
    PAP_PORT_A: String(registryPort("a", workerIndex)),
    PAP_PORT_B: String(registryPort("b", workerIndex)),
    PAP_PORT_C: String(registryPort("c", workerIndex)),
    PAP_PORT_D: String(registryPort("d", workerIndex)),
    // Override container names so multiple workers don't conflict
    COMPOSE_PROJECT_NAME: `federation-test-worker${workerIndex}`,
  };
}

/** Start the 4-registry federation cluster and wait until all are healthy. */
export async function startFederationCluster(
  workerIndex: number
): Promise<void> {
  const env = { ...process.env, ...portEnv(workerIndex) };

  spawnSync(
    "docker",
    [
      "compose",
      "-f",
      COMPOSE_FILE,
      "-p",
      `federation-test-worker${workerIndex}`,
      "up",
      "-d",
      "--remove-orphans",
    ],
    { env, stdio: "inherit" }
  );

  // Wait until all 4 registries respond on their /federation/identity endpoint
  await Promise.all(
    REGISTRY_NAMES.map((letter) =>
      waitForRegistry(registryUrl(letter, workerIndex))
    )
  );
}

/** Stop and remove the federation cluster for this worker. */
export function stopFederationCluster(workerIndex: number): void {
  const env = { ...process.env, ...portEnv(workerIndex) };
  spawnSync(
    "docker",
    [
      "compose",
      "-f",
      COMPOSE_FILE,
      "-p",
      `federation-test-worker${workerIndex}`,
      "down",
      "-v",
      "--remove-orphans",
    ],
    { env, stdio: "inherit" }
  );
}

/** Reset a single registry's database by restarting the container with a fresh tmpfs. */
export function resetRegistryDB(
  workerIndex: number,
  name: RegistryName
): void {
  const env = { ...process.env, ...portEnv(workerIndex) };
  spawnSync(
    "docker",
    [
      "compose",
      "-f",
      COMPOSE_FILE,
      "-p",
      `federation-test-worker${workerIndex}`,
      "restart",
      `registry-${name}`,
    ],
    { env, stdio: "inherit" }
  );
}

/** Get logs for a registry container (last N lines). */
export function getRegistryLogs(
  workerIndex: number,
  name: RegistryName,
  lines = 100
): string {
  const cname = containerName(name, workerIndex);
  const result = spawnSync(
    "docker",
    ["logs", "--tail", String(Math.floor(lines)), cname],
    { encoding: "utf8", stdio: "pipe" }
  );
  if (result.error || result.status !== 0) {
    return `[could not get logs for ${cname}]`;
  }
  return (result.stdout ?? "") + (result.stderr ?? "");
}

/** Poll a registry until it responds on /federation/identity (max 30s). */
async function waitForRegistry(url: string, timeoutMs = 30_000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(`${url}/federation/identity`, {
        // @ts-ignore — Node 18 fetch doesn't support rejectUnauthorized directly;
        // use the global agent approach below for real TLS skip
        signal: AbortSignal.timeout(2_000),
      });
      if (res.ok) return;
    } catch {
      // Not up yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`Registry at ${url} did not become healthy within ${timeoutMs}ms`);
}
