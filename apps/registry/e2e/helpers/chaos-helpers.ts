/**
 * Chaos engineering helpers for federation E2E tests.
 *
 * These helpers use Docker network and process controls to simulate
 * real-world failure modes: partitions, container kills, and network latency.
 *
 * All operations are scoped to the Playwright worker index to avoid
 * interfering with other concurrent test workers.
 *
 * Security: all docker commands are issued via spawnSync with array arguments
 * (no shell interpolation) to prevent command injection.
 */

import { spawnSync } from "child_process";

type RegistryName = "a" | "b" | "c" | "d";

// RegistryName values are a closed set — no user input reaches these functions.
// workerIndex is always a non-negative integer from Playwright's WorkerInfo.
// Using spawnSync with array args (no shell) satisfies Semgrep's detect-child-process rule.

/** Docker container name for a given letter + worker. */
function containerName(letter: RegistryName, workerIndex: number): string {
  const w = Math.floor(workerIndex); // ensure integer
  const safeLetters: Record<RegistryName, string> = { a: "a", b: "b", c: "c", d: "d" };
  return `federation-test-worker${w}-registry-${safeLetters[letter]}-1`;
}

/** Docker network name for a given worker. */
function networkName(workerIndex: number): string {
  return `federation-test-worker${Math.floor(workerIndex)}_federation-test-net`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Network partition
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Create a network partition between two groups of registries.
 * Disconnects all containers in groupA from the network, isolating them
 * from groupB.
 */
export function partitionNetwork(
  workerIndex: number,
  groupA: RegistryName[],
  _groupB: RegistryName[]
): void {
  const net = networkName(workerIndex);
  for (const name of groupA) {
    spawnSync("docker", ["network", "disconnect", net, containerName(name, workerIndex)], {
      stdio: "pipe",
    });
  }
}

/**
 * Reconnect containers that were previously disconnected from the network.
 */
export function reconnectNetwork(
  workerIndex: number,
  containers: RegistryName[]
): void {
  const net = networkName(workerIndex);
  for (const name of containers) {
    spawnSync("docker", ["network", "connect", net, containerName(name, workerIndex)], {
      stdio: "pipe",
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Container lifecycle
// ─────────────────────────────────────────────────────────────────────────────

/** Kill a registry container abruptly (SIGKILL). */
export function killRegistry(workerIndex: number, name: RegistryName): void {
  spawnSync("docker", ["kill", containerName(name, workerIndex)], { stdio: "pipe" });
}

/** Start a previously killed container after a delay. */
export function restartWithDelay(
  workerIndex: number,
  name: RegistryName,
  delayMs: number
): void {
  const cname = containerName(name, workerIndex);
  setTimeout(() => {
    spawnSync("docker", ["start", cname], { stdio: "pipe" });
  }, delayMs);
}

// ─────────────────────────────────────────────────────────────────────────────
// Network latency (via tc netem)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Add artificial network delay to a registry container's eth0 interface.
 * Requires NET_ADMIN capability on the container.
 */
export function addNetworkDelay(
  workerIndex: number,
  name: RegistryName,
  delayMs: number
): void {
  // Validate delayMs is a safe integer before converting to string arg
  const safeDelay = `${Math.floor(Math.abs(delayMs))}ms`;
  spawnSync(
    "docker",
    [
      "exec",
      containerName(name, workerIndex),
      "tc", "qdisc", "add", "dev", "eth0", "root", "netem", "delay", safeDelay,
    ],
    { stdio: "pipe" }
  );
}

/**
 * Remove all traffic control rules from a registry's eth0 interface,
 * restoring normal network speed.
 */
export function resetNetworkEffects(
  workerIndex: number,
  name: RegistryName
): void {
  spawnSync(
    "docker",
    ["exec", containerName(name, workerIndex), "tc", "qdisc", "del", "dev", "eth0", "root"],
    { stdio: "pipe" }
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Wait utilities
// ─────────────────────────────────────────────────────────────────────────────

/** Wait for a container to pass its healthcheck after a restart. */
export async function waitForContainerHealthy(
  workerIndex: number,
  name: RegistryName,
  timeoutMs = 30_000
): Promise<void> {
  const cname = containerName(name, workerIndex);
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const result = spawnSync(
      "docker",
      ["inspect", "--format={{.State.Health.Status}}", cname],
      { encoding: "utf8", stdio: "pipe" }
    );
    if (result.stdout?.trim() === "healthy") return;
    await new Promise((r) => setTimeout(r, 1_000));
  }
  throw new Error(
    `Container ${cname} did not become healthy within ${timeoutMs}ms`
  );
}
