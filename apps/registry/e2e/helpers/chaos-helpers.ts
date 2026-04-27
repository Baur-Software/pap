/**
 * Chaos engineering helpers for federation E2E tests.
 *
 * These helpers use Docker network and process controls to simulate
 * real-world failure modes: partitions, container kills, and network latency.
 *
 * All operations are scoped to the Playwright worker index to avoid
 * interfering with other concurrent test workers.
 */

import { execSync, spawnSync } from "child_process";

type RegistryName = "a" | "b" | "c" | "d";

/** Docker container name for a given letter + worker. */
function containerName(letter: RegistryName, workerIndex: number): string {
  return `registry-${letter}-worker${workerIndex}`;
}

/** Docker network name for a given worker. */
function networkName(workerIndex: number): string {
  return `federation-test-worker${workerIndex}_federation-test-net`;
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
  groupB: RegistryName[]
): void {
  const net = networkName(workerIndex);
  for (const name of groupA) {
    try {
      execSync(
        `docker network disconnect ${net} ${containerName(name, workerIndex)}`,
        { stdio: "pipe" }
      );
    } catch {
      // Container may already be disconnected
    }
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
    try {
      execSync(
        `docker network connect ${net} ${containerName(name, workerIndex)}`,
        { stdio: "pipe" }
      );
    } catch {
      // Already connected
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Container lifecycle
// ─────────────────────────────────────────────────────────────────────────────

/** Kill a registry container abruptly (SIGKILL). */
export function killRegistry(workerIndex: number, name: RegistryName): void {
  execSync(`docker kill ${containerName(name, workerIndex)}`, { stdio: "pipe" });
}

/** Start a previously killed container after a delay. */
export function restartWithDelay(
  workerIndex: number,
  name: RegistryName,
  delayMs: number
): void {
  setTimeout(() => {
    spawnSync("docker", ["start", containerName(name, workerIndex)], {
      stdio: "pipe",
    });
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
  execSync(
    `docker exec ${containerName(name, workerIndex)} tc qdisc add dev eth0 root netem delay ${delayMs}ms`,
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
  try {
    execSync(
      `docker exec ${containerName(name, workerIndex)} tc qdisc del dev eth0 root`,
      { stdio: "pipe" }
    );
  } catch {
    // qdisc may not exist if addNetworkDelay was never called
  }
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
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const out = execSync(
        `docker inspect --format='{{.State.Health.Status}}' ${containerName(name, workerIndex)}`,
        { encoding: "utf8", stdio: "pipe" }
      );
      if (out.trim() === "healthy") return;
    } catch {
      // Container may not exist yet
    }
    await new Promise((r) => setTimeout(r, 1_000));
  }
  throw new Error(
    `Container ${containerName(name, workerIndex)} did not become healthy within ${timeoutMs}ms`
  );
}
