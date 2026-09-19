#!/usr/bin/env python3
"""
Offline Double-Spend Simulation for human-money-core / Minuto
=============================================================
Compares double-spend detection performance in a realistic offline P2P small-world network:
  1. Mode A: Naive (Collision only when full voucher chains meet at the same node)
  2. Mode B: Immune System (Gossip of lightweight transaction fingerprints / ds_tags)

Features:
- Watts-Strogatz Small-World network with realistic 80/20 transaction clustering.
- Paired Monte Carlo runs: exact same transaction sequence & graph for fair comparison.
- Measures detection time, network transaction volume, fraud spread (victim count), and speedup.
- Pure Python 3 standard library (no external dependencies required).
"""

import argparse
import random
import statistics
from collections import deque, defaultdict
from dataclasses import dataclass
from typing import List, Set, Tuple, Dict, Optional


@dataclass
class Transaction:
    tx_id: int
    voucher_id: int
    sender: int
    receiver: int
    ds_tag: int         # Input commitment (same for colliding double-spend branches)
    branch_id: int      # 0 = normal, 1 = fork A, 2 = fork B
    step: int


class SmallWorldNetwork:
    """Watts-Strogatz Small World Graph with local clustering and shortcut hubs."""
    def __init__(self, num_nodes: int, k_neighbors: int, rewire_prob: float, rng: random.Random):
        self.num_nodes = num_nodes
        self.adj: Dict[int, Set[int]] = {i: set() for i in range(num_nodes)}
        
        # 1. Ring lattice: connect each node to k/2 nearest neighbors on both sides
        half_k = k_neighbors // 2
        for i in range(num_nodes):
            for j in range(1, half_k + 1):
                neighbor = (i + j) % num_nodes
                self.adj[i].add(neighbor)
                self.adj[neighbor].add(i)
                
        # 2. Rewire edges with probability rewire_prob
        for i in range(num_nodes):
            for j in range(1, half_k + 1):
                target = (i + j) % num_nodes
                if rng.random() < rewire_prob:
                    # Choose a random non-neighbor node
                    candidates = [node for node in range(num_nodes) if node != i and node not in self.adj[i]]
                    if candidates:
                        new_target = rng.choice(candidates)
                        # Remove old edge
                        self.adj[i].discard(target)
                        self.adj[target].discard(i)
                        # Add new shortcut edge
                        self.adj[i].add(new_target)
                        self.adj[new_target].add(i)
                        
        # Ensure connectivity
        self._ensure_connected(rng)

    def _ensure_connected(self, rng: random.Random):
        visited = set()
        components = []
        for i in range(self.num_nodes):
            if i not in visited:
                comp = set()
                queue = deque([i])
                visited.add(i)
                while queue:
                    curr = queue.popleft()
                    comp.add(curr)
                    for nbr in self.adj[curr]:
                        if nbr not in visited:
                            visited.add(nbr)
                            queue.append(nbr)
                components.append(comp)
                
        if len(components) > 1:
            for i in range(len(components) - 1):
                node_a = rng.choice(list(components[i]))
                node_b = rng.choice(list(components[i + 1]))
                self.adj[node_a].add(node_b)
                self.adj[node_b].add(node_a)

    def select_partner(self, sender: int, rng: random.Random, local_prob: float = 0.8) -> int:
        """Selects a recipient: 80% local cluster (friends/regular shops), 20% global."""
        neighbors = list(self.adj[sender])
        if rng.random() < local_prob and neighbors:
            return rng.choice(neighbors)
        else:
            candidates = [n for n in range(self.num_nodes) if n != sender]
            return rng.choice(candidates)


@dataclass
class SimulationResult:
    detected_mode_a: bool
    detected_mode_b: bool
    ticks_mode_a: int
    ticks_mode_b: int
    total_tx_mode_a: int
    total_tx_mode_b: int
    victims_mode_a: int
    victims_mode_b: int
    speedup_ticks: float
    speedup_tx: float


class SimulationRun:
    def __init__(
        self,
        num_nodes: int = 500,
        k_neighbors: int = 6,
        rewire_prob: float = 0.1,
        gossip_buffer_size: int = 15,
        gossip_batch_size: int = 4,
        max_ticks: int = 5000,
        tx_per_tick: int = 25,
        num_initial_vouchers: int = 100,
        scenario: str = "random", # "local", "distant", "random"
        seed: Optional[int] = None
    ):
        self.num_nodes = num_nodes
        self.k_neighbors = k_neighbors
        self.rewire_prob = rewire_prob
        self.gossip_buffer_size = gossip_buffer_size
        self.gossip_batch_size = gossip_batch_size
        self.max_ticks = max_ticks
        self.tx_per_tick = tx_per_tick
        self.num_initial_vouchers = num_initial_vouchers
        self.scenario = scenario
        self.rng = random.Random(seed)
        
        self.network = SmallWorldNetwork(num_nodes, k_neighbors, rewire_prob, self.rng)

    def _generate_transaction_stream(self, attacker: int, victim_1: int, victim_2: int) -> List[Tuple[int, int]]:
        """Pre-generates identical transaction partner stream for fair comparison."""
        tx_stream = []
        for _ in range(self.max_ticks * self.tx_per_tick):
            sender = self.rng.randint(0, self.num_nodes - 1)
            receiver = self.network.select_partner(sender, self.rng)
            tx_stream.append((sender, receiver))
        return tx_stream

    def run(self) -> SimulationResult:
        # Choose attacker
        attacker = self.rng.randint(0, self.num_nodes - 1)
        neighbors = list(self.network.adj[attacker])
        
        if self.scenario == "local" and len(neighbors) >= 2:
            victim_1, victim_2 = self.rng.sample(neighbors, 2)
        elif self.scenario == "distant":
            victim_1 = neighbors[0] if neighbors else (attacker + 1) % self.num_nodes
            distant_candidates = [n for n in range(self.num_nodes) if n != attacker and n not in neighbors]
            victim_2 = self.rng.choice(distant_candidates) if distant_candidates else (attacker + self.num_nodes // 2) % self.num_nodes
        else: # random
            candidates = [n for n in range(self.num_nodes) if n != attacker]
            victim_1, victim_2 = self.rng.sample(candidates, 2)

        # Pre-generate deterministic background transaction stream
        tx_stream = self._generate_transaction_stream(attacker, victim_1, victim_2)

        # Initial distribution of background vouchers
        voucher_holders_init: Dict[int, Set[int]] = defaultdict(set)
        for v_id in range(1, self.num_initial_vouchers + 1):
            holder = self.rng.randint(0, self.num_nodes - 1)
            voucher_holders_init[holder].add(v_id)

        # Run Mode A (No Gossip / Chain collision only)
        res_a = self._simulate_mode_a(attacker, victim_1, victim_2, tx_stream, voucher_holders_init)

        # Run Mode B (Immune System / Fingerprint Gossip)
        res_b = self._simulate_mode_b(attacker, victim_1, victim_2, tx_stream, voucher_holders_init)

        speedup_ticks = (res_a["ticks"] / res_b["ticks"]) if res_b["ticks"] > 0 else 1.0
        speedup_tx = (res_a["total_tx"] / res_b["total_tx"]) if res_b["total_tx"] > 0 else 1.0

        return SimulationResult(
            detected_mode_a=res_a["detected"],
            detected_mode_b=res_b["detected"],
            ticks_mode_a=res_a["ticks"],
            ticks_mode_b=res_b["ticks"],
            total_tx_mode_a=res_a["total_tx"],
            total_tx_mode_b=res_b["total_tx"],
            victims_mode_a=res_a["victims"],
            victims_mode_b=res_b["victims"],
            speedup_ticks=speedup_ticks,
            speedup_tx=speedup_tx,
        )

    def _simulate_mode_a(
        self,
        attacker: int,
        victim_1: int,
        victim_2: int,
        tx_stream: List[Tuple[int, int]],
        voucher_holders_init: Dict[int, Set[int]]
    ) -> dict:
        """Mode A: Only full voucher chain collision."""
        wallet_vouchers: Dict[int, Set[int]] = defaultdict(set)
        for n, vs in voucher_holders_init.items():
            wallet_vouchers[n] = set(vs)
            
        wallet_branches: Dict[int, Dict[int, int]] = defaultdict(dict)
        
        # Double spend inject
        wallet_vouchers[victim_1].add(0)
        wallet_branches[victim_1][0] = 1
        
        wallet_vouchers[victim_2].add(0)
        wallet_branches[victim_2][0] = 2

        victims_touched_fork1 = {victim_1}
        victims_touched_fork2 = {victim_2}

        tx_idx = 0
        total_tx = 0
        detected = False
        detection_tick = self.max_ticks

        for tick in range(1, self.max_ticks + 1):
            for _ in range(self.tx_per_tick):
                sender, receiver = tx_stream[tx_idx]
                tx_idx += 1
                total_tx += 1

                if wallet_vouchers[sender]:
                    v_to_send = next(iter(wallet_vouchers[sender]))
                    wallet_vouchers[sender].remove(v_to_send)
                    
                    branch = wallet_branches[sender].get(v_to_send, 0)

                    if v_to_send == 0:
                        if branch == 1:
                            victims_touched_fork1.add(receiver)
                        elif branch == 2:
                            victims_touched_fork2.add(receiver)

                        # Collision condition in Mode A:
                        # Receiver already has or previously received the OTHER branch!
                        if v_to_send in wallet_branches[receiver] and wallet_branches[receiver][v_to_send] != branch:
                            detected = True
                            detection_tick = tick
                            break

                        wallet_vouchers[receiver].add(v_to_send)
                        wallet_branches[receiver][v_to_send] = branch
                    else:
                        wallet_vouchers[receiver].add(v_to_send)

            if detected:
                break

        return {
            "detected": detected,
            "ticks": detection_tick,
            "total_tx": total_tx,
            "victims": len(victims_touched_fork1 | victims_touched_fork2)
        }

    def _simulate_mode_b(
        self,
        attacker: int,
        victim_1: int,
        victim_2: int,
        tx_stream: List[Tuple[int, int]],
        voucher_holders_init: Dict[int, Set[int]]
    ) -> dict:
        """Mode B: Fingerprint Gossip (Immune System)."""
        wallet_vouchers: Dict[int, Set[int]] = defaultdict(set)
        for n, vs in voucher_holders_init.items():
            wallet_vouchers[n] = set(vs)

        wallet_branches: Dict[int, Dict[int, int]] = defaultdict(dict)
        
        # Each node has a bounded known_fingerprints memory: ds_tag -> (branch_id, tx_step)
        known_fps: Dict[int, Dict[int, int]] = defaultdict(dict)
        # FIFO buffer for gossip forwarding
        gossip_queues: Dict[int, deque] = defaultdict(lambda: deque(maxlen=self.gossip_buffer_size))

        DS_TAG = 9999
        
        # Initial double-spend setup
        wallet_vouchers[victim_1].add(0)
        wallet_branches[victim_1][0] = 1
        known_fps[victim_1][DS_TAG] = 1
        gossip_queues[victim_1].append((DS_TAG, 1))

        wallet_vouchers[victim_2].add(0)
        wallet_branches[victim_2][0] = 2
        known_fps[victim_2][DS_TAG] = 2
        gossip_queues[victim_2].append((DS_TAG, 2))

        victims_touched_fork1 = {victim_1}
        victims_touched_fork2 = {victim_2}

        tx_idx = 0
        total_tx = 0
        detected = False
        detection_tick = self.max_ticks

        for tick in range(1, self.max_ticks + 1):
            for _ in range(self.tx_per_tick):
                sender, receiver = tx_stream[tx_idx]
                tx_idx += 1
                total_tx += 1

                # Collect gossip payload from sender (up to gossip_batch_size)
                gossip_payload = list(gossip_queues[sender])[-self.gossip_batch_size:]

                # Receiver processes gossip fingerprints
                for ds_tag, branch_id in gossip_payload:
                    if ds_tag in known_fps[receiver]:
                        if known_fps[receiver][ds_tag] != branch_id:
                            detected = True
                            detection_tick = tick
                            break
                    else:
                        known_fps[receiver][ds_tag] = branch_id
                        gossip_queues[receiver].append((ds_tag, branch_id))

                if detected:
                    break

                # Transfer voucher if sender has one
                if wallet_vouchers[sender]:
                    v_to_send = next(iter(wallet_vouchers[sender]))
                    wallet_vouchers[sender].remove(v_to_send)
                    branch = wallet_branches[sender].get(v_to_send, 0)

                    if v_to_send == 0:
                        if branch == 1:
                            victims_touched_fork1.add(receiver)
                        elif branch == 2:
                            victims_touched_fork2.add(receiver)

                        # Check collision against receiver's known fingerprints
                        if DS_TAG in known_fps[receiver] and known_fps[receiver][DS_TAG] != branch:
                            detected = True
                            detection_tick = tick
                            break

                        wallet_vouchers[receiver].add(v_to_send)
                        wallet_branches[receiver][v_to_send] = branch
                        known_fps[receiver][DS_TAG] = branch
                        gossip_queues[receiver].append((DS_TAG, branch))
                    else:
                        normal_ds_tag = 1000 + v_to_send
                        known_fps[receiver][normal_ds_tag] = 0
                        gossip_queues[receiver].append((normal_ds_tag, 0))
                        wallet_vouchers[receiver].add(v_to_send)

            if detected:
                break

        return {
            "detected": detected,
            "ticks": detection_tick,
            "total_tx": total_tx,
            "victims": len(victims_touched_fork1 | victims_touched_fork2)
        }


def run_benchmark(
    runs: int = 50,
    nodes: int = 500,
    k_neighbors: int = 6,
    rewire_prob: float = 0.1,
    gossip_buffer_size: int = 15,
    gossip_batch_size: int = 4,
    tx_per_tick: int = 25,
    scenario: str = "random",
    base_seed: int = 42
):
    print("=" * 80)
    print(f"  HUMAN-MONEY-CORE / MINUTO: OFFLINE DOUBLE-SPEND SIMULATION")
    print(f"  Parameters: Nodes={nodes}, k={k_neighbors}, p_rewire={rewire_prob}, Runs={runs}, Scenario={scenario}")
    print(f"  Gossip Config: BufferSize={gossip_buffer_size}, BatchPerTX={gossip_batch_size}, TX/Tick={tx_per_tick}")
    print("=" * 80)

    results: List[SimulationResult] = []

    for r in range(runs):
        sim = SimulationRun(
            num_nodes=nodes,
            k_neighbors=k_neighbors,
            rewire_prob=rewire_prob,
            gossip_buffer_size=gossip_buffer_size,
            gossip_batch_size=gossip_batch_size,
            tx_per_tick=tx_per_tick,
            scenario=scenario,
            seed=base_seed + r
        )
        res = sim.run()
        results.append(res)

    detected_a_count = sum(1 for r in results if r.detected_mode_a)
    detected_b_count = sum(1 for r in results if r.detected_mode_b)

    ticks_a = [r.ticks_mode_a for r in results if r.detected_mode_a]
    ticks_b = [r.ticks_mode_b for r in results if r.detected_mode_b]

    tx_a = [r.total_tx_mode_a for r in results if r.detected_mode_a]
    tx_b = [r.total_tx_mode_b for r in results if r.detected_mode_b]

    victims_a = [r.victims_mode_a for r in results]
    victims_b = [r.victims_mode_b for r in results]

    print("\n--- ERGEBNIS-ÜBERSICHT ---")
    print(f"Erkennungsrate Mode A (Ohne Fingerprints): {detected_a_count}/{runs} ({detected_a_count/runs*100:.1f} %)")
    print(f"Erkennungsrate Mode B (Mit Fingerprints):   {detected_b_count}/{runs} ({detected_b_count/runs*100:.1f} %)")
    print()

    print(f"{'Metrik':<35} | {'Ohne Fingerprints (Modus A)':<25} | {'Mit Fingerprints (Modus B)':<25} | {'Faktor / Vorteil':<15}")
    print("-" * 110)

    mean_ticks_a = statistics.mean(ticks_a) if ticks_a else float('inf')
    mean_ticks_b = statistics.mean(ticks_b) if ticks_b else 0
    med_ticks_a = statistics.median(ticks_a) if ticks_a else float('inf')
    med_ticks_b = statistics.median(ticks_b) if ticks_b else 0

    speedup_ticks_mean = (mean_ticks_a / mean_ticks_b) if mean_ticks_b > 0 else 1.0
    speedup_ticks_med = (med_ticks_a / med_ticks_b) if med_ticks_b > 0 else 1.0

    print(f"{'Zeit bis Erkennung (Ticks, Mean)':<35} | {mean_ticks_a:<25.1f} | {mean_ticks_b:<25.1f} | {speedup_ticks_mean:<15.1f}x schneller")
    print(f"{'Zeit bis Erkennung (Ticks, Median)':<35} | {med_ticks_a:<25.1f} | {med_ticks_b:<25.1f} | {speedup_ticks_med:<15.1f}x schneller")

    mean_tx_a = statistics.mean(tx_a) if tx_a else float('inf')
    mean_tx_b = statistics.mean(tx_b) if tx_b else 0
    med_tx_a = statistics.median(tx_a) if tx_a else float('inf')
    med_tx_b = statistics.median(tx_b) if tx_b else 0

    speedup_tx_mean = (mean_tx_a / mean_tx_b) if mean_tx_b > 0 else 1.0
    speedup_tx_med = (med_tx_a / med_tx_b) if med_tx_b > 0 else 1.0

    print(f"{'Netzwerk-Transaktionen (Mean)':<35} | {mean_tx_a:<25.1f} | {mean_tx_b:<25.1f} | {speedup_tx_mean:<15.1f}x weniger TX")
    print(f"{'Netzwerk-Transaktionen (Median)':<35} | {med_tx_a:<25.1f} | {med_tx_b:<25.1f} | {speedup_tx_med:<15.1f}x weniger TX")

    mean_vic_a = statistics.mean(victims_a)
    mean_vic_b = statistics.mean(victims_b)
    max_vic_a = max(victims_a)
    max_vic_b = max(victims_b)

    print(f"{'Geschädigte Opfer (Mean)':<35} | {mean_vic_a:<25.1f} | {mean_vic_b:<25.1f} | -{mean_vic_a - mean_vic_b:.1f} Opfer")
    print(f"{'Geschädigte Opfer (Maximal)':<35} | {max_vic_a:<25} | {max_vic_b:<25} | -{max_vic_a - max_vic_b} Opfer")

    print("=" * 80)
    return results


def main():
    parser = argparse.ArgumentParser(description="Simulate offline double-spend detection.")
    parser.add_argument("--runs", type=int, default=50, help="Number of Monte Carlo simulation runs")
    parser.add_argument("--nodes", type=int, default=500, help="Number of nodes in the network")
    parser.add_argument("--scenario", type=str, default="random", choices=["random", "local", "distant"], help="Attack scenario")
    parser.add_argument("--buffer-size", type=int, default=15, help="Gossip memory buffer size")
    parser.add_argument("--batch-size", type=int, default=4, help="Fingerprints forwarded per transaction")
    args = parser.parse_args()

    run_benchmark(
        runs=args.runs,
        nodes=args.nodes,
        scenario=args.scenario,
        gossip_buffer_size=args.buffer_size,
        gossip_batch_size=args.batch_size
    )


if __name__ == "__main__":
    main()
