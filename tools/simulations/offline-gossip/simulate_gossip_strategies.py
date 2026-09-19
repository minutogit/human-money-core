#!/usr/bin/env python3
"""
Gossip Strategy Benchmark & Information Distribution Simulation
===============================================================
Compares different local selection rules for P2P fingerprint gossip:
  1. Pure FIFO (Always send top M newest)
  2. Pure Random (Uniform sample of M from local memory)
  3. Hybrid (50% newest + 50% random from queue)
  4. Novelty / Low-Forward-Count (Prioritize items sent < 2 times locally)
  5. Baseline Complex (Full depth sorting + known_by_peers tracking)

Measures:
- Network coverage speed (% of nodes reached over time)
- Double-spend detection latency & victim containment
- Overhead & duplicate ratio
"""

import random
import statistics
from collections import deque, defaultdict
from dataclasses import dataclass
from typing import List, Set, Dict, Tuple, Optional


class SmallWorldNetwork:
    def __init__(self, num_nodes: int, k_neighbors: int = 6, rewire_prob: float = 0.1, rng: random.Random = None):
        self.num_nodes = num_nodes
        self.adj: Dict[int, Set[int]] = {i: set() for i in range(num_nodes)}
        half_k = k_neighbors // 2
        for i in range(num_nodes):
            for j in range(1, half_k + 1):
                neighbor = (i + j) % num_nodes
                self.adj[i].add(neighbor)
                self.adj[neighbor].add(i)
                
        for i in range(num_nodes):
            for j in range(1, half_k + 1):
                target = (i + j) % num_nodes
                if rng.random() < rewire_prob:
                    candidates = [node for node in range(num_nodes) if node != i and node not in self.adj[i]]
                    if candidates:
                        new_target = rng.choice(candidates)
                        self.adj[i].discard(target)
                        self.adj[target].discard(i)
                        self.adj[i].add(new_target)
                        self.adj[new_target].add(i)
                        
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
        neighbors = list(self.adj[sender])
        if rng.random() < local_prob and neighbors:
            return rng.choice(neighbors)
        else:
            candidates = [n for n in range(self.num_nodes) if n != sender]
            return rng.choice(candidates)


@dataclass
class StrategyMetrics:
    name: str
    ticks_to_detect: int
    tx_to_detect: int
    victims: int
    coverage_at_tick_50: float   # % of network that knows the fingerprint at tick 50
    coverage_at_tick_100: float  # % of network at tick 100


class StrategySimulation:
    def __init__(
        self,
        strategy_name: str,
        num_nodes: int = 500,
        buffer_size: int = 50,
        batch_size: int = 10,
        max_ticks: int = 3000,
        tx_per_tick: int = 25,
        rng: random.Random = None
    ):
        self.strategy_name = strategy_name
        self.num_nodes = num_nodes
        self.buffer_size = buffer_size
        self.batch_size = batch_size
        self.max_ticks = max_ticks
        self.tx_per_tick = tx_per_tick
        self.rng = rng or random.Random(42)
        self.network = SmallWorldNetwork(num_nodes, 6, 0.1, self.rng)

    def run(self, attacker: int, victim_1: int, victim_2: int, tx_stream: List[Tuple[int, int]]) -> StrategyMetrics:
        # State tracking per node
        # known_fps: node -> {ds_tag: branch_id}
        known_fps: Dict[int, Dict[int, int]] = defaultdict(dict)
        
        # Local queue / storage structure depending on strategy
        # For FIFO / Hybrid / Random: deque or list of (ds_tag, branch_id)
        queues: Dict[int, deque] = defaultdict(lambda: deque(maxlen=self.buffer_size))
        
        # For Novelty strategy: count of times forwarded locally
        forward_counts: Dict[int, Dict[int, int]] = defaultdict(lambda: defaultdict(int)) # node -> ds_tag -> count
        
        # For Complex strategy: known_by_peers tracking
        known_by_peers: Dict[int, Dict[int, Set[int]]] = defaultdict(lambda: defaultdict(set)) # node -> ds_tag -> set of peers

        # Voucher holders
        wallet_vouchers: Dict[int, Set[int]] = defaultdict(set)
        wallet_branches: Dict[int, Dict[int, int]] = defaultdict(dict)

        # Distribute 100 background vouchers
        for v_id in range(1, 101):
            holder = self.rng.randint(0, self.num_nodes - 1)
            wallet_vouchers[holder].add(v_id)

        # Inject Double Spend at t=0
        DS_TAG = 9999
        wallet_vouchers[victim_1].add(0)
        wallet_branches[victim_1][0] = 1
        known_fps[victim_1][DS_TAG] = 1
        queues[victim_1].append((DS_TAG, 1))

        wallet_vouchers[victim_2].add(0)
        wallet_branches[victim_2][0] = 2
        known_fps[victim_2][DS_TAG] = 2
        queues[victim_2].append((DS_TAG, 2))

        victims_fork1 = {victim_1}
        victims_fork2 = {victim_2}

        tx_idx = 0
        total_tx = 0
        detected = False
        detection_tick = self.max_ticks

        cov_50 = 0.0
        cov_100 = 0.0

        for tick in range(1, self.max_ticks + 1):
            # Measure coverage of the double spend tag in the network
            if tick == 50:
                holders = sum(1 for n in range(self.num_nodes) if DS_TAG in known_fps[n])
                cov_50 = (holders / self.num_nodes) * 100
            if tick == 100:
                holders = sum(1 for n in range(self.num_nodes) if DS_TAG in known_fps[n])
                cov_100 = (holders / self.num_nodes) * 100

            for _ in range(self.tx_per_tick):
                sender, receiver = tx_stream[tx_idx]
                tx_idx += 1
                total_tx += 1

                # 1. SELECT GOSSIP BATCH ACCORDING TO STRATEGY
                payload = self._select_payload(
                    sender, receiver, queues, forward_counts, known_by_peers, known_fps
                )

                # 2. RECEIVER PROCESSES GOSSIP
                for ds_tag, branch_id in payload:
                    forward_counts[sender][ds_tag] += 1
                    known_by_peers[sender][ds_tag].add(receiver)

                    if ds_tag in known_fps[receiver]:
                        if known_fps[receiver][ds_tag] != branch_id:
                            detected = True
                            detection_tick = tick
                            break
                    else:
                        known_fps[receiver][ds_tag] = branch_id
                        # Ingest into receiver's queue
                        if (ds_tag, branch_id) not in queues[receiver]:
                            queues[receiver].append((ds_tag, branch_id))

                if detected:
                    break

                # 3. TRANSFER VOUCHER
                if wallet_vouchers[sender]:
                    v_to_send = next(iter(wallet_vouchers[sender]))
                    wallet_vouchers[sender].remove(v_to_send)
                    branch = wallet_branches[sender].get(v_to_send, 0)

                    if v_to_send == 0:
                        if branch == 1:
                            victims_fork1.add(receiver)
                        elif branch == 2:
                            victims_fork2.add(receiver)

                        if DS_TAG in known_fps[receiver] and known_fps[receiver][DS_TAG] != branch:
                            detected = True
                            detection_tick = tick
                            break

                        wallet_vouchers[receiver].add(v_to_send)
                        wallet_branches[receiver][v_to_send] = branch
                        known_fps[receiver][DS_TAG] = branch
                        if (DS_TAG, branch) not in queues[receiver]:
                            queues[receiver].append((DS_TAG, branch))
                    else:
                        normal_ds = 1000 + v_to_send
                        known_fps[receiver][normal_ds] = 0
                        if (normal_ds, 0) not in queues[receiver]:
                            queues[receiver].append((normal_ds, 0))
                        wallet_vouchers[receiver].add(v_to_send)

            if detected:
                break

        if cov_50 == 0.0:
            holders = sum(1 for n in range(self.num_nodes) if DS_TAG in known_fps[n])
            cov_50 = (holders / self.num_nodes) * 100
        if cov_100 == 0.0:
            holders = sum(1 for n in range(self.num_nodes) if DS_TAG in known_fps[n])
            cov_100 = (holders / self.num_nodes) * 100

        return StrategyMetrics(
            name=self.strategy_name,
            ticks_to_detect=detection_tick,
            tx_to_detect=total_tx,
            victims=len(victims_fork1 | victims_fork2),
            coverage_at_tick_50=cov_50,
            coverage_at_tick_100=cov_100
        )

    def _select_payload(
        self,
        sender: int,
        receiver: int,
        queues: Dict[int, deque],
        forward_counts: Dict[int, Dict[int, int]],
        known_by_peers: Dict[int, Dict[int, Set[int]]],
        known_fps: Dict[int, Dict[int, int]]
    ) -> List[Tuple[int, int]]:
        items = list(queues[sender])
        if not items:
            return []

        if self.strategy_name == "Pure FIFO (Top Newest)":
            # Always the newest M items
            return items[-self.batch_size:]

        elif self.strategy_name == "Pure Random":
            # Random sample of M items
            return self.rng.sample(items, min(len(items), self.batch_size))

        elif self.strategy_name == "Hybrid (50% Newest + 50% Random)":
            # Half newest, half random from older
            half = self.batch_size // 2
            newest = items[-half:]
            older = items[:-half] if len(items) > half else []
            sampled_older = self.rng.sample(older, min(len(older), self.batch_size - len(newest)))
            return newest + sampled_older

        elif self.strategy_name == "Novelty-First (Lowest Forward Count)":
            # Sort by forward count ascending (items sent fewer times locally get priority)
            sorted_items = sorted(items, key=lambda x: forward_counts[sender][x[0]])
            return sorted_items[:self.batch_size]

        elif self.strategy_name == "Complex (known_by_peers tracking)":
            # Exclude items peer already knows
            filtered = [x for x in items if receiver not in known_by_peers[sender][x[0]]]
            if not filtered:
                filtered = items
            return filtered[-self.batch_size:]

        return items[-self.batch_size:]


def run_strategy_comparison(runs: int = 50, nodes: int = 500, buffer_size: int = 50, batch_size: int = 10):
    strategies = [
        "Pure FIFO (Top Newest)",
        "Pure Random",
        "Hybrid (50% Newest + 50% Random)",
        "Novelty-First (Lowest Forward Count)",
        "Complex (known_by_peers tracking)"
    ]

    print("=" * 95)
    print(f"  BENCHMARK: GOSSIP SELECTION STRATEGIES (KISS vs. COMPLEX)")
    print(f"  Nodes: {nodes}, Runs: {runs}, BufferSize: {buffer_size}, BatchPerTX: {batch_size}")
    print("=" * 95)

    strategy_results = defaultdict(list)

    for r in range(runs):
        seed = 1000 + r
        rng_master = random.Random(seed)
        
        # Pre-create topology and transaction stream so ALL strategies face the EXACT same world
        net = SmallWorldNetwork(nodes, 6, 0.1, rng_master)
        attacker = rng_master.randint(0, nodes - 1)
        candidates = [n for n in range(nodes) if n != attacker]
        victim_1, victim_2 = rng_master.sample(candidates, 2)

        # Pre-generate 3000 ticks of transactions
        tx_stream = []
        for _ in range(3000 * 25):
            s = rng_master.randint(0, nodes - 1)
            rec = net.select_partner(s, rng_master)
            tx_stream.append((s, rec))

        for strat in strategies:
            # Independent RNG with same seed for tie-breakers
            strat_rng = random.Random(seed + 99)
            sim = StrategySimulation(
                strategy_name=strat,
                num_nodes=nodes,
                buffer_size=buffer_size,
                batch_size=batch_size,
                rng=strat_rng
            )
            sim.network = net # Use exact same network
            res = sim.run(attacker, victim_1, victim_2, tx_stream)
            strategy_results[strat].append(res)

    print(f"\n{'Strategie':<38} | {'Dauer (Ticks)':<14} | {'TX bis Alarm':<14} | {'Opfer (Mean)':<12} | {'Netzabdeckung (t=50)'}")
    print("-" * 105)

    for strat in strategies:
        res_list = strategy_results[strat]
        mean_ticks = statistics.mean([r.ticks_to_detect for r in res_list])
        mean_tx = statistics.mean([r.tx_to_detect for r in res_list])
        mean_vic = statistics.mean([r.victims for r in res_list])
        mean_cov_50 = statistics.mean([r.coverage_at_tick_50 for r in res_list])

        print(f"{strat:<38} | {mean_ticks:<14.1f} | {mean_tx:<14.1f} | {mean_vic:<12.1f} | {mean_cov_50:<5.1f} %")

    print("=" * 105)


if __name__ == "__main__":
    run_strategy_comparison(runs=40, nodes=500, buffer_size=50, batch_size=10)
