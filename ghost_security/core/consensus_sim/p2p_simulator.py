"""Ghost Security Platform — P2P Network & Consensus Attack Simulator (Phase 15)

Mathematical simulation of:
- Eclipse attacks (Kademlia routing)
- Sybil attacks (PoW / PoS / DPoS)
- Selfish mining (Eyal & Sirer model)
- Nothing-at-stake (PoS fork exploitation)
- Consensus safety/liveness analysis (PBFT, Tendermint, Avalanche, TON BFT)
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class SimulationResult:
    attack_type: str
    success_probability: float      # 0.0–1.0
    expected_damage: str
    required_resources: Dict[str, object]
    detection_difficulty: str       # "easy", "medium", "hard"
    mitigation: str
    rounds_to_success: Optional[int] = None
    details: Dict[str, object] = field(default_factory=dict)


@dataclass
class RoutingAnalysis:
    protocol: str
    eclipse_threshold: float        # attacker fraction needed to eclipse a node
    sybil_resistance: str           # "weak", "medium", "strong"
    routing_table_poisoning: bool
    findings: List[str]


@dataclass
class ConsensusAnalysis:
    consensus_type: str
    safety_threshold: float         # max Byzantine fraction for safety
    liveness_threshold: float       # max Byzantine fraction for liveness
    current_byzantine_fraction: float
    is_safe: bool
    is_live: bool
    findings: List[str]


# ---------------------------------------------------------------------------
# Simulator
# ---------------------------------------------------------------------------

class P2PSimulator:
    """Simulate P2P network attacks and consensus protocol resilience."""

    def __init__(self, network_size: int = 100):
        self.network_size = network_size

    # ------------------------------------------------------------------
    # Eclipse attack
    # ------------------------------------------------------------------

    def simulate_eclipse_attack(
        self,
        target_nodes: int = 1,
        attacker_nodes: int = 10,
        routing_table_size: int = 8,
    ) -> SimulationResult:
        """Simulate Kademlia eclipse attack probability.

        Model: attacker needs to fill all routing_table_size slots of a target.
        Probability that a given slot is filled by attacker:
            p_slot = attacker_nodes / (network_size - 1)
        Probability that all slots are attacker-controlled:
            p_eclipse = p_slot ^ routing_table_size
        """
        n = self.network_size
        a = min(attacker_nodes, n - 1)

        p_slot = a / max(n - 1, 1)
        p_eclipse_single = p_slot ** routing_table_size

        # Expected rounds for attacker to gradually poison routing table
        # After k connection refreshes the probability converges
        p_after_10_refreshes = 1 - (1 - p_eclipse_single) ** 10
        rounds = math.ceil(math.log(0.5) / math.log(1 - p_eclipse_single)) if p_eclipse_single < 1 else 1

        # Resource estimate: IPs needed = attacker_nodes
        fraction = a / n
        diff = "easy" if fraction > 0.3 else ("medium" if fraction > 0.1 else "hard")

        return SimulationResult(
            attack_type="eclipse",
            success_probability=round(p_after_10_refreshes, 4),
            expected_damage=(
                "Target node is isolated from honest network. "
                "All its views of blockchain state are attacker-controlled. "
                "Enables double-spend against the target."
            ),
            required_resources={
                "attacker_nodes": a,
                "fraction_of_network": round(fraction, 3),
                "unique_ips_needed": a,
            },
            detection_difficulty=diff,
            mitigation=(
                "Enforce routing diversity (multiple subnets per bucket). "
                "Use feeler connections to discover new peers. "
                "Anchor connections to well-known trusted peers. "
                "Limit peer replacement rate."
            ),
            rounds_to_success=rounds,
            details={
                "p_slot": round(p_slot, 4),
                "p_eclipse_single_attempt": round(p_eclipse_single, 6),
                "p_eclipse_after_10_refreshes": round(p_after_10_refreshes, 4),
                "routing_table_size": routing_table_size,
            },
        )

    # ------------------------------------------------------------------
    # Sybil attack
    # ------------------------------------------------------------------

    def simulate_sybil_attack(
        self,
        sybil_fraction: float = 0.3,
        stake_distribution: str = "uniform",
        consensus_type: str = "pos",
    ) -> SimulationResult:
        """Simulate Sybil attack impact across consensus types."""
        f = min(max(sybil_fraction, 0.0), 1.0)

        if consensus_type == "pow":
            # PoW: Sybil nodes only matter if they have hash power
            # With 30% hash power, selfish mining becomes profitable
            profitable = f >= 0.25
            success_prob = min(f / 0.5, 1.0)
            damage = (
                f"With {f:.0%} hash power: selfish mining profitable (>25% threshold). "
                "Can double-spend with 6-confirmation finality." if profitable else
                f"With {f:.0%} hash power: below selfish-mining threshold. "
                "Cannot reliably double-spend."
            )
            mitigation = (
                "Mining pool size limits, merge mining restrictions, "
                "ASIC-friendly algorithms to decentralize mining."
            )
        elif consensus_type == "pos":
            # PoS: Sybil nodes with sybil_fraction of stake
            safety_threshold = 1 / 3
            liveness_threshold = 1 / 3
            can_break_safety = f > safety_threshold
            can_break_liveness = f > liveness_threshold
            success_prob = min(f / safety_threshold, 1.0)
            damage = (
                f"With {f:.0%} stake: "
                + ("CAN break safety (double finalize). " if can_break_safety else "Cannot break safety. ")
                + ("CAN halt liveness (no new blocks)." if can_break_liveness else "Cannot halt liveness.")
            )
            mitigation = (
                "Slashing for equivocation, long unbonding periods, "
                "distributed key generation for committee selection."
            )
        elif consensus_type == "dpos":
            # DPoS: Sybil nodes need to control delegate slots
            delegate_count = 21  # typical (EOS-like)
            slots_controlled = math.ceil(f * delegate_count)
            can_control = slots_controlled > delegate_count * 2 / 3
            success_prob = min(f / (2 / 3), 1.0)
            damage = (
                f"Controls {slots_controlled}/{delegate_count} delegate slots. "
                + ("Majority control — can reorder/censor transactions." if can_control else
                   "Minority — can only slow finality.")
            )
            mitigation = (
                "Approval voting with token-weighted votes, "
                "delegate rotation, reputation systems."
            )
        else:
            success_prob = f
            damage = f"Generic: {f:.0%} of network resources controlled."
            mitigation = "Proof-of-work or stake-based admission control."

        return SimulationResult(
            attack_type=f"sybil_{consensus_type}",
            success_probability=round(success_prob, 4),
            expected_damage=damage,
            required_resources={
                "sybil_fraction": f,
                "stake_or_hashpower_needed": f"{f:.0%} of total",
            },
            detection_difficulty="medium",
            mitigation=mitigation,
            details={
                "consensus_type": consensus_type,
                "stake_distribution": stake_distribution,
                "sybil_fraction": f,
            },
        )

    # ------------------------------------------------------------------
    # Selfish mining
    # ------------------------------------------------------------------

    def simulate_selfish_mining(
        self,
        attacker_hash_fraction: float = 0.3,
        gamma: float = 0.5,
    ) -> SimulationResult:
        """Eyal & Sirer (2014) selfish mining revenue model.

        α = attacker hash fraction
        γ = probability attacker wins the race when honest and selfish
            blocks are published simultaneously (network advantage)

        Revenue = α(1-α)²(4α + γ(1-2α)) / (1-α(1+(2-α)α))
        Profitable when revenue > α (i.e., more than fair share).
        """
        alpha = min(max(attacker_hash_fraction, 0.001), 0.999)
        g = gamma

        numerator   = alpha * (1 - alpha)**2 * (4*alpha + g*(1 - 2*alpha))
        denominator = 1 - alpha * (1 + (2 - alpha)*alpha)
        if abs(denominator) < 1e-9:
            revenue_fraction = alpha
        else:
            revenue_fraction = numerator / denominator

        revenue_fraction = max(0.0, min(revenue_fraction, 1.0))
        profitable = revenue_fraction > alpha
        # Threshold: minimum α for profitability ≈ (1-γ)/(3-2γ)
        threshold = (1 - g) / (3 - 2*g)

        rounds_to_orphan_honest = math.ceil(1 / (alpha + 1e-9))

        return SimulationResult(
            attack_type="selfish_mining",
            success_probability=round(revenue_fraction, 4),
            expected_damage=(
                f"Attacker revenue: {revenue_fraction:.1%} of block rewards (fair share: {alpha:.1%}). "
                + ("Selfish mining IS profitable — attacker gains disproportionate rewards." if profitable else
                   f"Not yet profitable. Threshold: α > {threshold:.1%}.")
            ),
            required_resources={
                "hash_fraction": alpha,
                "network_gamma": g,
                "profitable": profitable,
            },
            detection_difficulty="medium",
            mitigation=(
                "Uniform tie-breaking (γ→0), selfish mining detection via orphan rate monitoring, "
                "GHOST protocol or similar to reduce orphan advantage."
            ),
            rounds_to_success=rounds_to_orphan_honest,
            details={
                "alpha": alpha,
                "gamma": g,
                "revenue_fraction": round(revenue_fraction, 4),
                "profitable": profitable,
                "minimum_profitable_alpha": round(threshold, 3),
            },
        )

    # ------------------------------------------------------------------
    # Nothing-at-stake
    # ------------------------------------------------------------------

    def simulate_nothing_at_stake(
        self,
        validator_count: int = 100,
        fork_probability: float = 0.05,
    ) -> SimulationResult:
        """Model nothing-at-stake attack in naive PoS without slashing.

        Without slashing, rational validators sign ALL forks.
        Expected attacker advantage: can rewrite recent history.
        With slashing, rational validators converge to one fork.
        """
        # Without slashing: all validators sign all forks
        # Expected fork length a validator can sustain = 1/(1-fork_prob)
        expected_fork_depth = 1 / max(1 - fork_probability, 0.01)
        # Probability attacker can double-spend on a fork of depth k
        # = (probability all validators signed attacker's fork)
        # In naive PoS without slashing: 1.0 (all validators vote on all forks)
        success_prob_no_slash = min(fork_probability * expected_fork_depth, 1.0)
        success_prob_with_slash = fork_probability * 0.05  # slashing makes it costly

        return SimulationResult(
            attack_type="nothing_at_stake",
            success_probability=round(success_prob_no_slash, 4),
            expected_damage=(
                f"Without slashing: {success_prob_no_slash:.1%} probability of successful reorg. "
                f"Validators have incentive to sign all {expected_fork_depth:.1f} expected fork branches. "
                f"With slashing: probability drops to {success_prob_with_slash:.2%}."
            ),
            required_resources={
                "validator_count": validator_count,
                "stake_required": "0 (validators sign for free)",
                "slashing_reduces_to": f"{success_prob_with_slash:.2%}",
            },
            detection_difficulty="easy",
            mitigation=(
                "Implement slashing conditions for equivocation (signing two conflicting blocks). "
                "Use Casper FFG or similar finality gadget. "
                "Long unbonding periods to deter attacks."
            ),
            details={
                "fork_probability": fork_probability,
                "expected_fork_depth": round(expected_fork_depth, 2),
                "success_without_slash": round(success_prob_no_slash, 4),
                "success_with_slash": round(success_prob_with_slash, 4),
            },
        )

    # ------------------------------------------------------------------
    # Routing security analysis
    # ------------------------------------------------------------------

    def analyze_routing_security(self, protocol: str = "kademlia") -> RoutingAnalysis:
        findings: List[str] = []
        protocol = protocol.lower()

        if protocol == "kademlia":
            # Eclipse threshold: attacker needs ~30% of network for reliable eclipse
            eclipse_threshold = 0.30
            sybil_resistance = "weak"  # no stake requirement
            routing_table_poisoning = True
            findings += [
                "Kademlia XOR metric allows targeted node ID generation near victim.",
                "Routing table slots can be poisoned by mass-registering attacker IDs.",
                "No identity binding — generating many node IDs is free (Sybil attack).",
                "Eclipse attack feasible with ~30% of DHT nodes targeting a single victim.",
                "Mitigation: use verified peer IDs (signed by CA), enforce subnet diversity in buckets.",
            ]
        elif protocol in ("gossip", "epidemic"):
            eclipse_threshold = 0.51
            sybil_resistance = "medium"
            routing_table_poisoning = False
            findings += [
                "Gossip protocol has no targeted routing — eclipse requires majority of peers.",
                "Peer list poisoning via crafted gossip messages possible without rate limiting.",
                "Fanout parameter determines amplification factor for sybil nodes.",
            ]
        elif protocol == "structured_overlay":
            eclipse_threshold = 0.50
            sybil_resistance = "medium"
            routing_table_poisoning = True
            findings += [
                "Structured overlays are susceptible to routing detour attacks.",
                "An attacker controlling nodes on the path between two parties can intercept queries.",
            ]
        else:
            eclipse_threshold = 0.50
            sybil_resistance = "medium"
            routing_table_poisoning = False
            findings += [f"Protocol '{protocol}' — using conservative defaults."]

        return RoutingAnalysis(
            protocol=protocol,
            eclipse_threshold=eclipse_threshold,
            sybil_resistance=sybil_resistance,
            routing_table_poisoning=routing_table_poisoning,
            findings=findings,
        )

    # ------------------------------------------------------------------
    # Consensus safety/liveness
    # ------------------------------------------------------------------

    def check_consensus_liveness(
        self,
        byzantine_fraction: float = 0.1,
        consensus_type: str = "pbft",
    ) -> ConsensusAnalysis:
        """Analyse safety and liveness for common consensus protocols."""
        f = min(max(byzantine_fraction, 0.0), 1.0)
        ctype = consensus_type.lower()
        findings: List[str] = []

        # Thresholds per protocol
        thresholds: Dict[str, Tuple[float, float]] = {
            "pbft":       (1/3, 1/3),
            "tendermint": (1/3, 1/3),
            "hotstuff":   (1/3, 1/3),
            "avalanche":  (1/2, 0.20),
            "ton_bft":    (1/3, 1/3),  # 2/3 committee supermajority
            "casper_ffg": (1/3, 1/3),
            "nakamoto":   (1/2, 1/2),  # longest-chain PoW
        }

        safety_t, liveness_t = thresholds.get(ctype, (1/3, 1/3))
        is_safe  = f < safety_t
        is_live  = f < liveness_t

        findings.append(
            f"Protocol: {ctype.upper()} — "
            f"safety threshold {safety_t:.0%}, liveness threshold {liveness_t:.0%}."
        )
        findings.append(
            f"Current Byzantine fraction: {f:.0%} — "
            f"Safety: {'✓ OK' if is_safe else '✗ BROKEN'}, "
            f"Liveness: {'✓ OK' if is_live else '✗ BROKEN'}."
        )

        if not is_safe:
            findings.append(
                f"CRITICAL: Byzantine fraction {f:.0%} exceeds safety threshold {safety_t:.0%}. "
                "The protocol can finalize conflicting blocks (double-finalization)."
            )
        if not is_live:
            findings.append(
                f"WARNING: Byzantine fraction {f:.0%} exceeds liveness threshold {liveness_t:.0%}. "
                "The protocol may halt (no new blocks finalized)."
            )

        if ctype == "ton_bft":
            findings.append(
                "TON uses rotating validator committees (typically 100–400 validators). "
                "Attacker needs >1/3 of stake to subvert a committee. "
                "Stake concentration in a few validators reduces practical threshold."
            )
        elif ctype == "avalanche":
            findings.append(
                "Avalanche safety depends on quorum size (k) and threshold (α). "
                "With default k=20, α=15: effective safety threshold ≈ 1/2 of sampled nodes."
            )

        return ConsensusAnalysis(
            consensus_type=ctype,
            safety_threshold=safety_t,
            liveness_threshold=liveness_t,
            current_byzantine_fraction=f,
            is_safe=is_safe,
            is_live=is_live,
            findings=findings,
        )

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_report(self, results: List[SimulationResult]) -> str:
        lines = [
            "=" * 70,
            "  P2P / CONSENSUS ATTACK SIMULATION REPORT — SentinelOps Phase 15",
            "=" * 70,
            "",
        ]
        for r in results:
            lines.append(f"Attack type:        {r.attack_type.upper()}")
            lines.append(f"Success probability:{r.success_probability:.2%}")
            lines.append(f"Detection:          {r.detection_difficulty}")
            if r.rounds_to_success:
                lines.append(f"Est. rounds:        {r.rounds_to_success}")
            lines.append(f"Resources needed:   {r.required_resources}")
            lines.append(f"Expected damage:\n  {r.expected_damage}")
            lines.append(f"Mitigation:\n  {r.mitigation}")
            if r.details:
                lines.append("Details:")
                for k, v in r.details.items():
                    lines.append(f"  {k}: {v}")
            lines.append("-" * 70)
        return "\n".join(lines)
