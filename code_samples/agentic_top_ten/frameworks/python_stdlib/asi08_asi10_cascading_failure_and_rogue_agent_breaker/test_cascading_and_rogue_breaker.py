import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

from main import ControlAuthority, Denied, Operation, SwarmBreaker, run_demo


class BreakerTests(unittest.TestCase):
    def setUp(self):
        self.time = 1000.0
        self.authority = ControlAuthority(b"s" * 32, lambda: self.time)
        self.breaker = SwarmBreaker(self.authority.verify, lambda: self.time)
        self.root = self.authority.grant("planner", ("summarize", "save_draft"))
        self.breaker.register(self.root)

    def child(self, name="worker", parent=None, **changes):
        arguments = dict(parent=(parent or self.root).token_id)
        arguments.update(changes)
        child = self.authority.grant(name, ("save_draft",), **arguments)
        self.breaker.register(child)
        return child

    def operation(self, identifier="task-1", **changes):
        operation = Operation("save_draft", "mock://workspace", "summarize", "draft", identifier)
        return replace(operation, **changes)

    def test_positive_and_cross_peer_idempotency(self):
        first, second = self.child("one"), self.child("two")
        operation = self.operation()
        self.assertEqual(self.breaker.dispatch(first, operation), "committed")
        self.assertEqual(self.breaker.dispatch(second, operation), "duplicate suppressed")
        self.assertEqual(len(self.breaker.effect_snapshot()), 1)

    def test_changed_arguments_cannot_reuse_idempotency(self):
        self.breaker.dispatch(self.root, self.operation())
        before = self.breaker.effect_snapshot()
        with self.assertRaises(Denied):
            self.breaker.dispatch(self.root, self.operation(payload="different"))
        self.assertEqual(before, self.breaker.effect_snapshot())

    def test_shared_budget_under_concurrent_sibling_fanout(self):
        peers = [self.child("one"), self.child("two")]

        def commit(index):
            try:
                self.breaker.dispatch(peers[index % 2], self.operation(str(index)))
                return 1
            except Denied:
                return 0

        with ThreadPoolExecutor(max_workers=16) as executor:
            self.assertEqual(sum(executor.map(commit, range(32))), 8)
        self.assertEqual(len(self.breaker.effect_snapshot()), 8)

    def test_concurrent_duplicate_is_consumed_once(self):
        def commit(_):
            return self.breaker.dispatch(self.root, self.operation())
        with ThreadPoolExecutor(max_workers=16) as executor:
            results = list(executor.map(commit, range(32)))
        self.assertEqual(results.count("committed"), 1)
        self.assertEqual(len(self.breaker.effect_snapshot()), 1)

    def test_cycle_breaker_stops_descendant_effects(self):
        worker = self.child()
        cyclic = self.authority.grant("planner", ("save_draft",), parent=worker.token_id)
        with self.assertRaises(Denied):
            self.breaker.register(cyclic)
        with self.assertRaises(Denied):
            self.breaker.dispatch(worker, self.operation())
        self.assertEqual(self.breaker.effect_snapshot(), ())

    def test_fanout_breaker_and_max_hops(self):
        self.child("one")
        self.child("two")
        with self.assertRaises(Denied):
            self.child("overflow")
        with self.assertRaises(Denied):
            self.breaker.dispatch(self.root, self.operation())
        other = SwarmBreaker(self.authority.verify, lambda: self.time, max_hops=1)
        other.register(self.root)
        worker = self.authority.grant("worker", ("save_draft",), parent=self.root.token_id)
        other.register(worker)
        peer = self.authority.grant("peer", ("save_draft",), parent=worker.token_id)
        with self.assertRaises(Denied):
            other.register(peer)

    def test_error_dampening_cooldown_and_per_hop_circuit(self):
        worker = self.child()
        self.breaker.inject_failures(worker, 3)
        for index in range(3):
            with self.assertRaises(Denied):
                self.breaker.dispatch(worker, self.operation(str(index)))
            with self.assertRaises(Denied):
                self.breaker.dispatch(worker, self.operation("too-soon"))
            self.time += 2 ** (index + 1)
        with self.assertRaises(Denied):
            self.breaker.dispatch(worker, self.operation("after-circuit"))
        self.assertEqual(self.breaker.effect_snapshot(), ())
        self.assertEqual(self.breaker.dispatch(self.root, self.operation("unaffected")), "committed")

    def test_retry_budget_cannot_be_reset_by_cooldown(self):
        breaker = SwarmBreaker(self.authority.verify, lambda: self.time,
                               retries=2, error_limit=5)
        breaker.register(self.root)
        breaker.inject_failures(self.root, 2)
        for delay in (2, 4):
            with self.assertRaises(Denied):
                breaker.dispatch(self.root, self.operation())
            self.time += delay
        with self.assertRaises(Denied):
            breaker.dispatch(self.root, self.operation())
        self.assertEqual(breaker.effect_snapshot(), ())

    def test_shared_attempt_budget_counts_failed_work(self):
        breaker = SwarmBreaker(self.authority.verify, lambda: self.time,
                               attempt_budget=2, error_limit=5)
        breaker.register(self.root)
        breaker.inject_failures(self.root, 2)
        for index, delay in enumerate((2, 4)):
            with self.assertRaises(Denied):
                breaker.dispatch(self.root, self.operation(str(index)))
            self.time += delay
        with self.assertRaises(Denied):
            breaker.dispatch(self.root, self.operation("new-id"))
        self.assertEqual(breaker.effect_snapshot(), ())

    def test_behavioral_drift_quarantines_worker_and_peer(self):
        worker = self.child()
        peer = self.child("peer", worker)
        for index in range(3):
            with self.assertRaises(Denied):
                self.breaker.dispatch(worker, self.operation(str(index), purpose="release"))
        self.assertEqual(self.breaker.revoked_agents(), ("peer", "worker"))
        with self.assertRaises(Denied):
            self.breaker.dispatch(peer, self.operation())
        self.assertEqual(self.breaker.effect_snapshot(), ())

    def test_out_of_policy_action_rate_quarantine(self):
        worker = self.child()
        for index in range(3):
            with self.assertRaises(Denied):
                self.breaker.dispatch(worker, self.operation(str(index), tool="release"))
        self.assertEqual(self.breaker.revoked_agents(), ("worker",))

    def test_signed_kill_revokes_transitive_peers_not_unrelated_sibling(self):
        worker = self.child()
        sibling = self.child("sibling")
        peer = self.child("peer", worker)
        command = self.authority.kill("worker")
        self.assertEqual(self.breaker.quarantine(command), ("peer", "worker"))
        for token in (worker, peer):
            with self.assertRaises(Denied):
                self.breaker.dispatch(token, self.operation())
        self.breaker.dispatch(sibling, self.operation("sibling"))
        self.assertEqual(len(self.breaker.effect_snapshot()), 1)
        with self.assertRaises(Denied):
            self.breaker.quarantine(command)

    def test_kill_tamper_stale_epoch_and_expiry_fail_closed(self):
        command = self.authority.kill("planner", ttl=1)
        for altered in (replace(command, agent="worker"), replace(command, epoch=2),
                        replace(command, expires_at=999999)):
            with self.assertRaises(Denied):
                self.breaker.quarantine(altered)
        self.time += 1
        with self.assertRaises(Denied):
            self.breaker.quarantine(command)
        self.assertEqual(self.breaker.revoked_agents(), ())

    def test_token_tamper_unknown_token_and_ancestor_expiry(self):
        worker = self.child()
        for altered in (replace(worker, scope=("release",)), replace(worker, parent=None),
                        replace(worker, agent="planner"),
                        self.authority.grant("unregistered", ("save_draft",))):
            with self.assertRaises(Denied):
                self.breaker.dispatch(altered, self.operation())
        self.time = 1300
        with self.assertRaises(Denied):
            self.breaker.dispatch(worker, self.operation())
        self.assertEqual(self.breaker.effect_snapshot(), ())

    def test_current_policy_epoch_invalidates_authentic_tokens_and_kill_commands(self):
        command = self.authority.kill("planner")
        self.breaker.epoch = 2
        with self.assertRaises(Denied):
            self.breaker.dispatch(self.root, self.operation())
        with self.assertRaises(Denied):
            self.breaker.quarantine(command)
        self.assertEqual(self.breaker.effect_snapshot(), ())

    def test_delegation_scope_expiry_and_epoch_attenuation(self):
        narrow = self.child()
        wider = self.authority.grant("wider", ("summarize",), parent=narrow.token_id)
        with self.assertRaises(Denied):
            self.breaker.register(wider)
        for changes in ({"expires_at": 1301}, {"epoch": 2}):
            with self.assertRaises(Denied):
                self.child("invalid", **changes)

    def test_kill_root_halts_entire_swarm_and_duplicate_paths(self):
        worker = self.child()
        peer = self.child("peer", worker)
        self.breaker.dispatch(peer, self.operation())
        self.assertEqual(self.breaker.quarantine(self.authority.kill("planner")),
                         ("peer", "planner", "worker"))
        for token in (self.root, worker, peer):
            with self.assertRaises(Denied):
                self.breaker.dispatch(token, self.operation())
        self.assertEqual(len(self.breaker.effect_snapshot()), 1)

    def test_demo(self):
        self.assertEqual(run_demo()["protected_effects"], 1)


if __name__ == "__main__":
    unittest.main()
