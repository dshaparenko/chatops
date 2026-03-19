package bot

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// --- Test helpers ---

// testCountPending returns the number of entries in formUpdates.pending.
// Used to assert that no timers or snapshots are left behind (no memory leak).
func testCountPending(s *Slack) int {
	s.formUpdates.mu.Lock()
	defer s.formUpdates.mu.Unlock()
	return len(s.formUpdates.pending)
}

// testCountRevisions returns the number of keys in formUpdates.revisions.
func testCountRevisions(s *Slack) int {
	s.formUpdates.mu.Lock()
	defer s.formUpdates.mu.Unlock()
	return len(s.formUpdates.revisions)
}

func testSlackWithDebounce(debounceMs int) *Slack {
	return &Slack{
		options: SlackOptions{FormUpdateDebounceMs: debounceMs},
		formUpdates: formUpdatesState{
			pending:   make(map[string]*PendingFormUpdate),
			revisions: make(map[string]int64),
			inFlight:  make(map[string]int64),
		},
	}
}

func testMessageWithKey(channelID, timestamp string) *SlackMessage {
	return &SlackMessage{
		key: &SlackMessageKey{
			channelID: channelID,
			timestamp: timestamp,
			threadTS:  "",
		},
	}
}

// --- Pending cleanup and leak safety ---

func TestPendingCleanupScenarios(t *testing.T) {
	cases := []struct {
		name       string
		debounceMs int
		prepare    func(s *Slack) int
		cleanup    func(s *Slack)
		wantAfter  int
	}{
		{
			name:       "single key cancel",
			debounceMs: 100,
			prepare: func(s *Slack) int {
				m := testMessageWithKey("ch1", "ts1")
				s.scheduleDebouncedFormUpdateWithRevision(m, 1)
				return 1
			},
			cleanup:   func(s *Slack) { s.cancelPendingFormUpdate(testMessageWithKey("ch1", "ts1").key) },
			wantAfter: 0,
		},
		{
			name:       "cancel all few keys",
			debounceMs: 50,
			prepare: func(s *Slack) int {
				for _, msg := range []struct{ ch, ts string }{{"ch1", "ts1"}, {"ch2", "ts2"}, {"ch3", "ts3"}} {
					s.scheduleDebouncedFormUpdateWithRevision(testMessageWithKey(msg.ch, msg.ts), 1)
				}
				return 3
			},
			cleanup:   func(s *Slack) { s.cancelAllPendingFormUpdates() },
			wantAfter: 0,
		},
		{
			name:       "cancel all many keys",
			debounceMs: 50,
			prepare: func(s *Slack) int {
				const numKeys = 200
				for i := 0; i < numKeys; i++ {
					s.scheduleDebouncedFormUpdateWithRevision(testMessageWithKey("ch", fmt.Sprintf("ts%d", i)), 1)
				}
				return numKeys
			},
			cleanup:   func(s *Slack) { s.cancelAllPendingFormUpdates() },
			wantAfter: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := testSlackWithDebounce(tc.debounceMs)
			before := tc.prepare(s)
			require.Equal(t, before, testCountPending(s), "unexpected pending count before cleanup")
			tc.cleanup(s)
			require.Equal(t, tc.wantAfter, testCountPending(s), "unexpected pending count after cleanup")
		})
	}
}

// Re-scheduling the same key must keep a single pending entry.
func TestScheduleReplacesPending(t *testing.T) {
	s := testSlackWithDebounce(200)
	m := testMessageWithKey("ch1", "ts1")

	s.scheduleDebouncedFormUpdateWithRevision(m, 1)
	s.scheduleDebouncedFormUpdateWithRevision(m, 2)

	require.Equal(t, 1, testCountPending(s), "only one pending per key (old timer replaced)")

	s.cancelPendingFormUpdate(m.key)
	require.Equal(t, 0, testCountPending(s), "no pending after cancel")
}

// Repeated schedule/cancel cycles must not accumulate pending entries.
func TestScheduleCancelNoLeak(t *testing.T) {
	s := testSlackWithDebounce(100)
	m := testMessageWithKey("ch1", "ts1")
	const iterations = 500

	for i := 0; i < iterations; i++ {
		s.scheduleDebouncedFormUpdateWithRevision(m, int64(i+1))
		s.cancelPendingFormUpdate(m.key)
	}

	require.Equal(t, 0, testCountPending(s),
		"no pending after %d schedule+cancel cycles (no leak)", iterations)
}

// --- Revision map leak safety ---

func TestRevisionMapScenarios(t *testing.T) {
	t.Run("one entry per key", func(t *testing.T) {
		s := testSlackWithDebounce(100)
		m := testMessageWithKey("ch1", "ts1")
		for i := 0; i < 20; i++ {
			s.bumpFormUpdateRevision(m.key)
		}
		require.Equal(t, 1, testCountRevisions(s), "repeated bumps of one key must keep one revisions entry")
	})

	t.Run("bounded by distinct keys", func(t *testing.T) {
		s := testSlackWithDebounce(50)
		const numKeys = 150

		for i := 0; i < numKeys; i++ {
			m := testMessageWithKey("ch", fmt.Sprintf("ts%d", i))
			s.bumpFormUpdateRevision(m.key)
			s.scheduleDebouncedFormUpdateWithRevision(m, 1)
		}

		require.Equal(t, numKeys, testCountRevisions(s), "revisions must have one entry per distinct key")
		require.Equal(t, numKeys, testCountPending(s), "all entries are pending before cancelAll")

		s.cancelAllPendingFormUpdates()
		require.Equal(t, 0, testCountPending(s), "cancelAll must clear pending")
		require.Equal(t, numKeys, testCountRevisions(s), "cancelAll must not grow revisions map")
	})
}

// --- Guard clauses and no-op inputs ---

func TestScheduleWithRevisionNoOpInputs(t *testing.T) {
	cases := []struct {
		name       string
		debounceMs int
		msg        *SlackMessage
		revision   int64
	}{
		{name: "nil message", debounceMs: 100, msg: nil, revision: 1},
		{name: "nil key", debounceMs: 100, msg: &SlackMessage{key: nil}, revision: 1},
		{name: "debounce disabled", debounceMs: 0, msg: testMessageWithKey("ch1", "ts1"), revision: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := testSlackWithDebounce(tc.debounceMs)
			s.scheduleDebouncedFormUpdateWithRevision(tc.msg, tc.revision)
			require.Equal(t, 0, testCountPending(s), "must stay no-op")
		})
	}
}

// --- Cancel behavior (no-op/idempotent) ---

func TestCancelPendingScenarios(t *testing.T) {
	cases := []struct {
		name       string
		cancelKey  func(m1, m2 *SlackMessage) *SlackMessageKey
		cancelRuns int
		want       int
	}{
		{
			name:       "nil key no-op",
			cancelKey:  func(_, _ *SlackMessage) *SlackMessageKey { return nil },
			cancelRuns: 1,
			want:       1,
		},
		{
			name:       "wrong key no-op",
			cancelKey:  func(_ *SlackMessage, m2 *SlackMessage) *SlackMessageKey { return m2.key },
			cancelRuns: 1,
			want:       1,
		},
		{
			name:       "idempotent cancel",
			cancelKey:  func(m1, _ *SlackMessage) *SlackMessageKey { return m1.key },
			cancelRuns: 2,
			want:       0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := testSlackWithDebounce(100)
			m1 := testMessageWithKey("ch1", "ts1")
			m2 := testMessageWithKey("ch2", "ts2")
			s.scheduleDebouncedFormUpdateWithRevision(m1, 1)

			key := tc.cancelKey(m1, m2)
			for i := 0; i < tc.cancelRuns; i++ {
				s.cancelPendingFormUpdate(key)
			}
			require.Equal(t, tc.want, testCountPending(s), "unexpected pending count after cancel")

			s.cancelPendingFormUpdate(m1.key)
			require.Equal(t, 0, testCountPending(s), "cleanup must leave zero pending")
		})
	}
}

// cancelAll is safe on empty and remains idempotent.
func TestCancelAllPendingIdempotent(t *testing.T) {
	s := testSlackWithDebounce(100)
	s.cancelAllPendingFormUpdates()
	require.Equal(t, 0, testCountPending(s), "cancelAll on empty is safe")
	m := testMessageWithKey("ch1", "ts1")
	s.scheduleDebouncedFormUpdateWithRevision(m, 1)
	s.cancelAllPendingFormUpdates()
	s.cancelAllPendingFormUpdates()
	require.Equal(t, 0, testCountPending(s), "second cancelAll still leaves 0 pending")
}

// --- Revision API behavior ---

func TestRevisionAPIScenarios(t *testing.T) {
	t.Run("bump nil key", func(t *testing.T) {
		s := testSlackWithDebounce(100)
		require.Equal(t, int64(0), s.bumpFormUpdateRevision(nil), "bump(nil) must return 0")
		require.Equal(t, 0, testCountRevisions(s), "bump(nil) must not add revisions entry")
	})

	t.Run("get unknown key", func(t *testing.T) {
		s := testSlackWithDebounce(100)
		require.Equal(t, int64(0), s.getFormUpdateRevision("unknown/channel"), "unknown key => 0")
	})

	t.Run("get after bumps", func(t *testing.T) {
		s := testSlackWithDebounce(100)
		m := testMessageWithKey("ch1", "ts1")
		keyStr := m.key.String()

		require.Equal(t, int64(0), s.getFormUpdateRevision(keyStr), "before bump => 0")
		require.Equal(t, int64(1), s.bumpFormUpdateRevision(m.key), "first bump => 1")
		require.Equal(t, int64(1), s.getFormUpdateRevision(keyStr), "after first bump => 1")
		require.Equal(t, int64(2), s.bumpFormUpdateRevision(m.key), "second bump => 2")
		require.Equal(t, int64(2), s.getFormUpdateRevision(keyStr), "after second bump => 2")
	})
}

func TestRevisionPruneByMaxEntries(t *testing.T) {
	origMax := formUpdateRevisionsMaxEntries
	formUpdateRevisionsMaxEntries = 3
	t.Cleanup(func() {
		formUpdateRevisionsMaxEntries = origMax
	})

	s := testSlackWithDebounce(100)
	for i := 0; i < 5; i++ {
		s.bumpFormUpdateRevision(testMessageWithKey("ch", fmt.Sprintf("ts%d", i)).key)
	}
	require.LessOrEqual(t, testCountRevisions(s), 3, "revisions map must stay within hard cap")
}

func TestRevisionPruneKeepsPendingKeys(t *testing.T) {
	origMax := formUpdateRevisionsMaxEntries
	formUpdateRevisionsMaxEntries = 1
	t.Cleanup(func() {
		formUpdateRevisionsMaxEntries = origMax
	})

	s := testSlackWithDebounce(1000)
	m1 := testMessageWithKey("ch1", "ts1")
	m2 := testMessageWithKey("ch2", "ts2")
	key1 := m1.key.String()

	s.bumpFormUpdateRevision(m1.key)
	s.scheduleDebouncedFormUpdateWithRevision(m1, 1)
	s.bumpFormUpdateRevision(m2.key) // triggers prune

	require.Equal(t, int64(1), s.getFormUpdateRevision(key1), "pending key revision must survive prune")
	require.Equal(t, 1, testCountPending(s), "pending entry must stay intact")
	s.cancelPendingFormUpdate(m1.key)
}

func TestRevisionPruneDoesNotDeleteCurrentBump(t *testing.T) {
	origMax := formUpdateRevisionsMaxEntries
	formUpdateRevisionsMaxEntries = 1
	t.Cleanup(func() {
		formUpdateRevisionsMaxEntries = origMax
	})

	s := testSlackWithDebounce(100)
	otherKey := testMessageWithKey("ch-other", "ts-other").key.String()
	currentKey := testMessageWithKey("ch-current", "ts-current").key

	// Keep one existing key pending so prune cannot remove it.
	s.formUpdates.revisions[otherKey] = 5
	s.formUpdates.pending[otherKey] = &PendingFormUpdate{}

	got := s.bumpFormUpdateRevision(currentKey)
	require.Equal(t, int64(1), got, "current bumped key must not be pruned")
	require.Equal(t, int64(1), s.getFormUpdateRevision(currentKey.String()), "current key revision must remain in map")
}

// Wrapper scheduleDebouncedFormUpdate should create one pending entry.
func TestScheduleDebouncedAddsPending(t *testing.T) {
	s := testSlackWithDebounce(100)
	m := testMessageWithKey("ch1", "ts1")
	s.scheduleDebouncedFormUpdate(m)
	require.Equal(t, 1, testCountPending(s), "scheduleDebouncedFormUpdate must add pending when debounce enabled")
	s.cancelPendingFormUpdate(m.key)
	require.Equal(t, 0, testCountPending(s), "cancel clears it")
}

// Stale revision must be ignored and keep a single pending entry.
func TestStaleRevisionIgnored(t *testing.T) {
	s := testSlackWithDebounce(100)
	m := testMessageWithKey("ch1", "ts1")

	s.scheduleDebouncedFormUpdateWithRevision(m, 2)
	require.Equal(t, 1, testCountPending(s), "one pending after first schedule")

	s.bumpFormUpdateRevision(m.key)
	s.scheduleDebouncedFormUpdateWithRevision(m, 1) // revision 1 is now stale

	require.Equal(t, 1, testCountPending(s), "stale schedule must not add extra entry")

	s.cancelPendingFormUpdate(m.key)
	require.Equal(t, 0, testCountPending(s), "no pending after cancel")
}

// revision=0 should resolve to current per-key revision.
func TestScheduleWithZeroRevisionUsesCurrent(t *testing.T) {
	s := testSlackWithDebounce(1000)
	m := testMessageWithKey("ch1", "ts1")
	keyStr := m.key.String()

	currentRevision := s.bumpFormUpdateRevision(m.key)
	require.Equal(t, int64(1), currentRevision, "first bump sets revision to 1")

	s.scheduleDebouncedFormUpdateWithRevision(m, 0)

	s.formUpdates.mu.Lock()
	p, ok := s.formUpdates.pending[keyStr]
	s.formUpdates.mu.Unlock()
	require.True(t, ok, "pending entry must be created")
	require.NotNil(t, p.snapshot, "pending snapshot must be set")
	require.Equal(t, currentRevision, p.snapshot.revision, "revision=0 must resolve to current revision")

	s.cancelPendingFormUpdate(m.key)
	require.Equal(t, 0, testCountPending(s), "no pending after cancel")
}

// runPendingFormUpdate is a no-op for unknown key or wrong generation.
func TestRunPendingNoOpForMissingOrWrongGen(t *testing.T) {
	s := testSlackWithDebounce(1000)
	m := testMessageWithKey("ch1", "ts1")
	keyStr := m.key.String()

	s.runPendingFormUpdate("missing/key", 1)
	require.Equal(t, 0, testCountPending(s), "unknown key must be no-op")

	s.scheduleDebouncedFormUpdateWithRevision(m, 1)
	require.Equal(t, 1, testCountPending(s), "one pending after schedule")

	s.formUpdates.mu.Lock()
	p, ok := s.formUpdates.pending[keyStr]
	s.formUpdates.mu.Unlock()
	require.True(t, ok, "pending entry must exist")
	actualGeneration := p.generation

	s.runPendingFormUpdate(keyStr, actualGeneration+1)
	require.Equal(t, 1, testCountPending(s), "wrong generation must not remove current pending")

	s.cancelPendingFormUpdate(m.key)
	require.Equal(t, 0, testCountPending(s), "no pending after cancel")
}

// Timer-fire happy path is covered best by integration tests with Slack API mock.

// --- Concurrency (run with go test -race) ---

// Many goroutines schedule/cancel the same key; pending must end at 0.
func TestConcurrentScheduleCancelSameKey(t *testing.T) {
	s := testSlackWithDebounce(50)
	m := testMessageWithKey("ch1", "ts1")
	key := m.key
	const concurrency = 30
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(rev int64) {
			defer wg.Done()
			s.scheduleDebouncedFormUpdateWithRevision(m, rev)
			s.cancelPendingFormUpdate(key)
		}(int64(i + 1))
	}
	wg.Wait()
	require.Equal(t, 0, testCountPending(s), "no pending after concurrent schedule+cancel same key")
}

// Many goroutines schedule/cancel distinct keys; pending 0 and revisions bounded.
func TestConcurrentScheduleCancelDifferentKeys(t *testing.T) {
	s := testSlackWithDebounce(50)
	const concurrency = 30
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			m := testMessageWithKey("ch", fmt.Sprintf("ts%d", idx))
			s.bumpFormUpdateRevision(m.key)
			s.scheduleDebouncedFormUpdateWithRevision(m, 1)
			s.cancelPendingFormUpdate(m.key)
		}(i)
	}
	wg.Wait()
	require.Equal(t, 0, testCountPending(s), "no pending after concurrent schedule+cancel different keys")
	require.Equal(t, concurrency, testCountRevisions(s), "one revision entry per key")
}

func TestHasInFlightOlderUpdateScenarios(t *testing.T) {
	s := testSlackWithDebounce(100)
	key := testMessageWithKey("ch1", "ts1").key.String()

	// no in-flight entry -> false
	require.False(t, s.hasInFlightOlderUpdate(key, 2), "no in-flight state must return false")

	s.formUpdates.mu.Lock()
	s.formUpdates.inFlight[key] = 2
	s.formUpdates.mu.Unlock()

	// older in-flight revision -> true
	require.True(t, s.hasInFlightOlderUpdate(key, 3), "older in-flight revision must be detected")
	// same/newer target revision -> false
	require.False(t, s.hasInFlightOlderUpdate(key, 2), "same revision is not older")
	require.False(t, s.hasInFlightOlderUpdate(key, 1), "newer in-flight revision should not match")
}
