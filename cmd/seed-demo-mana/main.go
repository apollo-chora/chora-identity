// Command seed-demo-mana is a one-off, narrowly scoped operator command that
// credits the DEMO mana balance to an explicit list of EXISTING GCIDs.
//
// WHY THIS EXISTS. The full seed program (cmd/seed) also upserts the tenant,
// user rows, Argon2id credentials and memberships, so running it on a live
// deployment merely to add demo balances can mutate identity data it was never
// meant to touch (round-9 review). This command performs ONLY the wallet
// credit — `user_mana` + `mana_ledger`, written by the already-tested
// transactional primitive pg.SeedDemoGrant. It NEVER creates a user, and never
// touches local_credentials or tenant_memberships: a GCID with no `users` row is
// reported as unknown and left alone. It is not a substitute for ad-hoc SQL
// against wallet balances, which is explicitly rejected.
//
// IDEMPOTENT. The idempotency key is deterministic (`demo-seed:v1:<gcid>`) —
// the SAME key cmd/seed uses, so the two recognise each other's grants and
// whichever ran first wins. A re-run replays: it finds the existing ledger row
// and credits nothing, and a balance the account has since spent is never
// reset.
//
// TRANSACTION SHAPE. Each GCID gets ONE transaction, opened by
// pg.RunInUserTx, which applies `SET LOCAL chora.user_gcid = '<gcid>'` so the
// user_isolation RLS policy on user_mana / mana_ledger scopes the writes to
// that account. SeedDemoGrant is handed THAT transaction — it takes an existing
// tx by design — so no nested transaction is opened and no second connection is
// held while the primitive runs. Per-GCID transactions also mean one bad GCID
// does not roll back the rest of the batch.
//
// AUTHORIZATION GATE. Both the dry run and the real run refuse unless
// CHORA_DEMO_MANA_TOPUP_ENABLED=true AND CHORA_DEMO_MODE=true, and refuse
// outright when CHORA_ENV is `prod` or `production`. CHORA_ENV being unset must
// not enable anything.
//
// Environment:
//
//	CHORA_DB_DSN                  — chora_identity connection string (required)
//	CHORA_DEMO_MANA_GCIDS         — comma-separated GCIDs (unless -gcids/-gcid)
//	CHORA_DEMO_MANA_GRANT_UNITS   — units per GCID (default 1000000000)
//	CHORA_DEMO_MANA_TOPUP_ENABLED — must be true
//	CHORA_DEMO_MODE               — must be true
//	CHORA_ENV                     — must not be prod/production
//
// Usage:
//
//	# DRY RUN — reads the wallet and ledger state, writes nothing
//	CHORA_DEMO_MODE=true CHORA_DEMO_MANA_TOPUP_ENABLED=true \
//	  CHORA_DB_DSN=postgres://... go run ./cmd/seed-demo-mana \
//	  -gcids=<gcid>,<gcid> -dry-run
//
//	# REAL RUN — the same invocation without -dry-run
//	CHORA_DEMO_MODE=true CHORA_DEMO_MANA_TOPUP_ENABLED=true \
//	  CHORA_DB_DSN=postgres://... go run ./cmd/seed-demo-mana \
//	  -gcids=<gcid>,<gcid>
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/apollo-chora/chora-identity/internal/adapter/pg"
	mana "github.com/apollo-chora/chora-identity/internal/domain/user_mana"
)

const (
	// demoSeedGrantPrefix is the SAME deterministic key cmd/seed derives, so a
	// grant applied by either command is replayed by the other instead of being
	// credited twice.
	demoSeedGrantPrefix = "demo-seed:v1:"
	// defaultGrantUnits is the demo balance: one billion mana.
	defaultGrantUnits = int64(1_000_000_000)

	envDSN        = "CHORA_DB_DSN"
	envGcids      = "CHORA_DEMO_MANA_GCIDS"
	envGrantUnits = "CHORA_DEMO_MANA_GRANT_UNITS"
	envDemoMode   = "CHORA_DEMO_MODE"
	envDemoTopup  = "CHORA_DEMO_MANA_TOPUP_ENABLED"
	envChoraEnv   = "CHORA_ENV"

	// Per-GCID outcomes reported in the audit summary.
	statusApplied       = "applied"
	statusReplayed      = "replayed"
	statusUnknownGcid   = "unknown-gcid"
	statusWouldApply    = "would-apply"
	statusWouldReplay   = "would-replay"
	statusConflict      = "conflict"
	statusWouldConflict = "would-conflict"
	statusFailed        = "failed"
)

// config is the command's resolved input.
type config struct {
	DSN    string
	Gcids  []string
	Units  int64
	DryRun bool
}

// gcidsFlag collects a repeatable -gcid flag.
type gcidsFlag []string

func (f *gcidsFlag) String() string { return strings.Join(*f, ",") }

func (f *gcidsFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

// loadConfig resolves the flags and the environment. GCIDs may come from
// -gcids (comma-separated), repeated -gcid flags, or CHORA_DEMO_MANA_GCIDS;
// they are canonicalised to lowercase UUIDs and de-duplicated, because the
// idempotency key is per GCID.
func loadConfig(args []string) (config, error) {
	fs := flag.NewFlagSet("seed-demo-mana", flag.ContinueOnError)
	var repeated gcidsFlag
	fs.Var(&repeated, "gcid", "a GCID to grant demo mana to (repeatable)")
	list := fs.String("gcids", os.Getenv(envGcids), "comma-separated GCIDs (default $"+envGcids+")")
	amount := fs.Int64("amount", grantUnitsFromEnv(), "units granted per GCID (default $"+envGrantUnits+")")
	dryRun := fs.Bool("dry-run", false, "report what WOULD happen from the current wallet and ledger state; write nothing")
	dsn := fs.String("dsn", os.Getenv(envDSN), "chora_identity connection string (default $"+envDSN+")")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}

	var raw []string
	if s := strings.TrimSpace(*list); s != "" {
		for _, part := range strings.Split(s, ",") {
			p := strings.TrimSpace(part)
			if p == "" {
				// A trailing comma (or a blank slot between commas) is a typo, not
				// a GCID — the round-6 review requires it to be rejected rather
				// than silently skipped.
				return config{}, errors.New("the GCID list has an empty entry — every entry must be a non-empty GCID (UUID)")
			}
			raw = append(raw, p)
		}
	}
	raw = append(raw, repeated...)

	seen := make(map[string]bool, len(raw))
	gcids := make([]string, 0, len(raw))
	for _, r := range raw {
		id, err := uuid.Parse(strings.TrimSpace(r))
		if err != nil {
			return config{}, fmt.Errorf("gcid %q is not a UUID: %w", r, err)
		}
		canonical := id.String()
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		gcids = append(gcids, canonical)
	}
	if len(gcids) == 0 {
		return config{}, fmt.Errorf("no GCIDs given: pass -gcids=<a,b>, a repeated -gcid=<a>, or set %s", envGcids)
	}
	if *amount <= 0 {
		return config{}, fmt.Errorf("the grant amount must be > 0, got %d", *amount)
	}
	if strings.TrimSpace(*dsn) == "" {
		return config{}, fmt.Errorf("%s is required (or -dsn)", envDSN)
	}
	return config{DSN: strings.TrimSpace(*dsn), Gcids: gcids, Units: *amount, DryRun: *dryRun}, nil
}

// grantUnitsFromEnv returns the configured per-GCID grant, or the 1e9 default.
func grantUnitsFromEnv() int64 {
	if v, err := strconv.ParseInt(strings.TrimSpace(os.Getenv(envGrantUnits)), 10, 64); err == nil && v > 0 {
		return v
	}
	return defaultGrantUnits
}

// authorize enforces the demo authorization gate. It refuses in a production
// environment FIRST, so a production run never depends on the other two flags
// being absent.
func authorize() error {
	choraEnv := strings.TrimSpace(os.Getenv(envChoraEnv))
	if strings.EqualFold(choraEnv, "prod") || strings.EqualFold(choraEnv, "production") {
		return fmt.Errorf("refusing to run: %s=%q is a production environment", envChoraEnv, choraEnv)
	}
	if !envIsTrue(envDemoMode) {
		return fmt.Errorf("refusing to run: %s must be set to true", envDemoMode)
	}
	if !envIsTrue(envDemoTopup) {
		return fmt.Errorf("refusing to run: %s must be set to true", envDemoTopup)
	}
	return nil
}

func envIsTrue(key string) bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(key)), "true")
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	cfg, err := loadConfig(os.Args[1:])
	if err != nil {
		log.Fatalf("seed-demo-mana: %v", err)
	}
	if err := authorize(); err != nil {
		log.Fatalf("seed-demo-mana: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DSN)
	if err != nil {
		log.Fatalf("seed-demo-mana: pgxpool: %v", err)
	}
	defer pool.Close()

	runCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	if err := run(runCtx, pg.NewPgxPoolQuerier(pool), cfg, os.Stdout); err != nil {
		log.Fatalf("seed-demo-mana: %v", err)
	}
}

// grantOutcome is one GCID's audit record.
type grantOutcome struct {
	Gcid        string
	Status      string
	BeforeUnits int64
	AfterUnits  int64
	Err         error
}

// run applies (or dry-runs) the grant for every configured GCID and prints the
// audit summary. The WHOLE list is processed before returning, so one bad GCID
// does not hide the fate of the rest; the returned error reports that at least
// one GCID was not granted.
func run(ctx context.Context, txr pg.UserTxQuerier, cfg config, out io.Writer) error {
	mode := "APPLY"
	if cfg.DryRun {
		mode = "DRY RUN — no writes"
	}
	fmt.Fprintf(out, "seed-demo-mana: %s gcids=%d units_per_gcid=%d key_prefix=%s\n",
		mode, len(cfg.Gcids), cfg.Units, demoSeedGrantPrefix)

	var (
		outcomes []grantOutcome
		notDone  []string
		firstErr error
	)
	for _, gcid := range cfg.Gcids {
		o := processGcid(ctx, txr, cfg, gcid)
		outcomes = append(outcomes, o)
		printOutcome(out, o)
		if o.Err != nil {
			notDone = append(notDone, gcid)
			if firstErr == nil {
				firstErr = o.Err
			}
		}
	}
	printSummary(out, outcomes)
	if len(notDone) > 0 {
		// The per-GCID lines above carry the detail; the wrapped cause keeps
		// errors.Is usable for the sentinels (idempotency conflict).
		return fmt.Errorf("%d of %d gcid(s) were not granted (%s): %w",
			len(notDone), len(cfg.Gcids), strings.Join(notDone, ", "), firstErr)
	}
	return nil
}

// processGcid handles one GCID inside its own RLS-scoped transaction.
func processGcid(ctx context.Context, txr pg.UserTxQuerier, cfg config, gcid string) grantOutcome {
	o := grantOutcome{Gcid: gcid}
	err := txr.RunInUserTx(ctx, gcid, "", func(ctx context.Context, tx pg.Tx) error {
		return grantInTx(ctx, tx, cfg, &o)
	})
	if err != nil {
		o.Status = statusFailed
		if errors.Is(err, mana.ErrIdempotencyConflict) {
			o.Status = statusConflict
		}
		o.Err = err
	}
	return o
}

// grantInTx runs on the caller's already-RLS-scoped transaction. It reads the
// account's current wallet and ledger state, then — unless this is a dry run —
// hands the SAME transaction to pg.SeedDemoGrant. It writes nothing else: no
// user row, no credential, no membership.
func grantInTx(ctx context.Context, tx pg.Tx, cfg config, o *grantOutcome) error {
	exists, err := userExistsTx(ctx, tx, o.Gcid)
	if err != nil {
		return err
	}
	if !exists {
		// The primitive would happily create a wallet row for a GCID that has no
		// account, i.e. conjure mana for nobody. Refuse, and say so. Nothing is
		// rolled back: this transaction wrote nothing.
		o.Status = statusUnknownGcid
		o.Err = fmt.Errorf("gcid %s has no account — refusing to create one", o.Gcid)
		return nil
	}

	before, err := visibleBalanceTx(ctx, tx, o.Gcid)
	if err != nil {
		return err
	}
	o.BeforeUnits, o.AfterUnits = before, before

	key := demoSeedGrantKey(o.Gcid)
	existing, err := ledgerEntryTx(ctx, tx, o.Gcid, key)
	if err != nil {
		return err
	}
	in := mana.CreditWalletInput{
		Gcid:           o.Gcid,
		Units:          cfg.Units,
		Direction:      mana.DirectionMint,
		Reason:         mana.ReasonDemoGrant,
		IdempotencyKey: key,
	}

	if cfg.DryRun {
		switch {
		case existing == nil:
			projected, err := mana.CheckedAddUnits(before, cfg.Units)
			if err != nil {
				return err
			}
			o.Status, o.AfterUnits = statusWouldApply, projected
		case mana.CreditWalletMatchesLedger(existing, in):
			// Already applied: the balance stays where it is.
			o.Status = statusWouldReplay
		default:
			// The key exists but records a different operation — the real run
			// would be refused with ErrIdempotencyConflict. Report it now.
			o.Status = statusWouldConflict
			o.Err = fmt.Errorf("%w: gcid=%s key=%s", mana.ErrIdempotencyConflict, o.Gcid, key)
		}
		return nil
	}

	res, err := pg.SeedDemoGrant(ctx, tx, o.Gcid, key, cfg.Units)
	if err != nil {
		return err
	}
	if res != nil && res.Replayed {
		o.Status = statusReplayed
	} else {
		o.Status = statusApplied
	}
	if res != nil {
		o.AfterUnits = res.BalanceAfterUnits
	}
	return nil
}

// demoSeedGrantKey derives the deterministic idempotency key for a GCID.
func demoSeedGrantKey(gcid string) string { return demoSeedGrantPrefix + gcid }

// userExistsTx reports whether an ACCOUNT exists for the GCID. `users` carries
// no RLS policy, so this needs no GUC. A missing account is never created here.
func userExistsTx(ctx context.Context, tx pg.Tx, gcid string) (bool, error) {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE gcid = $1)`, gcid).Scan(&exists); err != nil {
		return false, fmt.Errorf("read user %s: %w", gcid, err)
	}
	return exists, nil
}

// visibleBalanceTx reads the user-visible balance — the personal wallet plus any
// remaining tenant-subsidy allocation — which is the quantity SeedDemoGrant
// reports as BalanceAfterUnits. 0 when no wallet row exists yet.
func visibleBalanceTx(ctx context.Context, tx pg.Tx, gcid string) (int64, error) {
	var bal int64
	err := tx.QueryRow(ctx,
		`SELECT COALESCE(balance_units, 0) FROM user_mana WHERE gcid = $1`, gcid).Scan(&bal)
	if err != nil && !errors.Is(err, pg.ErrNoRows) {
		return 0, fmt.Errorf("read wallet %s: %w", gcid, err)
	}
	var subsidy int64
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(sum(remaining_units), 0)::bigint FROM mana_subsidy_allocations WHERE gcid = $1`,
		gcid).Scan(&subsidy); err != nil {
		return 0, fmt.Errorf("read subsidy allocations %s: %w", gcid, err)
	}
	return bal + subsidy, nil
}

// ledgerEntryTx reads the ledger row recorded under (gcid, key), or nil when the
// key has never been used. It is the same lookup the primitive performs, done
// here so the dry run can classify the outcome without writing.
func ledgerEntryTx(ctx context.Context, tx pg.Tx, gcid, key string) (*mana.LedgerEntry, error) {
	row := tx.QueryRow(ctx, `
		SELECT entry_id, gcid, direction, units, reason,
		       source_subscription_id, source_action_id, source_allocation_id, source_topup_id,
		       balance_after_units, idempotency_key, request_id, reverses_entry_id, recorded_at
		  FROM mana_ledger
		 WHERE gcid = $1 AND idempotency_key = $2
		 ORDER BY recorded_at ASC
		 LIMIT 1`, gcid, key)
	var (
		e                                                        mana.LedgerEntry
		direction, reason                                        string
		subID, actionID, allocID, topupID, requestID, reversesID *string
	)
	if err := row.Scan(&e.EntryID, &e.Gcid, &direction, &e.Units, &reason,
		&subID, &actionID, &allocID, &topupID,
		&e.BalanceAfterUnits, &e.IdempotencyKey, &requestID, &reversesID, &e.RecordedAt); err != nil {
		if errors.Is(err, pg.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("read ledger %s/%s: %w", gcid, key, err)
	}
	e.Direction, e.Reason = mana.Direction(direction), mana.Reason(reason)
	e.SourceSubscriptionID, e.SourceActionID = deref(subID), deref(actionID)
	e.SourceAllocationID, e.SourceTopupID = deref(allocID), deref(topupID)
	e.RequestID, e.ReversesEntryID = deref(requestID), deref(reversesID)
	return &e, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// printOutcome writes one GCID's audit line.
func printOutcome(out io.Writer, o grantOutcome) {
	switch o.Status {
	case statusApplied:
		fmt.Fprintf(out, "seed-demo-mana: gcid=%s status=%s before=%d after=%d key=%s\n",
			o.Gcid, o.Status, o.BeforeUnits, o.AfterUnits, demoSeedGrantKey(o.Gcid))
	case statusReplayed:
		fmt.Fprintf(out, "seed-demo-mana: gcid=%s status=%s balance=%d key=%s — already granted, credited nothing\n",
			o.Gcid, o.Status, o.AfterUnits, demoSeedGrantKey(o.Gcid))
	case statusUnknownGcid:
		fmt.Fprintf(out, "seed-demo-mana: gcid=%s status=%s — no such account; NOT created, nothing granted\n",
			o.Gcid, o.Status)
	case statusWouldApply:
		fmt.Fprintf(out, "seed-demo-mana: gcid=%s status=%s before=%d after=%d key=%s\n",
			o.Gcid, o.Status, o.BeforeUnits, o.AfterUnits, demoSeedGrantKey(o.Gcid))
	case statusWouldReplay:
		fmt.Fprintf(out, "seed-demo-mana: gcid=%s status=%s balance=%d key=%s — the real run would credit nothing\n",
			o.Gcid, o.Status, o.AfterUnits, demoSeedGrantKey(o.Gcid))
	default:
		fmt.Fprintf(out, "seed-demo-mana: gcid=%s status=%s error=%v\n", o.Gcid, o.Status, o.Err)
	}
}

// printSummary writes the batch audit line: the applied-vs-replayed counts per
// status, plus the units actually credited in this run.
func printSummary(out io.Writer, outcomes []grantOutcome) {
	counts := map[string]int{}
	var credited int64
	for _, o := range outcomes {
		counts[o.Status]++
		if o.Status == statusApplied {
			credited += o.AfterUnits - o.BeforeUnits
		}
	}
	fmt.Fprintf(out, "seed-demo-mana: summary gcids=%d", len(outcomes))
	for _, s := range []string{
		statusApplied, statusReplayed, statusUnknownGcid,
		statusWouldApply, statusWouldReplay,
		statusConflict, statusWouldConflict, statusFailed,
	} {
		if counts[s] > 0 {
			fmt.Fprintf(out, " %s=%d", s, counts[s])
		}
	}
	fmt.Fprintf(out, " units_credited=%d\n", credited)
}
