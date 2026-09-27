package workflow

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
	"cert-me/internal/storage/sqlstore/core"
	"cert-me/internal/storage/sqlstore/dialect"
)

// TransitionRepository implements port.TransitionRepository on the caller's
// unit of work. Impact and deployment rows remain independent, append-only
// facts; this repository never creates a transaction of its own.
type TransitionRepository struct {
	executor core.SQLExecutor
	dialect  dialect.Dialect
}

// NewTransitionRepository constructs a transition repository bound to
// executor.
func NewTransitionRepository(executor core.SQLExecutor, d dialect.Dialect) (*TransitionRepository, error) {
	validated, err := validate(executor, d)
	if err != nil {
		return nil, err
	}
	return &TransitionRepository{executor: executor, dialect: validated}, nil
}

var _ port.TransitionRepository = (*TransitionRepository)(nil)

func (r *TransitionRepository) GetForUpdate(ctx context.Context, id domain.TransitionID) (domain.Transition, error) {
	if err := checkContext(ctx); err != nil {
		return domain.Transition{}, err
	}
	if _, err := domain.ParseTransitionID(string(id)); err != nil {
		return domain.Transition{}, fmt.Errorf("sqlstore workflow: validate transition id: %w", err)
	}
	b := r.dialect.NewBuilder()
	query := "SELECT id, source_authority_id, target_authority_id, mode, state, reported_by, reported_at, reason, version FROM ca_transitions WHERE id = " +
		b.Add(string(id)) + r.dialect.RowLockClause()
	transition, err := scanTransition(r.executor.QueryRowContext(ctx, query, b.Args()...))
	if err != nil {
		return domain.Transition{}, fmt.Errorf("sqlstore workflow: get transition for update: %w", missing(err))
	}
	return transition, nil
}

func (r *TransitionRepository) Insert(ctx context.Context, transition domain.Transition) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if _, err := domain.NewTransition(domain.TransitionFacts{
		ID: transition.ID(), SourceAuthorityID: transition.SourceAuthorityID(), TargetAuthorityID: transition.TargetAuthorityID(),
		Mode: transition.Mode(), State: transition.State(), ReportedBy: transition.ReportedBy(), ReportedAt: transition.ReportedAt(),
		Reason: transition.Reason(), Version: transition.Version(),
	}); err != nil {
		return fmt.Errorf("sqlstore workflow: validate transition: %w", err)
	}
	if _, err := domain.ParseVersion(int64(transition.Version())); err != nil {
		return fmt.Errorf("sqlstore workflow: validate transition: %w", err)
	}
	now := nowUnixMicro()
	b := r.dialect.NewBuilder()
	query := "INSERT INTO ca_transitions (id, created_at, updated_at, version, source_authority_id, target_authority_id, mode, state, reported_by, reported_at, reason) VALUES (" +
		b.Add(string(transition.ID())) + ", " + b.Add(now) + ", " + b.Add(now) + ", " + b.Add(int64(transition.Version())) + ", " +
		b.Add(string(transition.SourceAuthorityID())) + ", " + optionalString(string(transition.TargetAuthorityID()), b) + ", " +
		b.Add(string(transition.Mode())) + ", " + b.Add(string(transition.State())) + ", " + b.Add(string(transition.ReportedBy())) + ", " +
		b.Add(transition.ReportedAt().UnixMicro()) + ", " + b.Add(transition.Reason()) + ")"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return insertError("insert transition", err)
	}
	return nil
}

func (r *TransitionRepository) Save(ctx context.Context, transition domain.Transition, expectedVersion domain.Version) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if _, err := domain.ParseVersion(int64(expectedVersion)); err != nil {
		return fmt.Errorf("sqlstore workflow: validate expected transition version: %w", err)
	}
	if _, err := domain.NewTransition(domain.TransitionFacts{
		ID: transition.ID(), SourceAuthorityID: transition.SourceAuthorityID(), TargetAuthorityID: transition.TargetAuthorityID(),
		Mode: transition.Mode(), State: transition.State(), ReportedBy: transition.ReportedBy(), ReportedAt: transition.ReportedAt(),
		Reason: transition.Reason(), Version: transition.Version(),
	}); err != nil {
		return fmt.Errorf("sqlstore workflow: validate transition: %w", err)
	}
	if _, err := domain.ParseVersion(int64(transition.Version())); err != nil {
		return fmt.Errorf("sqlstore workflow: validate transition: %w", err)
	}
	b := r.dialect.NewBuilder()
	query := "UPDATE ca_transitions SET updated_at = " + b.Add(nowUnixMicro()) + ", version = " + b.Add(int64(transition.Version())) +
		", source_authority_id = " + b.Add(string(transition.SourceAuthorityID())) + ", target_authority_id = " + optionalString(string(transition.TargetAuthorityID()), b) +
		", mode = " + b.Add(string(transition.Mode())) + ", state = " + b.Add(string(transition.State())) +
		", reported_by = " + b.Add(string(transition.ReportedBy())) + ", reported_at = " + b.Add(transition.ReportedAt().UnixMicro()) +
		", reason = " + b.Add(transition.Reason()) + " WHERE id = " + b.Add(string(transition.ID())) + " AND version = " + b.Add(int64(expectedVersion))
	result, err := r.executor.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return fmt.Errorf("sqlstore workflow: save transition: %w", err)
	}
	affected, err := rowsAffected(result, nil)
	if err != nil {
		return fmt.Errorf("sqlstore workflow: inspect transition save: %w", err)
	}
	if affected != 0 {
		return nil
	}
	return r.checkTransitionVersion(ctx, transition.ID(), expectedVersion)
}

func (r *TransitionRepository) checkTransitionVersion(ctx context.Context, id domain.TransitionID, expectedVersion domain.Version) error {
	b := r.dialect.NewBuilder()
	query := "SELECT version FROM ca_transitions WHERE id = " + b.Add(string(id))
	var stored int64
	if err := r.executor.QueryRowContext(ctx, query, b.Args()...).Scan(&stored); err != nil {
		return fmt.Errorf("sqlstore workflow: inspect transition version: %w", missing(err))
	}
	if stored != int64(expectedVersion) {
		return port.ErrVersionConflict
	}
	// MySQL-compatible drivers may report zero for a matched no-op update.
	return nil
}

func scanTransition(row rowScanner) (domain.Transition, error) {
	var id, sourceID, mode, state, reportedBy, reason string
	var targetID sql.NullString
	var reportedAt, version int64
	if err := row.Scan(&id, &sourceID, &targetID, &mode, &state, &reportedBy, &reportedAt, &reason, &version); err != nil {
		return domain.Transition{}, err
	}
	parsedID, err := domain.ParseTransitionID(id)
	if err != nil {
		return domain.Transition{}, fmt.Errorf("invalid stored transition id: %w", err)
	}
	parsedSource, err := domain.ParseAuthorityID(sourceID)
	if err != nil {
		return domain.Transition{}, fmt.Errorf("invalid stored transition source: %w", err)
	}
	var parsedTarget domain.AuthorityID
	if targetID.Valid {
		parsedTarget, err = domain.ParseAuthorityID(targetID.String)
		if err != nil {
			return domain.Transition{}, fmt.Errorf("invalid stored transition target: %w", err)
		}
	}
	parsedActor, err := domain.ParseAccountID(reportedBy)
	if err != nil {
		return domain.Transition{}, fmt.Errorf("invalid stored transition actor: %w", err)
	}
	parsedVersion, err := domain.ParseVersion(version)
	if err != nil {
		return domain.Transition{}, fmt.Errorf("invalid stored transition version: %w", err)
	}
	return domain.NewTransition(domain.TransitionFacts{
		ID: parsedID, SourceAuthorityID: parsedSource, TargetAuthorityID: parsedTarget,
		Mode: domain.TransitionMode(mode), State: domain.TransitionState(state), ReportedBy: parsedActor,
		ReportedAt: domain.InstantFromUnixMicro(reportedAt), Reason: reason, Version: parsedVersion,
	})
}

func (r *TransitionRepository) AddImpact(ctx context.Context, impact domain.TransitionImpact) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if _, err := validateImpact(impact); err != nil {
		return fmt.Errorf("sqlstore workflow: validate transition impact: %w", err)
	}
	b := r.dialect.NewBuilder()
	query := "INSERT INTO transition_impacts (transition_id, certificate_id, replacement_certificate_id, reissued_at) VALUES (" +
		b.Add(string(impact.TransitionID())) + ", " + b.Add(string(impact.CertificateID())) + ", " +
		optionalString(string(impact.ReplacementCertificateID()), b) + ", " + optionalInstant(impact.ReissuedAt(), b) + ")"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return insertError("insert transition impact", err)
	}
	return nil
}

func (r *TransitionRepository) LinkReplacement(ctx context.Context, impact domain.TransitionImpact) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if _, err := validateImpact(impact); err != nil {
		return fmt.Errorf("sqlstore workflow: validate transition impact: %w", err)
	}
	if !impact.IsResolved() {
		return errors.New("sqlstore workflow: link replacement requires a resolved impact")
	}
	b := r.dialect.NewBuilder()
	query := "UPDATE transition_impacts SET replacement_certificate_id = " + b.Add(string(impact.ReplacementCertificateID())) +
		", reissued_at = " + b.Add(impact.ReissuedAt().UnixMicro()) + " WHERE transition_id = " + b.Add(string(impact.TransitionID())) +
		" AND certificate_id = " + b.Add(string(impact.CertificateID())) + " AND replacement_certificate_id IS NULL"
	result, err := r.executor.ExecContext(ctx, query, b.Args()...)
	if err != nil {
		return fmt.Errorf("sqlstore workflow: link transition replacement: %w", err)
	}
	affected, err := rowsAffected(result, nil)
	if err != nil {
		return fmt.Errorf("sqlstore workflow: inspect transition impact link: %w", err)
	}
	if affected != 0 {
		return nil
	}
	return r.checkUnresolvedImpact(ctx, impact)
}

func (r *TransitionRepository) checkUnresolvedImpact(ctx context.Context, impact domain.TransitionImpact) error {
	b := r.dialect.NewBuilder()
	query := "SELECT 1 FROM transition_impacts WHERE transition_id = " + b.Add(string(impact.TransitionID())) + " AND certificate_id = " + b.Add(string(impact.CertificateID()))
	var found int
	if err := r.executor.QueryRowContext(ctx, query, b.Args()...).Scan(&found); err != nil {
		return fmt.Errorf("sqlstore workflow: inspect transition impact: %w", missing(err))
	}
	// The impact exists but it was already resolved by another update (or the
	// driver reported a no-op despite the non-empty pointer update).
	return port.ErrVersionConflict
}

func validateImpact(impact domain.TransitionImpact) (domain.TransitionImpact, error) {
	return domain.NewTransitionImpact(domain.TransitionImpactFacts{
		TransitionID: impact.TransitionID(), CertificateID: impact.CertificateID(),
		ReplacementCertificateID: impact.ReplacementCertificateID(), ReissuedAt: impact.ReissuedAt(),
	})
}

func (r *TransitionRepository) AddDeploymentConfirmation(ctx context.Context, confirmation domain.DeploymentConfirmation) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if _, err := domain.NewDeploymentConfirmation(domain.DeploymentConfirmationFacts{
		TransitionID: confirmation.TransitionID(), CertificateID: confirmation.CertificateID(), TargetLabel: confirmation.TargetLabel(),
		Action: confirmation.Action(), ConfirmedBy: confirmation.ConfirmedBy(), ConfirmedAt: confirmation.ConfirmedAt(),
	}); err != nil {
		return fmt.Errorf("sqlstore workflow: validate deployment confirmation: %w", err)
	}
	id, err := newUUID()
	if err != nil {
		return fmt.Errorf("sqlstore workflow: generate deployment confirmation id: %w", err)
	}
	b := r.dialect.NewBuilder()
	query := "INSERT INTO deployment_confirmations (id, created_at, transition_id, certificate_id, target_label, action, confirmed_by, confirmed_at) VALUES (" +
		b.Add(id) + ", " + b.Add(nowUnixMicro()) + ", " + b.Add(string(confirmation.TransitionID())) + ", " +
		optionalString(string(confirmation.CertificateID()), b) + ", " + b.Add(confirmation.TargetLabel()) + ", " +
		b.Add(string(confirmation.Action())) + ", " + b.Add(string(confirmation.ConfirmedBy())) + ", " + b.Add(confirmation.ConfirmedAt().UnixMicro()) + ")"
	if _, err := r.executor.ExecContext(ctx, query, b.Args()...); err != nil {
		return insertError("insert deployment confirmation", err)
	}
	return nil
}

func newUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	compact := hex.EncodeToString(raw[:])
	return compact[:8] + "-" + compact[8:12] + "-" + compact[12:16] + "-" + compact[16:20] + "-" + compact[20:], nil
}

func (r *TransitionRepository) ListImpacts(ctx context.Context, transitionID domain.TransitionID) ([]domain.TransitionImpact, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if _, err := domain.ParseTransitionID(string(transitionID)); err != nil {
		return nil, fmt.Errorf("sqlstore workflow: validate transition id: %w", err)
	}
	b := r.dialect.NewBuilder()
	query := "SELECT transition_id, certificate_id, replacement_certificate_id, reissued_at FROM transition_impacts WHERE transition_id = " + b.Add(string(transitionID)) + " ORDER BY certificate_id"
	rows, err := r.executor.QueryContext(ctx, query, b.Args()...)
	if err != nil {
		return nil, fmt.Errorf("sqlstore workflow: list transition impacts: %w", err)
	}
	defer rows.Close()
	out := make([]domain.TransitionImpact, 0)
	for rows.Next() {
		impact, err := scanImpact(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlstore workflow: scan transition impact: %w", err)
		}
		out = append(out, impact)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore workflow: list transition impacts: %w", err)
	}
	return out, nil
}

func scanImpact(row rowScanner) (domain.TransitionImpact, error) {
	var transitionID, certificateID string
	var replacementID sql.NullString
	var reissuedAt sql.NullInt64
	if err := row.Scan(&transitionID, &certificateID, &replacementID, &reissuedAt); err != nil {
		return domain.TransitionImpact{}, err
	}
	parsedTransitionID, err := domain.ParseTransitionID(transitionID)
	if err != nil {
		return domain.TransitionImpact{}, fmt.Errorf("invalid stored impact transition id: %w", err)
	}
	parsedCertificateID, err := domain.ParseCertificateID(certificateID)
	if err != nil {
		return domain.TransitionImpact{}, fmt.Errorf("invalid stored impact certificate id: %w", err)
	}
	facts := domain.TransitionImpactFacts{TransitionID: parsedTransitionID, CertificateID: parsedCertificateID}
	if replacementID.Valid {
		facts.ReplacementCertificateID, err = domain.ParseCertificateID(replacementID.String)
		if err != nil {
			return domain.TransitionImpact{}, fmt.Errorf("invalid stored replacement certificate id: %w", err)
		}
	}
	if reissuedAt.Valid {
		facts.ReissuedAt = domain.InstantFromUnixMicro(reissuedAt.Int64)
	}
	return domain.NewTransitionImpact(facts)
}

func (r *TransitionRepository) ListDeploymentConfirmations(ctx context.Context, transitionID domain.TransitionID) ([]domain.DeploymentConfirmation, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if _, err := domain.ParseTransitionID(string(transitionID)); err != nil {
		return nil, fmt.Errorf("sqlstore workflow: validate transition id: %w", err)
	}
	b := r.dialect.NewBuilder()
	query := "SELECT transition_id, certificate_id, target_label, action, confirmed_by, confirmed_at FROM deployment_confirmations WHERE transition_id = " +
		b.Add(string(transitionID)) + " ORDER BY created_at, id"
	rows, err := r.executor.QueryContext(ctx, query, b.Args()...)
	if err != nil {
		return nil, fmt.Errorf("sqlstore workflow: list deployment confirmations: %w", err)
	}
	defer rows.Close()
	out := make([]domain.DeploymentConfirmation, 0)
	for rows.Next() {
		confirmation, err := scanConfirmation(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlstore workflow: scan deployment confirmation: %w", err)
		}
		out = append(out, confirmation)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore workflow: list deployment confirmations: %w", err)
	}
	return out, nil
}

func scanConfirmation(row rowScanner) (domain.DeploymentConfirmation, error) {
	var transitionID, targetLabel, action string
	var certificateID, confirmedBy sql.NullString
	var confirmedAt sql.NullInt64
	if err := row.Scan(&transitionID, &certificateID, &targetLabel, &action, &confirmedBy, &confirmedAt); err != nil {
		return domain.DeploymentConfirmation{}, err
	}
	parsedTransitionID, err := domain.ParseTransitionID(transitionID)
	if err != nil {
		return domain.DeploymentConfirmation{}, fmt.Errorf("invalid stored confirmation transition id: %w", err)
	}
	facts := domain.DeploymentConfirmationFacts{
		TransitionID: parsedTransitionID, TargetLabel: targetLabel, Action: domain.DeploymentAction(action),
	}
	if certificateID.Valid {
		facts.CertificateID, err = domain.ParseCertificateID(certificateID.String)
		if err != nil {
			return domain.DeploymentConfirmation{}, fmt.Errorf("invalid stored confirmation certificate id: %w", err)
		}
	}
	if confirmedBy.Valid {
		facts.ConfirmedBy, err = domain.ParseAccountID(confirmedBy.String)
		if err != nil {
			return domain.DeploymentConfirmation{}, fmt.Errorf("invalid stored confirmation actor: %w", err)
		}
	}
	if confirmedAt.Valid {
		facts.ConfirmedAt = domain.InstantFromUnixMicro(confirmedAt.Int64)
	}
	return domain.NewDeploymentConfirmation(facts)
}
