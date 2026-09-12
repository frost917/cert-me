package porttest

import (
	"context"
	"sort"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

type transitionRepo struct{ s *state }

var _ port.TransitionRepository = transitionRepo{}

func (r transitionRepo) GetForUpdate(_ context.Context, transitionID domain.TransitionID) (domain.Transition, error) {
	t, ok := r.s.transitions[transitionID]
	if !ok {
		return domain.Transition{}, port.ErrNotFound
	}
	return t, nil
}

func (r transitionRepo) Insert(_ context.Context, transition domain.Transition) error {
	if _, ok := r.s.transitions[transition.ID()]; ok {
		return ErrDuplicate
	}
	r.s.transitions[transition.ID()] = transition
	return nil
}

func (r transitionRepo) Save(_ context.Context, transition domain.Transition, expectedVersion domain.Version) error {
	existing, ok := r.s.transitions[transition.ID()]
	if !ok {
		return port.ErrNotFound
	}
	if existing.Version() != expectedVersion {
		return ErrVersionConflict
	}
	r.s.transitions[transition.ID()] = transition
	return nil
}

func (r transitionRepo) AddImpact(_ context.Context, impact domain.TransitionImpact) error {
	key := impactKey{transitionID: impact.TransitionID(), certificateID: impact.CertificateID()}
	if _, ok := r.s.impacts[key]; ok {
		return ErrDuplicate
	}
	r.s.impacts[key] = impact
	return nil
}

// LinkReplacement records the reissued certificate against an existing
// impact row. It is a distinct method from AddImpact so a replacement can
// never quietly create an impact that was never part of the transition's
// original scope.
func (r transitionRepo) LinkReplacement(_ context.Context, impact domain.TransitionImpact) error {
	key := impactKey{transitionID: impact.TransitionID(), certificateID: impact.CertificateID()}
	if _, ok := r.s.impacts[key]; !ok {
		return port.ErrNotFound
	}
	r.s.impacts[key] = impact
	return nil
}

// AddDeploymentConfirmation appends an operator's manual confirmation. These
// are preserved rather than replaced: the audit value of a transition is the
// sequence of confirmations, not just the latest one.
func (r transitionRepo) AddDeploymentConfirmation(_ context.Context, confirmation domain.DeploymentConfirmation) error {
	r.s.deploymentConfirmations = append(r.s.deploymentConfirmations, confirmation)
	return nil
}

func (r transitionRepo) ListImpacts(_ context.Context, transitionID domain.TransitionID) ([]domain.TransitionImpact, error) {
	out := make([]domain.TransitionImpact, 0)
	for key, impact := range r.s.impacts {
		if key.transitionID == transitionID {
			out = append(out, impact)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CertificateID() < out[j].CertificateID() })
	return out, nil
}

// DeploymentConfirmations exposes the confirmation trail to tests.
func (s *Store) DeploymentConfirmations() []domain.DeploymentConfirmation {
	snapshot := s.root.Load()
	out := make([]domain.DeploymentConfirmation, len(snapshot.deploymentConfirmations))
	copy(out, snapshot.deploymentConfirmations)
	return out
}

// ListDeploymentConfirmations returns transitionID's confirmations in the
// order they were added, which is the order a real append-only table would
// read them back in.
func (r transitionRepo) ListDeploymentConfirmations(_ context.Context, transitionID domain.TransitionID) ([]domain.DeploymentConfirmation, error) {
	var out []domain.DeploymentConfirmation
	for _, c := range r.s.deploymentConfirmations {
		if c.TransitionID() == transitionID {
			out = append(out, c)
		}
	}
	return out, nil
}
