package porttest

import (
	"context"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

type crlRepo struct{ s *state }

var _ port.CRLRepository = crlRepo{}

func (r crlRepo) GetStateForUpdate(_ context.Context, caKeyGenerationID domain.CAKeyGenerationID) (domain.CRLState, error) {
	st, ok := r.s.crlStates[caKeyGenerationID]
	if !ok {
		return domain.CRLState{}, port.ErrNotFound
	}
	return st, nil
}

// SaveState is where CRL number and generation monotonicity is ultimately
// persisted. The store only enforces the optimistic lock; the no-going-back
// rule itself lives in domain.CRLState, so a service cannot bypass it by
// assembling a fresh value here.
func (r crlRepo) SaveState(_ context.Context, st domain.CRLState, expectedVersion domain.Version) error {
	existing, ok := r.s.crlStates[st.CAKeyGenerationID()]
	if !ok {
		if expectedVersion != 0 {
			return port.ErrNotFound
		}
		r.s.crlStates[st.CAKeyGenerationID()] = st
		return nil
	}
	if existing.Version() != expectedVersion {
		return ErrVersionConflict
	}
	r.s.crlStates[st.CAKeyGenerationID()] = st
	return nil
}

// InsertDocument stores a signed CRL original. Documents are immutable once
// written -- MarkPublished on the state is what decides which one is current
// -- so a repeated id is a duplicate rather than an update.
func (r crlRepo) InsertDocument(_ context.Context, document port.CRLDocument) error {
	if _, ok := r.s.crlDocuments[document.ID]; ok {
		return ErrDuplicate
	}
	derKey := crlDocumentUniqueKey(document)
	if derKey != "" {
		if _, ok := r.s.crlDocumentsByDER[derKey]; ok {
			return ErrDuplicate
		}
	}
	r.s.crlDocuments[document.ID] = cloneCRLDocument(document)
	if derKey != "" {
		r.s.crlDocumentsByDER[derKey] = document.ID
	}
	return nil
}

// crlDocumentUniqueKey mirrors crl_documents.der_sha256 UQ. Normal service
// calls provide the parser's DER fingerprint; deriving it for a zero value
// keeps the in-memory double honest for hand-built fixtures as well.
func crlDocumentUniqueKey(document port.CRLDocument) string {
	if !document.DERSHA256.IsZero() {
		return document.DERSHA256.Hex()
	}
	if len(document.DER) == 0 {
		return ""
	}
	return domain.NewFingerprint(document.DER).Hex()
}

func (r crlRepo) GetDocument(_ context.Context, id domain.CRLDocumentID) (port.CRLDocument, error) {
	doc, ok := r.s.crlDocuments[id]
	if !ok {
		return port.CRLDocument{}, port.ErrNotFound
	}
	return cloneCRLDocument(doc), nil
}
