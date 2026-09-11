package porttest

import (
	"sort"

	"cert-me/internal/app/contract"
	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

// cloneBytes copies a []byte so the stored copy and the caller's copy never
// alias. domain.* value types already do this themselves behind private
// fields (see state.go's package doc); this is only needed for the
// port-level structs below that expose a plain public []byte/map field.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func cloneStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneAuthorityIDs(ids []domain.AuthorityID) []domain.AuthorityID {
	if ids == nil {
		return nil
	}
	out := make([]domain.AuthorityID, len(ids))
	copy(out, ids)
	return out
}

// cloneCRLDocument copies document.DER, the one exported byte slice on this
// port-level projection type.
func cloneCRLDocument(d port.CRLDocument) port.CRLDocument {
	d.DER = cloneBytes(d.DER)
	return d
}

// cloneJob copies job.Payload.
func cloneJob(j port.Job) port.Job {
	j.Payload = cloneBytes(j.Payload)
	return j
}

// cloneRevision copies revision's two JSON snapshots.
func cloneRevision(r port.RevocationRevision) port.RevocationRevision {
	r.PreviousValuesJSON = cloneBytes(r.PreviousValuesJSON)
	r.NewValuesJSON = cloneBytes(r.NewValuesJSON)
	return r
}

// cloneSettings copies settings.SettingsJSON.
func cloneSettings(s port.Settings) port.Settings {
	s.SettingsJSON = cloneBytes(s.SettingsJSON)
	return s
}

// cloneRequestResult copies result.ResultJSON.
func cloneRequestResult(r port.OperationRequestResult) port.OperationRequestResult {
	r.ResultJSON = cloneBytes(r.ResultJSON)
	return r
}

// cloneAuditEvent copies event.Details.Fields, the one mutable collection on
// an otherwise flat, string-typed struct.
func cloneAuditEvent(e port.AuditEvent) port.AuditEvent {
	e.Details.Fields = cloneStringMap(e.Details.Fields)
	return e
}

// cloneManifestFiles copies a PublicImportManifest.Files slice. Each element
// (contract.ImportManifestFileFacts) is a flat struct of value types
// (string/domain.Fingerprint/domain.CertificateID), so copying the slice
// header's backing array is enough to stop the caller's slice and the stored
// one aliasing the same elements.
func cloneManifestFiles(files []contract.ImportManifestFileFacts) []contract.ImportManifestFileFacts {
	if files == nil {
		return nil
	}
	out := make([]contract.ImportManifestFileFacts, len(files))
	copy(out, files)
	return out
}

// cloneManifest copies manifest.Files, the one exported slice on
// contract.PublicImportManifest.
func cloneManifest(m contract.PublicImportManifest) contract.PublicImportManifest {
	m.Files = cloneManifestFiles(m.Files)
	return m
}

// cloneInstantPtr copies a *domain.Instant so the stored copy and the
// caller's copy never share the pointee -- domain.Instant itself is a flat
// value type, but the pointer wrapping it (ImportResultView.CommittedAt) is
// exactly the kind of "nested pointer" the reviewer's finding calls out.
func cloneInstantPtr(t *domain.Instant) *domain.Instant {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

// cloneCertificateIDPtr copies a *domain.CertificateID
// (ImportItemView.ExistingID), the other nested pointer ImportResultView
// carries transitively through its Items.
func cloneCertificateIDPtr(id *domain.CertificateID) *domain.CertificateID {
	if id == nil {
		return nil
	}
	v := *id
	return &v
}

// cloneCertificateIDs copies a []domain.CertificateID
// (ImportResultView.CertificateIDs).
func cloneCertificateIDs(ids []domain.CertificateID) []domain.CertificateID {
	if ids == nil {
		return nil
	}
	out := make([]domain.CertificateID, len(ids))
	copy(out, ids)
	return out
}

// cloneImportItems copies an []ImportItemView, including each item's
// ExistingID pointer.
func cloneImportItems(items []contract.ImportItemView) []contract.ImportItemView {
	if items == nil {
		return nil
	}
	out := make([]contract.ImportItemView, len(items))
	for i, it := range items {
		it.ExistingID = cloneCertificateIDPtr(it.ExistingID)
		out[i] = it
	}
	return out
}

// cloneImportResult copies every mutable field of ImportResultView:
// CommittedAt's pointee, Items (and each item's ExistingID pointee),
// CertificateIDs and AuthorityIDs.
func cloneImportResult(r contract.ImportResultView) contract.ImportResultView {
	r.CommittedAt = cloneInstantPtr(r.CommittedAt)
	r.Items = cloneImportItems(r.Items)
	r.CertificateIDs = cloneCertificateIDs(r.CertificateIDs)
	r.AuthorityIDs = cloneAuthorityIDs(r.AuthorityIDs)
	return r
}

// cloneImportBatch copies ImportBatch's two mutable fields, Manifest and
// Result, so a stored batch and whatever Insert/GetBatch hands a caller
// never alias the same Files/Items/CertificateIDs/AuthorityIDs backing
// arrays or CommittedAt/ExistingID pointees. This is the fix for the
// reviewer's [P2] finding: without it, a batch obtained from a later
// GetBatch could mutate Manifest.Files[0] and, even though the write
// callback then rolls back, the mutation would already have reached the
// map's shared struct value.
func cloneImportBatch(b port.ImportBatch) port.ImportBatch {
	b.Manifest = cloneManifest(b.Manifest)
	b.Result = cloneImportResult(b.Result)
	return b
}

// cloneCRLSHA256Hex copies TakeoverEvidence.CRLSHA256Hex, the slice field
// the reviewer named directly.
func cloneCRLSHA256Hex(hexes []string) []string {
	if hexes == nil {
		return nil
	}
	out := make([]string, len(hexes))
	copy(out, hexes)
	return out
}

// cloneTakeoverEvidence copies evidence.CRLSHA256Hex.
func cloneTakeoverEvidence(e contract.TakeoverEvidence) contract.TakeoverEvidence {
	e.CRLSHA256Hex = cloneCRLSHA256Hex(e.CRLSHA256Hex)
	return e
}

// cloneTakeover copies Takeover's one mutable field, Evidence.
// HistoryAssertion/PreviousMaxNumberHex/ConfirmedBy/ConfirmedAt/Version are
// all flat value types with no exported slice/map/pointer.
func cloneTakeover(t port.Takeover) port.Takeover {
	t.Evidence = cloneTakeoverEvidence(t.Evidence)
	return t
}

// sortSecretKeys gives ListEncrypted a deterministic order. Rotate walks the
// whole set in one transaction, so a test asserting that every ciphertext
// moved generation needs a stable sequence to compare against.
func sortSecretKeys(keys []secretKey) {
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].keyID != keys[j].keyID {
			return keys[i].keyID < keys[j].keyID
		}
		return keys[i].purpose < keys[j].purpose
	})
}

// cloneLeafCertificateRecord copies PolicySnapshotJSON, the one exported
// byte slice on this port-level projection type.
func cloneLeafCertificateRecord(r port.LeafCertificateRecord) port.LeafCertificateRecord {
	r.PolicySnapshotJSON = cloneBytes(r.PolicySnapshotJSON)
	return r
}
