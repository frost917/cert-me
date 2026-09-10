package porttest

import (
	"sort"

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
