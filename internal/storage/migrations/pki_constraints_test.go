package migrations

import (
	"fmt"
	"strings"
	"testing"
)

// Synthetic DER values exercise relational constraints, not certificate parsing.
func testPKIConstraints(t *testing.T, exec, reject func(string, ...any)) {
	t.Helper()
	id := func(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
	for n := 10; n <= 12; n++ {
		exec("INSERT INTO key_materials (id,created_at,spki_sha256,spki_der,algorithm,parameters_json,origin) VALUES (?,1,?,?,'ecdsa_p256','{}','generated')", id(n), fmt.Sprintf("%064x", n), []byte{byte(n)})
	}
	reject("INSERT INTO key_materials (id,created_at,spki_sha256,spki_der,algorithm,parameters_json,origin) VALUES (?,1,?,?,'ecdsa_p256','{}','generated')", id(13), fmt.Sprintf("%064x", 12), []byte{12})
	exec("INSERT INTO authorities (id,created_at,updated_at,version,kind,name,issuance_state) VALUES (?,1,1,0,'root','root','inventory')", id(20))
	exec("INSERT INTO authorities (id,created_at,updated_at,version,kind,name,management_parent_id,issuance_state) VALUES (?,1,1,0,'intermediate','inter',?,'inventory')", id(21), id(20))
	for n := 0; n < 2; n++ {
		exec("INSERT INTO ca_key_generations (id,created_at,authority_id,key_material_id,generation_no) VALUES (?,1,?,?,0)", id(30+n), id(20+n), id(10+n))
	}
	certSQL := "INSERT INTO certificates (id,created_at,der_sha256,der,key_material_id,issuer_ca_key_generation_id,serial_hex,not_before,not_after,subject_json,extensions_json,origin) VALUES (?,1,?,?,?,?,?,1,100,'{}','{}','generated')"
	exec(certSQL, id(40), fmt.Sprintf("%064x", 40), []byte{40}, id(10), id(30), "1")
	exec("INSERT INTO ca_certificates (certificate_id,ca_key_generation_id) VALUES (?,?)", id(40), id(30))
	exec(certSQL, id(41), fmt.Sprintf("%064x", 41), []byte{41}, id(11), id(30), "2")
	exec("INSERT INTO ca_certificates (certificate_id,ca_key_generation_id,issuer_ca_certificate_id) VALUES (?,?,?)", id(41), id(31), id(40))
	// Both leaf certificates deliberately reference the same public key.
	exec(certSQL, id(42), fmt.Sprintf("%064x", 42), []byte{42}, id(12), id(31), "1")
	exec(certSQL, id(43), fmt.Sprintf("%064x", 43), []byte{43}, id(12), id(31), "2")
	reject(certSQL, id(44), fmt.Sprintf("%064x", 44), []byte{44}, id(12), id(31), "2")
	reject(certSQL, id(44), fmt.Sprintf("%064x", 44), []byte{44}, id(12), id(31), "01")
	reject(certSQL, id(44), fmt.Sprintf("%064x", 44), []byte{44}, id(12), id(31), "zz")
	exec("INSERT INTO leaf_series (id,created_at,updated_at,version,name,purpose,management_authority_id,validity_policy_json,rotate_every) VALUES (?,1,1,0,'leaf','distributed',?,'{}',3)", id(50), id(21))
	exec("INSERT INTO leaf_key_generations (id,created_at,series_id,key_material_id,generation_no,renewal_count,prior_history_unknown,custody) VALUES (?,1,?,?,0,0,?,'pending_delivery')", id(51), id(50), id(12), false)
	for n := 42; n <= 43; n++ {
		exec("INSERT INTO leaf_certificates (certificate_id,series_id,leaf_key_generation_id,issuer_ca_certificate_id,operation,renewal_count_at_issue,policy_snapshot_json) VALUES (?,?,?,?,'initial',0,'{}')", id(n), id(50), id(51), id(41))
	}
	exec("UPDATE leaf_series SET current_certificate_id=?,current_key_generation_id=? WHERE id=?", id(42), id(51), id(50))
	exec("INSERT INTO key_deliveries (id,created_at,updated_at,version,leaf_key_generation_id,certificate_id,expires_at,state) VALUES (?,1,1,0,?,?,10,'pending')", id(60), id(51), id(42))
	reject("UPDATE key_deliveries SET state='transferring' WHERE id=?", id(60))
	exec("UPDATE key_deliveries SET state='transferring',consumed_at=2 WHERE id=?", id(60))
	reject("UPDATE leaf_series SET rotate_every=0 WHERE id=?", id(50))
	tokenSQL := "INSERT INTO download_tokens (id,created_at,token_hash,purpose,certificate_id,key_delivery_id,expires_at,created_by) VALUES (?,1,?,?,?,?,10,?)"
	reject(tokenSQL, id(61), strings.Repeat("c", 64), "leaf_public", id(42), id(60), id(1))
	reject(tokenSQL, id(61), strings.Repeat("c", 64), "leaf_private", id(42), nil, id(1))
	// CRL-only history survives without a certificate, including >64-bit serials.
	revokeSQL := "INSERT INTO revocations (id,created_at,updated_at,version,issuer_ca_key_generation_id,serial_hex,revoked_at,reason,source,change_generation) VALUES (?,1,1,0,?,?,1,'keyCompromise','imported',1)"
	exec(revokeSQL, id(70), id(31), "7"+strings.Repeat("f", 39))
	reject(revokeSQL, id(71), id(31), "7"+strings.Repeat("f", 39))
	reject("DELETE FROM ca_key_generations WHERE id=?", id(31))
}
