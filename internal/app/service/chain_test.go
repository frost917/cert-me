package service

import (
	"bytes"
	"context"
	"testing"
	"time"

	"cert-me/internal/app/port"
	"cert-me/internal/domain"
)

func TestStoredCAChainEntryPoints(t *testing.T) {
	for _, entry := range []string{"delivery", "import"} {
		for _, fault := range []string{"", "cycle", "missing_record"} {
			t.Run(entry+"/"+fault, func(t *testing.T) {
				fx := seedPrivateFixture(t, distTestNow().Add(domain.NewDuration(time.Hour)), domain.DeliveryStatePending)
				ctx := context.Background()
				if err := fx.store.Read(ctx, func(tx port.TxStores) error {
					leaf, err := tx.PKI().GetLeafCertificateRecord(ctx, fx.certID)
					if err != nil {
						t.Fatal(err)
					}
					root, err := tx.PKI().GetCertificate(ctx, leaf.IssuerCACertificateID)
					if err != nil {
						t.Fatal(err)
					}
					wrapped := chainFaultTx{TxStores: tx, fault: fault}
					var chain [][]byte
					if entry == "delivery" {
						chain, err = buildChainDER(ctx, wrapped, fx.certID)
					} else {
						chain, err = existingIssuerChainDER(ctx, wrapped, root.ID())
					}
					if fault == "" {
						if err != nil || len(chain) != 1 || !bytes.Equal(chain[0], root.DER()) {
							t.Fatalf("chain = %x, %v; want the issuer root only", chain, err)
						}
					} else {
						want := "chain_cycle"
						if entry == "import" {
							want = "import_chain_cycle"
						}
						if fault == "missing_record" {
							want = "chain_ca_record_missing"
							if entry == "import" {
								want = "import_chain_record_read_failed"
							}
						}
						if err == nil || len(chain) != 0 {
							t.Fatalf("corrupt chain returned %x, %v", chain, err)
						}
						if coded, ok := err.(interface{ Code() string }); !ok || coded.Code() != want {
							t.Fatalf("error = %v, want code %s", err, want)
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

type chainFaultTx struct {
	port.TxStores
	fault string
}

func (t chainFaultTx) PKI() port.PKIRepository {
	return chainFaultPKI{PKIRepository: t.TxStores.PKI(), fault: t.fault}
}

type chainFaultPKI struct {
	port.PKIRepository
	fault string
}

func (r chainFaultPKI) GetCACertificateRecord(ctx context.Context, id domain.CertificateID) (port.CACertificateRecord, error) {
	if r.fault == "missing_record" {
		return port.CACertificateRecord{}, port.ErrNotFound
	}
	record, err := r.PKIRepository.GetCACertificateRecord(ctx, id)
	if r.fault == "cycle" {
		record.IssuerCACertificateID = id
	}
	return record, err
}
