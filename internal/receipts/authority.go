package receipts

import "github.com/ckodex-labs/ckodex-oskal/core/assurance"

// SigningAuthority returns the configured authority claim. It does not
// authenticate identity or establish trust in the manager's public key.
func (m *ReceiptManager) SigningAuthority() assurance.AuthorityRef {
	if m == nil {
		return assurance.AuthorityRef{}
	}
	return m.evaluator
}
