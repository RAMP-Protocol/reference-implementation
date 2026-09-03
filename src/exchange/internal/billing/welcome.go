package billing

// WelcomeCreditKey derives the idempotency key of the shared welcome-credit
// ledger slot for one agent: "service-welcome:" + billingRef. The Register
// flow's default-credit grant and the operator funding scripts' reserved
// "service-welcome" label both derive their transfer id from this one string,
// so whichever side lands first wins and the other side is a no-op — an agent
// is never double-credited. "service-welcome" is a reserved label that has
// never carried any other derivation; every other funding label keeps the
// amount-bearing staging derivation and therefore stacks deliberately.
//
// This function is the single Go owner of the derivation. The shell copy in
// deploy/terraform/scripts/fund-staging-agent.sh must stay byte-identical;
// the pinned-vector test in welcome_test.go breaks when either the prefix or
// the transfer-id derivation drifts.
func WelcomeCreditKey(billingRef string) string {
	return "service-welcome:" + billingRef
}
