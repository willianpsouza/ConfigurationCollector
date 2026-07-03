package vendor

func init() { Register(huawei{}) }

// huawei cobre NE8000 / CE / S-series (VRP). Shell interativo, paginacao
// desligada por sessao com "screen-length 0 temporary".
type huawei struct{}

func (huawei) Name() string { return "huawei" }
func (huawei) Mode() Mode   { return ModeShell }
func (huawei) Exit() string { return "quit" }

func (huawei) Setup() []string {
	return []string{"screen-length 0 temporary"}
}

func (huawei) Prompts() []string {
	return []string{"<", ">", "]"}
}

func (huawei) Commands() []string {
	return []string{
		"display version",
		"display device",
		"display license",
		"display current-configuration",
		"display interface brief",
		"display interface description",
		"display interface transceiver",
		"display lldp neighbor brief",
		"display eth-trunk brief",
		"display bgp peer",
		"display ospf peer",
		"display isis peer",
		// Estado de transporte MPLS (read-only) para correlacao da malha.
		"display mpls ldp session",
		"display mpls ldp interface",
		"display mpls l2vc brief",
		"display mpls te tunnel-interface",
		"display mpls lsp",
		"display vsi",
		"display vpls connection",
	}
}
