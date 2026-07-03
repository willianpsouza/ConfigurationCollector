package vendor

func init() { Register(zte{}) }

// zte cobre a linha 5960X e similares (ZXR10). Shell interativo, paginacao
// desligada com "terminal length 0".
type zte struct{}

func (zte) Name() string { return "zte" }
func (zte) Mode() Mode   { return ModeShell }
func (zte) Exit() string { return "exit" }

func (zte) Setup() []string {
	return []string{"terminal length 0"}
}

func (zte) Prompts() []string {
	return []string{"#", ">"}
}

func (zte) Commands() []string {
	return []string{
		"show version",
		"show license",
		"show hardware",
		"show running-config",
		"show interface brief",
		"show interface description",
		"show lldp neighbor",
		"show opticalinfo brief",
		"show temperature detail",
		"show interface summary",
		"show ip bgp summary",
		"show ip ospf neighbor",
		"show isis topology",
	}
}
