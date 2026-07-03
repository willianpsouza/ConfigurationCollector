package vendor

func init() { Register(cisco{}) }

// cisco cobre IOS / IOS-XE e a maioria dos NOS estilo IOS (inclui varios
// Datacom DmOS com sintaxe show-based). Shell interativo, paginacao desligada
// com "terminal length 0".
//
// Pressuposto: o usuario ja loga em modo privilegiado (enable). Se o parque
// exigir "enable" + senha separada, isso vira um campo de driver/asset numa
// fase seguinte.
type cisco struct{}

func (cisco) Name() string { return "cisco" }
func (cisco) Mode() Mode   { return ModeShell }
func (cisco) Exit() string { return "exit" }

func (cisco) Setup() []string {
	return []string{"terminal length 0"}
}

func (cisco) Prompts() []string {
	return []string{"#", ">"}
}

func (cisco) Commands() []string {
	return []string{
		"show version",
		"show inventory",
		"show running-config",
		"show ip interface brief",
		"show interfaces description",
		"show interfaces status",
		"show lldp neighbors",
		"show cdp neighbors",
		"show ip bgp summary",
		"show ip ospf neighbor",
	}
}
