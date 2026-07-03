package vendor

func init() { Register(mikrotik{}) }

// mikrotik cobre RouterOS. Usa ModeExec: cada comando roda como exec SSH
// separado, o que evita a paginacao interativa ("-- more --") do terminal do
// RouterOS. O "/export" traz a config completa (sem show-defaults para ficar
// enxuto; troque por "/export verbose" se quiser tudo).
type mikrotik struct{}

func (mikrotik) Name() string { return "mikrotik" }
func (mikrotik) Mode() Mode   { return ModeExec }
func (mikrotik) Exit() string { return "/quit" }

// Setup/Prompts nao se aplicam ao ModeExec, mas mantemos prompts uteis caso o
// transporte caia para shell (ex.: Telnet).
func (mikrotik) Setup() []string   { return nil }
func (mikrotik) Prompts() []string { return []string{"] > ", "] <"} }

func (mikrotik) Commands() []string {
	return []string{
		"/system identity print",
		"/system resource print",
		"/system routerboard print",
		"/system package print",
		"/interface print detail",
		"/ip address print detail",
		"/export compact",
	}
}
