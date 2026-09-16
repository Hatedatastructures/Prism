package previewclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type clientConfig struct {
	Proxies     []proxyConfig `yaml:"proxies"`
	ProxyGroups []proxyGroup  `yaml:"proxy-groups"`
	Rules       []string      `yaml:"rules"`
}

type proxyConfig struct {
	Name          string         `yaml:"name"`
	Type          string         `yaml:"type"`
	UDP           bool           `yaml:"udp"`
	TLS           bool           `yaml:"tls"`
	SNI           string         `yaml:"sni"`
	ServerName    string         `yaml:"servername"`
	Plugin        string         `yaml:"plugin"`
	PluginOptions map[string]any `yaml:"plugin-opts"`
	ShadowTLS     map[string]any `yaml:"shadow-tls-opts"`
	Restls        map[string]any `yaml:"restls-opts"`
	Reality       map[string]any `yaml:"reality-opts"`
	Smux          *smuxConfig    `yaml:"smux"`
}

type smuxConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Protocol       string `yaml:"protocol"`
	OnlyTCP        bool   `yaml:"only-tcp"`
	MaxConnections *int   `yaml:"max-connections"`
	MaxConn        *int   `yaml:"max-conn"`
	MaxStreams     *int   `yaml:"max-streams"`
	MinStreams     *int   `yaml:"min-streams"`
}

type proxyGroup struct {
	Name    string   `yaml:"name"`
	Proxies []string `yaml:"proxies"`
}

type serverConfig struct {
	Protocols []struct {
		ID      string `yaml:"Id"`
		Name    string `yaml:"Name"`
		Builtin string `yaml:"Builtin"`
	} `yaml:"Protocols"`
	Carriers []struct {
		ID      string `yaml:"Id"`
		Builtin string `yaml:"Builtin"`
	} `yaml:"Carriers"`
	ProtocolBindings []struct {
		ProtocolID string   `yaml:"ProtocolId"`
		CarrierID  string   `yaml:"CarrierId"`
		TCPEnabled bool     `yaml:"TcpEnabled"`
		UDPEnabled bool     `yaml:"UdpEnabled"`
		MuxModes   []string `yaml:"MuxModes"`
	} `yaml:"ProtocolBindings"`
}

func readYAML[T any](t *testing.T, path string) T {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var value T
	if err := yaml.Unmarshal(data, &value); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return value
}

func repositoryRoot() string {
	return filepath.Clean(filepath.Join("..", "..", ".."))
}

func findGroup(t *testing.T, config clientConfig, name string) proxyGroup {
	t.Helper()
	for _, group := range config.ProxyGroups {
		if group.Name == name {
			return group
		}
	}
	t.Fatalf("proxy group %q is missing", name)
	return proxyGroup{}
}

func indexProxies(t *testing.T, proxies []proxyConfig) map[string]proxyConfig {
	t.Helper()
	indexed := make(map[string]proxyConfig, len(proxies))
	for _, proxy := range proxies {
		if proxy.Name == "" {
			t.Fatal("proxy name is required")
		}
		if _, exists := indexed[proxy.Name]; exists {
			t.Fatalf("duplicate proxy name %q", proxy.Name)
		}
		indexed[proxy.Name] = proxy
	}
	return indexed
}

func TestProxyGroupsMatchServerTCPBindings(t *testing.T) {
	root := repositoryRoot()
	client := readYAML[clientConfig](t, filepath.Join(root, "PrismPreviewClient.yaml"))
	server := readYAML[serverConfig](t, filepath.Join(root, "PreviewConfigurationLan.json"))
	proxies := indexProxies(t, client.Proxies)
	protocolNames := make(map[string]string, len(server.Protocols))
	for _, protocol := range server.Protocols {
		protocolNames[protocol.ID] = strings.ToLower(protocol.Name)
	}

	clientName := map[string]string{
		"http":            "Http",
		"socks5":          "SOCKS5 TCP Cert",
		"vless":           "VLESS TCP",
		"trojan":          "Trojan TCP",
		"vmess":           "VMess TCP",
		"shadowsocks2022": "SS2022 TCP",
	}
	expected := map[string]bool{"DIRECT": true}
	for _, binding := range server.ProtocolBindings {
		if !binding.TCPEnabled || binding.CarrierID != "" || len(binding.MuxModes) != 0 {
			continue
		}
		protocol := protocolNames[binding.ProtocolID]
		name, supported := clientName[protocol]
		if !supported {
			t.Fatalf("no bare-TCP client node mapping for server protocol %q", protocol)
		}
		if _, exists := proxies[name]; !exists {
			t.Fatalf("server TCP protocol %q maps to missing client node %q", protocol, name)
		}
		expected[name] = true
	}

	active := findGroup(t, client, "PrismPreview-Active")
	actual := make(map[string]bool, len(active.Proxies))
	for _, name := range active.Proxies {
		if name != "DIRECT" {
			if _, exists := proxies[name]; !exists {
				t.Fatalf("active group references missing proxy %q", name)
			}
			actual[name] = true
		}
	}
	for name := range expected {
		if name != "DIRECT" && !actual[name] {
			t.Errorf("server-enabled bare TCP node %q is not in active group", name)
		}
	}
	for name := range actual {
		if !expected[name] {
			t.Errorf("active node %q is not enabled by the server TCP binding snapshot", name)
		}
	}

	pending := findGroup(t, client, "PrismPreview-Pending")
	for _, name := range pending.Proxies {
		if _, exists := proxies[name]; !exists {
			t.Errorf("pending group references missing proxy %q", name)
		}
		if actual[name] {
			t.Errorf("proxy %q is listed in both active and pending groups", name)
		}
	}
}

func TestUDPAndMuxNodesHaveConsistentDatagramSemantics(t *testing.T) {
	root := repositoryRoot()
	config := readYAML[clientConfig](t, filepath.Join(root, "PrismPreviewClient.yaml"))
	for _, proxy := range config.Proxies {
		nameHasUDP := strings.Contains(strings.ToUpper(proxy.Name), "UDP")
		if nameHasUDP && !proxy.UDP {
			t.Errorf("UDP node %q must set udp: true", proxy.Name)
		}
		if nameHasUDP && proxy.Smux != nil && proxy.Smux.Enabled && !proxy.Smux.OnlyTCP {
			t.Errorf("UDP node %q must leave sing-mux on TCP only", proxy.Name)
		}
		if proxy.Smux != nil {
			if proxy.Smux.MaxConn != nil {
				t.Errorf("proxy %q uses obsolete smux key max-conn; use max-connections", proxy.Name)
			}
			if proxy.Smux.MaxConnections != nil &&
				(proxy.Smux.MaxStreams != nil || proxy.Smux.MinStreams != nil) {
				t.Errorf("proxy %q combines mutually exclusive smux max-connections and stream limits", proxy.Name)
			}
		}
		if proxy.Type == "hysteria2" || proxy.Type == "tuic" {
			if !proxy.UDP {
				t.Errorf("QUIC proxy %q must explicitly allow UDP", proxy.Name)
			}
			if strings.Contains(strings.ToUpper(proxy.Name), "TCP") {
				t.Errorf("QUIC proxy %q is mislabeled as TCP", proxy.Name)
			}
		}
	}
}

func TestTrojanCarrierFieldsUseMihomoTLSOptions(t *testing.T) {
	root := repositoryRoot()
	config := readYAML[clientConfig](t, filepath.Join(root, "PrismPreviewClient.yaml"))
	for _, proxy := range config.Proxies {
		if proxy.Type != "trojan" {
			continue
		}
		if !proxy.TLS {
			t.Errorf("Trojan proxy %q must set tls: true", proxy.Name)
		}
		if proxy.Plugin == "shadow-tls" || proxy.Plugin == "restls" {
			t.Errorf("Trojan proxy %q uses a Shadowsocks plugin field", proxy.Name)
		}
		if proxy.ShadowTLS != nil || proxy.Restls != nil || proxy.Reality != nil {
			if proxy.SNI == "" && proxy.ServerName == "" {
				t.Errorf("Trojan carrier proxy %q must set sni/servername", proxy.Name)
			}
		}
	}
}

func TestTLSCarrierNodesEnableTLSAndSetServerName(t *testing.T) {
	root := repositoryRoot()
	config := readYAML[clientConfig](t, filepath.Join(root, "PrismPreviewClient.yaml"))
	proxies := indexProxies(t, config.Proxies)
	tlsNodes := []string{
		"HTTP Native TLS", "SOCKS5 Native TLS TCP", "VLESS Native TLS TCP", "Trojan Native TLS TCP",
		"VLESS Reality TCP", "Trojan Reality TCP", "VMess Reality TCP",
		"VLESS ShadowTLS TCP", "Trojan ShadowTLS TCP", "AnyTLS ShadowTLS TCP",
		"VLESS Restls TLS13 TCP", "Trojan Restls TLS13 TCP", "AnyTLS Restls TLS13 TCP",
	}
	for _, name := range tlsNodes {
		proxy, exists := proxies[name]
		if !exists {
			continue
		}
		if !proxy.TLS {
			t.Errorf("TLS carrier proxy %q must set tls: true", name)
		}
		if proxy.SNI == "" && proxy.ServerName == "" {
			t.Errorf("TLS carrier proxy %q must set sni/servername", name)
		}
	}
}

func TestAnyTLSRealityCombinationIsAbsent(t *testing.T) {
	root := repositoryRoot()
	config := readYAML[clientConfig](t, filepath.Join(root, "PrismPreviewClient.yaml"))
	for _, proxy := range config.Proxies {
		if proxy.Type == "anytls" && proxy.Reality != nil {
			t.Errorf("Mihomo does not support AnyTLS+Reality (%q)", proxy.Name)
		}
	}
}

func TestClientProxyMatrixIncludesRequiredCarrierAndDatagramCases(t *testing.T) {
	root := repositoryRoot()
	config := readYAML[clientConfig](t, filepath.Join(root, "PrismPreviewClient.yaml"))
	proxies := indexProxies(t, config.Proxies)
	want := []string{
		"HTTP Native TLS", "SOCKS5 Native TLS TCP", "VLESS Native TLS TCP", "Trojan Native TLS TCP",
		"VLESS Reality TCP", "Trojan Reality TCP", "VMess Reality TCP",
		"SS2022 ShadowTLS TCP", "VLESS ShadowTLS TCP", "Trojan ShadowTLS TCP", "AnyTLS ShadowTLS TCP",
		"SS2022 Restls TLS13 TCP", "VLESS Restls TLS13 TCP", "Trojan Restls TLS13 TCP", "AnyTLS Restls TLS13 TCP",
		"AnyTLS TCP", "AnyTLS UDP", "SOCKS5 UDP Cert", "VLESS UDP", "Trojan UDP",
		"VMess UDP", "SS2022 UDP", "Hysteria2 QUIC", "TUIC v5 QUIC",
	}
	for _, name := range want {
		if _, exists := proxies[name]; !exists {
			t.Errorf("required pending client matrix node %q is missing", name)
		}
	}

	active := findGroup(t, config, "PrismPreview-Active")
	activeSet := make(map[string]bool, len(active.Proxies))
	for _, name := range active.Proxies {
		activeSet[name] = true
	}
	for _, name := range want {
		if activeSet[name] {
			t.Errorf("unverified matrix node %q must not be marked active", name)
		}
	}
}

func TestProxyGroupsAreCompleteAndDisjoint(t *testing.T) {
	root := repositoryRoot()
	config := readYAML[clientConfig](t, filepath.Join(root, "PrismPreviewClient.yaml"))
	proxies := indexProxies(t, config.Proxies)
	active := findGroup(t, config, "PrismPreview-Active")
	pending := findGroup(t, config, "PrismPreview-Pending")
	matrix := findGroup(t, config, "PrismPreview-ProtocolMatrix")
	activeSet := make(map[string]bool, len(active.Proxies))
	statusSet := make(map[string]bool, len(active.Proxies)+len(pending.Proxies))
	for _, name := range active.Proxies {
		if statusSet[name] {
			t.Errorf("duplicate active proxy group entry %q", name)
		}
		statusSet[name] = true
		activeSet[name] = true
	}
	for _, name := range pending.Proxies {
		if statusSet[name] {
			t.Errorf("proxy %q is duplicated across active/pending", name)
		}
		statusSet[name] = true
	}
	for name := range proxies {
		if !statusSet[name] {
			t.Errorf("proxy %q is missing from active/pending status groups", name)
		}
	}
	for name := range statusSet {
		if name != "DIRECT" {
			if _, exists := proxies[name]; !exists {
				t.Errorf("active/pending references unknown proxy %q", name)
			}
		}
	}
	matrixSet := make(map[string]bool, len(matrix.Proxies))
	for _, name := range matrix.Proxies {
		if matrixSet[name] {
			t.Errorf("duplicate protocol matrix entry %q", name)
		}
		matrixSet[name] = true
		if _, exists := proxies[name]; !exists {
			t.Errorf("protocol matrix references unknown proxy %q", name)
		}
	}
	for name := range proxies {
		if !matrixSet[name] {
			t.Errorf("proxy %q is missing from the exhaustive protocol matrix", name)
		}
		if activeSet[name] && statusSet[name] == false {
			t.Errorf("active proxy %q has no status membership", name)
		}
	}
}
