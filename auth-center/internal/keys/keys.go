package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

//go:embed forbidden/*.json
var forbiddenFS embed.FS

const (
	RoleActive = "active"
	RoleNext   = "next"
	AlgRS256   = "RS256"
	AlgES256   = "ES256"
)

// Input 是从进程配置解析出的一把密钥。Kid 为空时从 PEM 首行 `# kid: ...` 读取。
type Input struct {
	Kid     string
	Alg     string
	PEMFile string
	Role    string
}

// Manager 持有当前签名密钥和可选的下一把密钥，并已确认它们不是 conformance 测试密钥。
type Manager struct {
	active    jose.JSONWebKey
	next      *jose.JSONWebKey
	forbidden []jose.JSONWebKey
}

// ConformanceKeyError 表示签名密钥的 kid 或公钥与 conformance/keys 中的测试密钥相同。
type ConformanceKeyError struct {
	Kid    string
	Reason string
}

func (e *ConformanceKeyError) Error() string {
	return fmt.Sprintf("signing key matches a conformance test key (%s, kid %q); refusing to start", e.Reason, e.Kid)
}

// LoadFiles 读取 PEM，校验算法，并拒绝测试密钥。
func LoadFiles(inputs []Input) (*Manager, error) {
	forbidden, err := loadForbidden()
	if err != nil {
		return nil, err
	}
	var active *jose.JSONWebKey
	var next *jose.JSONWebKey
	for _, in := range inputs {
		jwk, err := loadFile(in)
		if err != nil {
			return nil, err
		}
		if err := rejectConformance(jwk, forbidden); err != nil {
			return nil, err
		}
		switch in.Role {
		case RoleActive:
			cp := jwk
			active = &cp
		case RoleNext:
			cp := jwk
			next = &cp
		default:
			return nil, fmt.Errorf("unknown key role %q", in.Role)
		}
	}
	if active == nil {
		return nil, errors.New("active signing key is required")
	}
	if next != nil && next.KeyID == active.KeyID {
		return nil, errors.New("active and next signing keys have the same kid")
	}
	return &Manager{active: *active, next: next, forbidden: forbidden}, nil
}

// Check 对一把已经解析的私钥再跑一次测试密钥拒绝。测试用来覆盖「只改 kid」和「只改公钥材料」两种情况。
func Check(jwk jose.JSONWebKey) error {
	forbidden, err := loadForbidden()
	if err != nil {
		return err
	}
	return rejectConformance(jwk, forbidden)
}

func loadFile(in Input) (jose.JSONWebKey, error) {
	raw, err := os.ReadFile(in.PEMFile)
	if err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("read signing key: %w", err)
	}
	kid := in.Kid
	fileKid := kidFromPEM(raw)
	if kid == "" {
		kid = fileKid
	} else if fileKid != "" && fileKid != kid {
		return jose.JSONWebKey{}, fmt.Errorf("kid %q does not match pem comment %q", kid, fileKid)
	}
	if kid == "" {
		return jose.JSONWebKey{}, errors.New("signing key kid is required")
	}
	return ParsePrivatePEM(raw, kid, in.Alg)
}

// ParsePrivatePEM 解析 PKCS#8 或 PKCS#1 / SEC1 私钥。只接受 RS256 的 RSA，以及 ES256 的 P-256。
func ParsePrivatePEM(raw []byte, kid, alg string) (jose.JSONWebKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return jose.JSONWebKey{}, errors.New("signing key pem is invalid")
	}
	key, err := parsePrivate(block)
	if err != nil {
		return jose.JSONWebKey{}, err
	}
	if err := checkAlg(key, alg); err != nil {
		return jose.JSONWebKey{}, err
	}
	if !privateKey(key) {
		return jose.JSONWebKey{}, errors.New("signing key must be a private key")
	}
	return jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: alg, Use: "sig"}, nil
}

func parsePrivate(block *pem.Block) (any, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported pem type %q", block.Type)
	}
}

func checkAlg(key any, alg string) error {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if alg != AlgRS256 {
			return fmt.Errorf("RSA key only allows RS256")
		}
		if k.N.BitLen() < 2048 {
			return fmt.Errorf("RSA key must be at least 2048 bits")
		}
	case *ecdsa.PrivateKey:
		if alg != AlgES256 {
			return fmt.Errorf("EC key only allows ES256")
		}
		if k.Curve != elliptic.P256() {
			return fmt.Errorf("ES256 requires P-256")
		}
	default:
		return fmt.Errorf("unsupported signing key type %T", key)
	}
	return nil
}

func privateKey(key any) bool {
	switch key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		return true
	default:
		return false
	}
}

func kidFromPEM(raw []byte) string {
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		const prefix = "# kid:"
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
		if strings.HasPrefix(line, "-----BEGIN") {
			break
		}
	}
	return ""
}

// ActiveAlgorithm 是当前签名密钥的算法，RS256 或 ES256。
func (m *Manager) ActiveAlgorithm() string {
	return m.active.Algorithm
}

// Sign 用 active 私钥签 JWT。typ 写入头，例如 at+jwt。只签 active，不使用 next。
func (m *Manager) Sign(claims map[string]any, typ string) (string, error) {
	if typ == "" {
		return "", errors.New("typ is required")
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(m.active.Algorithm), Key: m.active}, opts)
	if err != nil {
		return "", err
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return signed.CompactSerialize()
}

// PublicJWKS 返回当前要发布的公钥集合。轮换调度不在本骨架里；若配置了 next，会和 active 一起发布。
func (m *Manager) PublicJWKS() ([]byte, error) {
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicOf(m.active)}}
	if m.next != nil {
		set.Keys = append(set.Keys, publicOf(*m.next))
	}
	return json.Marshal(set)
}

// Kids 返回 active 与可选 next 的 kid，用于启动日志。
func (m *Manager) Kids() []string {
	out := []string{m.active.KeyID}
	if m.next != nil {
		out = append(out, m.next.KeyID)
	}
	return out
}

func publicOf(k jose.JSONWebKey) jose.JSONWebKey {
	pub := k.Public()
	pub.KeyID = k.KeyID
	pub.Algorithm = k.Algorithm
	pub.Use = "sig"
	return pub
}

func loadForbidden() ([]jose.JSONWebKey, error) {
	entries, err := forbiddenFS.ReadDir("forbidden")
	if err != nil {
		return nil, err
	}
	var keys []jose.JSONWebKey
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := forbiddenFS.ReadFile("forbidden/" + e.Name())
		if err != nil {
			return nil, err
		}
		var set jose.JSONWebKeySet
		if err := json.Unmarshal(raw, &set); err != nil {
			return nil, fmt.Errorf("forbidden jwks %s: %w", e.Name(), err)
		}
		keys = append(keys, set.Keys...)
	}
	if len(keys) == 0 {
		return nil, errors.New("embedded conformance jwks is empty")
	}
	return keys, nil
}

func rejectConformance(jwk jose.JSONWebKey, forbidden []jose.JSONWebKey) error {
	pub, err := normalizePublic(jwk.Key)
	if err != nil {
		return err
	}
	for _, other := range forbidden {
		if jwk.KeyID != "" && jwk.KeyID == other.KeyID {
			return &ConformanceKeyError{Kid: jwk.KeyID, Reason: "kid"}
		}
		otherPub, err := normalizePublic(other.Key)
		if err != nil {
			return err
		}
		if samePublic(pub, otherPub) {
			return &ConformanceKeyError{Kid: jwk.KeyID, Reason: "public key"}
		}
	}
	return nil
}

func normalizePublic(key any) (any, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported key type %T", key)
	}
}

func samePublic(a, b any) bool {
	switch av := a.(type) {
	case *rsa.PublicKey:
		bv, ok := b.(*rsa.PublicKey)
		return ok && av.E == bv.E && av.N.Cmp(bv.N) == 0
	case *ecdsa.PublicKey:
		bv, ok := b.(*ecdsa.PublicKey)
		return ok && av.Curve == bv.Curve && av.X.Cmp(bv.X) == 0 && av.Y.Cmp(bv.Y) == 0
	default:
		return false
	}
}

// GenerateES256 生成开发用 P-256 私钥。PEM 首行写 `# kid:`。
func GenerateES256(kid string) (pemBytes []byte, jwk jose.JSONWebKey, err error) {
	if kid == "" {
		var buf [4]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return nil, jose.JSONWebKey{}, err
		}
		kid = fmt.Sprintf("dev-%x", buf[:])
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, jose.JSONWebKey{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, jose.JSONWebKey{}, err
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	pemBytes = append([]byte("# kid: "+kid+"\n"), body...)
	jwk = jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: AlgES256, Use: "sig"}
	if err := Check(jwk); err != nil {
		return nil, jose.JSONWebKey{}, err
	}
	return pemBytes, jwk, nil
}

// GenerateRSA 生成开发用 RSA 私钥。PEM 首行写 `# kid:`，方便容器只挂一个文件。
// 调用方负责把字节写到磁盘。生成结果会先过测试密钥检查。
func GenerateRSA(kid string, bits int) (pemBytes []byte, jwk jose.JSONWebKey, err error) {
	if bits < 2048 {
		return nil, jose.JSONWebKey{}, errors.New("RSA key must be at least 2048 bits")
	}
	if kid == "" {
		var buf [4]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return nil, jose.JSONWebKey{}, err
		}
		kid = fmt.Sprintf("dev-%x", buf[:])
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, jose.JSONWebKey{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, jose.JSONWebKey{}, err
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	pemBytes = append([]byte("# kid: "+kid+"\n"), body...)
	jwk = jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: AlgRS256, Use: "sig"}
	if err := Check(jwk); err != nil {
		return nil, jose.JSONWebKey{}, err
	}
	return pemBytes, jwk, nil
}
