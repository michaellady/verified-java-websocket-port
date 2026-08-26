package corpora

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// GenerationInput seeds the whole corpus derivation. PublicSeed is committed
// in public manifests. Secret never leaves the protected custodian store; the
// hidden and sealed tiers, their commitment salts, and the canary tokens are
// all derived from it and the rotation epoch.
type GenerationInput struct {
	PublicSeed string
	Secret     string
	Epoch      int
}

// PlanCount reconciles the generation plan with the emitted corpus.
type PlanCount struct {
	Expected int
	Selected int
	Filtered int
}

// GeneratedCorpora is one deterministic generation of all four tiers.
type GeneratedCorpora struct {
	Public       []Scenario
	Hidden       []Scenario
	Sealed       []Scenario
	Handshake    []HandshakeCase
	CanaryIDs    map[string][]string
	CanaryTokens map[string]string
	PlanCounts   map[string]PlanCount
	Epoch        int
	PublicSeed   string
}

// StandardLimits is the default per-scenario limit envelope.
func StandardLimits() Limits {
	return Limits{
		MaxInputBytes:    65536,
		MaxBufferedBytes: 65536,
		MaxActions:       64,
		MaxFrames:        64,
		MaxOutputBytes:   4194304,
	}
}

// GenerateAll derives every tier from the generation input.
func GenerateAll(input GenerationInput) (*GeneratedCorpora, error) {
	if input.PublicSeed == "" {
		return nil, fmt.Errorf("public seed is required")
	}
	if decoded, err := hex.DecodeString(input.Secret); err != nil || len(decoded) != 32 {
		return nil, fmt.Errorf("secret must be 32 bytes of lowercase hex")
	}
	if input.Epoch < 1 {
		return nil, fmt.Errorf("epoch must be >= 1")
	}
	generated := &GeneratedCorpora{
		CanaryIDs:    map[string][]string{},
		CanaryTokens: map[string]string{},
		PlanCounts:   map[string]PlanCount{},
		Epoch:        input.Epoch,
		PublicSeed:   input.PublicSeed,
	}

	publicScenarios, publicPlan, _, err := generateBehaviorTier(
		"public", "pub", input.PublicSeed+"|public", nil)
	if err != nil {
		return nil, err
	}
	generated.Public = publicScenarios
	generated.PlanCounts["public"] = publicPlan

	for _, tier := range []struct{ name, short string }{
		{"hidden", "hid"}, {"sealed", "sea"}} {
		seed := heldOutSeed(input, tier.name)
		canaries := canarySpecs(input, tier.name)
		scenarios, plan, canaryIDs, err := generateBehaviorTier(
			tier.name, tier.short, seed, canaries)
		if err != nil {
			return nil, err
		}
		if tier.name == "hidden" {
			generated.Hidden = scenarios
		} else {
			generated.Sealed = scenarios
		}
		generated.PlanCounts[tier.name] = plan
		generated.CanaryIDs[tier.name] = canaryIDs.ids
		for id, token := range canaryIDs.tokens {
			generated.CanaryTokens[id] = token
		}
	}

	handshake, plan, err := generateHandshakeTier(input.PublicSeed + "|handshake")
	if err != nil {
		return nil, err
	}
	generated.Handshake = handshake
	generated.PlanCounts["handshake"] = plan
	return generated, nil
}

// GeneratePublic derives only the seed-public tiers — public behavior and
// handshake — so any checkout can re-derive and reconcile the committed
// public artifacts without the protected custodian secret.
func GeneratePublic(publicSeed string) ([]Scenario, []HandshakeCase, map[string]PlanCount, error) {
	if publicSeed == "" {
		return nil, nil, nil, fmt.Errorf("public seed is required")
	}
	public, publicPlan, _, err := generateBehaviorTier(
		"public", "pub", publicSeed+"|public", nil)
	if err != nil {
		return nil, nil, nil, err
	}
	handshake, handshakePlan, err := generateHandshakeTier(publicSeed + "|handshake")
	if err != nil {
		return nil, nil, nil, err
	}
	return public, handshake, map[string]PlanCount{
		"public": publicPlan, "handshake": handshakePlan}, nil
}

// heldOutSeed derives a tier seed from the custodian secret and epoch, so
// rotation re-derives held-out content without touching the public tier.
func heldOutSeed(input GenerationInput, tier string) string {
	stream := NewStream(input.Secret, fmt.Sprintf("held-out-seed|%s|epoch-%d", tier, input.Epoch))
	return hex.EncodeToString(stream.Bytes(32))
}

type canarySpec struct {
	token string
}

type canaryResult struct {
	ids    []string
	tokens map[string]string
}

const canariesPerTier = 3

func canarySpecs(input GenerationInput, tier string) []canarySpec {
	specs := make([]canarySpec, canariesPerTier)
	for i := range specs {
		stream := NewStream(input.Secret, fmt.Sprintf("canary|%s|epoch-%d|%d", tier, input.Epoch, i))
		specs[i] = canarySpec{token: "cnry" + hex.EncodeToString(stream.Bytes(8))}
	}
	return specs
}

// CanonicalDigest binds one generation as a single digest.
func (g *GeneratedCorpora) CanonicalDigest() (string, error) {
	var lines [][]byte
	for _, tier := range [][]Scenario{g.Public, g.Hidden, g.Sealed} {
		for _, sc := range tier {
			line, err := sc.CanonicalLine()
			if err != nil {
				return "", err
			}
			lines = append(lines, line)
		}
	}
	for _, c := range g.Handshake {
		line, err := c.CanonicalLine()
		if err != nil {
			return "", err
		}
		lines = append(lines, line)
	}
	joined := append([]byte{}, []byte(fmt.Sprintf("epoch:%d\n", g.Epoch))...)
	for _, line := range lines {
		joined = append(joined, line...)
		joined = append(joined, '\n')
	}
	return DigestSHA256(joined), nil
}

func tierDigest(scenarios []Scenario) (string, error) {
	var joined []byte
	for _, sc := range scenarios {
		line, err := sc.CanonicalLine()
		if err != nil {
			return "", err
		}
		joined = append(joined, line...)
		joined = append(joined, '\n')
	}
	return DigestSHA256(joined), nil
}

type familySpec struct {
	name  string
	count int
	build func(s *Stream, i int) (ScenarioCore, []string, error)
}

func generateBehaviorTier(tier, short, seed string, canaries []canarySpec) (
	[]Scenario, PlanCount, canaryResult, error) {
	type draft struct {
		family    string
		seedIndex int
		core      ScenarioCore
		basis     []string
		canary    string
	}
	var drafts []draft
	expected := 0
	for _, family := range behaviorPlan(tier != "public") {
		for i := 0; i < family.count; i++ {
			expected++
			stream := NewStream(seed, fmt.Sprintf("family|%s|%d", family.name, i))
			core, basis, err := family.build(stream, i)
			if err != nil {
				return nil, PlanCount{}, canaryResult{}, fmt.Errorf(
					"family %s[%d]: %w", family.name, i, err)
			}
			drafts = append(drafts, draft{family: family.name, seedIndex: i,
				core: core, basis: basis})
		}
	}
	for i, spec := range canaries {
		expected++
		stream := NewStream(seed, fmt.Sprintf("canary-shape|%d", i))
		filler := stream.ASCII(4 + stream.Intn(12))
		text := spec.token + " " + filler
		mask := stream.Mask()
		wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeText,
			Payload: []byte(text)}, &mask)
		core := ScenarioCore{Role: "server", InitialState: "open",
			Limits: StandardLimits(),
			Steps:  []Step{{Kind: "bytes", DataBase64: base64Std(wire)}}}
		drafts = append(drafts, draft{family: "text-single", seedIndex: 1000 + i,
			core: core, basis: textBasis(), canary: spec.token})
	}

	// Deterministic dedup by executable-content digest.
	seen := map[string]bool{}
	var kept []draft
	for _, d := range drafts {
		coreMap, err := (Scenario{Core: d.core}).toMap()
		if err != nil {
			return nil, PlanCount{}, canaryResult{}, err
		}
		delete(coreMap, "expected")
		content, err := CanonicalJSON(coreMap)
		if err != nil {
			return nil, PlanCount{}, canaryResult{}, err
		}
		digest := DigestSHA256(content)
		if seen[digest] {
			continue
		}
		seen[digest] = true
		kept = append(kept, d)
	}

	// Deterministic seeded shuffle so canary positions are not structural.
	shuffle := NewStream(seed, "tier-shuffle")
	for i := len(kept) - 1; i > 0; i-- {
		j := shuffle.Intn(i + 1)
		kept[i], kept[j] = kept[j], kept[i]
	}

	canaryOut := canaryResult{tokens: map[string]string{}}
	scenarios := make([]Scenario, 0, len(kept))
	for index, d := range kept {
		derived, err := DeriveExpected(d.core)
		if err != nil {
			return nil, PlanCount{}, canaryResult{}, fmt.Errorf(
				"family %s[%d] is not derivable: %w", d.family, d.seedIndex, err)
		}
		id := fmt.Sprintf("us005.%s.%04d", short, index)
		scenarios = append(scenarios, Scenario{
			ScenarioID:        id,
			Tier:              tier,
			Family:            d.family,
			SeedIndex:         d.seedIndex,
			Core:              d.core,
			Expected:          derived,
			ExpectationBasis:  d.basis,
			ExpectationStatus: ExpectationStatusReferenceModel,
		})
		if d.canary != "" {
			canaryOut.ids = append(canaryOut.ids, id)
			canaryOut.tokens[id] = d.canary
		}
	}
	plan := PlanCount{Expected: expected, Selected: len(scenarios),
		Filtered: expected - len(scenarios)}
	return scenarios, plan, canaryOut, nil
}

func textBasis() []string {
	return []string{"behavior.messages.text-binary", "rfc6455.section-5-6"}
}

func fragmentBasis() []string {
	return []string{"behavior.fragmentation.reassembly", "rfc6455.section-5-4"}
}

func controlBasis() []string {
	return []string{"behavior.control.ping-pong", "rfc6455.section-5-5-2", "rfc6455.section-5-5-3"}
}

func closeBasis() []string {
	return []string{"behavior.close.terminal-state", "rfc6455.section-5-5-1", "rfc6455.section-7"}
}

func utf8Basis() []string {
	return []string{"property.messages.utf8-strictness", "rfc3629.utf8", "rfc6455.section-8-1"}
}

func limitBasis() []string {
	return []string{"property.fragmentation.bounded-state", "rfc6455.section-10-4"}
}

func stateBasis() []string {
	return []string{"behavior.connection.state-transitions", "property.connection.state-machine-total"}
}

func closeCodeBasis() []string {
	return []string{"property.close.code-validity", "rfc6455.section-7-4"}
}

func framingBasis() []string {
	return []string{"rfc6455.section-5-2"}
}

// roleFor alternates the role under test.
func roleFor(i int) string {
	if i%2 == 0 {
		return "server"
	}
	return "client"
}

// inboundChunk encodes a frame as arriving bytes with role-correct masking.
func inboundChunk(role string, s *Stream, frame WireFrame) []byte {
	if role == "server" {
		mask := s.Mask()
		return EncodeFrame(frame, &mask)
	}
	return EncodeFrame(frame, nil)
}

func bytesStep(chunk []byte) Step {
	return Step{Kind: "bytes", DataBase64: base64Std(chunk)}
}

func singleFrameScenario(role string, s *Stream, frame WireFrame) ScenarioCore {
	return ScenarioCore{Role: role, InitialState: "open", Limits: StandardLimits(),
		Steps: []Step{bytesStep(inboundChunk(role, s, frame))}}
}

// splitRunes divides text into part rune groups, each nonempty.
func splitRunes(text string, parts int) []string {
	runes := []rune(text)
	if parts > len(runes) {
		parts = len(runes)
	}
	out := make([]string, 0, parts)
	per := len(runes) / parts
	at := 0
	for i := 0; i < parts; i++ {
		end := at + per
		if i == parts-1 {
			end = len(runes)
		}
		out = append(out, string(runes[at:end]))
		at = end
	}
	return out
}

// behaviorPlan returns the shared family plan; held-out tiers additionally
// carry boundary families whose semantics were pinned by reading the
// quarantined Java-WebSocket 1.6.0 sources (CloseFrame, Draft_6455, Draft,
// ControlFrame) rather than reseeds of public families.
func behaviorPlan(heldOut bool) []familySpec {
	valid := func(core ScenarioCore, basis []string) (ScenarioCore, []string, error) {
		return core, basis, nil
	}
	validCloseCodes := []int{1000, 1001, 1008, 1011, 3000, 4999}
	invalidCloseCodes := []int{999, 1004, 1005, 1006, 1015}
	plan := behaviorPlanShared(valid, validCloseCodes, invalidCloseCodes)
	if heldOut {
		plan = append(plan, behaviorPlanHeldOut(valid)...)
	}
	return plan
}

func behaviorPlanShared(valid func(ScenarioCore, []string) (ScenarioCore, []string, error),
	validCloseCodes, invalidCloseCodes []int) []familySpec {
	return []familySpec{
		{"text-single", 4, func(s *Stream, i int) (ScenarioCore, []string, error) {
			role := roleFor(i)
			text := s.UTF8Text(3 + s.Intn(20))
			return valid(singleFrameScenario(role, s, WireFrame{
				Fin: true, Opcode: OpcodeText, Payload: []byte(text)}), textBasis())
		}},
		{"text-empty", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			return valid(singleFrameScenario("server", s, WireFrame{
				Fin: true, Opcode: OpcodeText, Payload: nil}), textBasis())
		}},
		{"binary-single", 4, func(s *Stream, i int) (ScenarioCore, []string, error) {
			role := roleFor(i)
			payload := s.Bytes(1 + s.Intn(40))
			return valid(singleFrameScenario(role, s, WireFrame{
				Fin: true, Opcode: OpcodeBinary, Payload: payload}), textBasis())
		}},
		{"binary-empty", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			return valid(singleFrameScenario("client", s, WireFrame{
				Fin: true, Opcode: OpcodeBinary, Payload: nil}), textBasis())
		}},
		{"fragmented-text", 3, func(s *Stream, i int) (ScenarioCore, []string, error) {
			role := roleFor(i)
			text := s.UTF8Text(6 + s.Intn(10))
			parts := splitRunes(text, 2+i%2)
			steps := make([]Step, 0, len(parts))
			for p, part := range parts {
				opcode := OpcodeContinuous
				if p == 0 {
					opcode = OpcodeText
				}
				steps = append(steps, bytesStep(inboundChunk(role, s, WireFrame{
					Fin: p == len(parts)-1, Opcode: opcode, Payload: []byte(part)})))
			}
			return valid(ScenarioCore{Role: role, InitialState: "open",
				Limits: StandardLimits(), Steps: steps}, fragmentBasis())
		}},
		{"fragmented-binary", 2, func(s *Stream, i int) (ScenarioCore, []string, error) {
			role := roleFor(i)
			payload := s.Bytes(8 + s.Intn(24))
			cut := 1 + s.Intn(len(payload)-1)
			steps := []Step{
				bytesStep(inboundChunk(role, s, WireFrame{Fin: false,
					Opcode: OpcodeBinary, Payload: payload[:cut]})),
				bytesStep(inboundChunk(role, s, WireFrame{Fin: true,
					Opcode: OpcodeContinuous, Payload: payload[cut:]})),
			}
			return valid(ScenarioCore{Role: role, InitialState: "open",
				Limits: StandardLimits(), Steps: steps}, fragmentBasis())
		}},
		{"fragment-interleaved-ping", 2, func(s *Stream, i int) (ScenarioCore, []string, error) {
			role := roleFor(i)
			text := s.UTF8Text(6)
			parts := splitRunes(text, 2)
			steps := []Step{
				bytesStep(inboundChunk(role, s, WireFrame{Fin: false,
					Opcode: OpcodeText, Payload: []byte(parts[0])})),
				bytesStep(inboundChunk(role, s, WireFrame{Fin: true,
					Opcode: OpcodePing, Payload: s.Bytes(s.Intn(20))})),
				bytesStep(inboundChunk(role, s, WireFrame{Fin: true,
					Opcode: OpcodeContinuous, Payload: []byte(parts[1])})),
			}
			return valid(ScenarioCore{Role: role, InitialState: "open",
				Limits: StandardLimits(), Steps: steps}, fragmentBasis())
		}},
		{"ping-inbound", 2, func(s *Stream, i int) (ScenarioCore, []string, error) {
			role := roleFor(i)
			return valid(singleFrameScenario(role, s, WireFrame{
				Fin: true, Opcode: OpcodePing, Payload: s.Bytes(s.Intn(126))}), controlBasis())
		}},
		{"pong-inbound", 2, func(s *Stream, i int) (ScenarioCore, []string, error) {
			role := roleFor(i)
			return valid(singleFrameScenario(role, s, WireFrame{
				Fin: true, Opcode: OpcodePong, Payload: s.Bytes(s.Intn(126))}), controlBasis())
		}},
		{"close-remote", 3, func(s *Stream, i int) (ScenarioCore, []string, error) {
			role := roleFor(i)
			code := validCloseCodes[s.Intn(len(validCloseCodes))]
			reason := s.ASCII(s.Intn(20))
			payload := append([]byte{byte(code >> 8), byte(code)}, []byte(reason)...)
			return valid(singleFrameScenario(role, s, WireFrame{
				Fin: true, Opcode: OpcodeClose, Payload: payload}), closeBasis())
		}},
		{"close-remote-empty", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			return valid(singleFrameScenario("server", s, WireFrame{
				Fin: true, Opcode: OpcodeClose, Payload: nil}), closeBasis())
		}},
		{"close-local-then-remote", 2, func(s *Stream, i int) (ScenarioCore, []string, error) {
			role := roleFor(i)
			code := validCloseCodes[s.Intn(len(validCloseCodes))]
			remote := append([]byte{byte(code >> 8), byte(code)}, []byte(s.ASCII(s.Intn(10)))...)
			steps := []Step{
				{Kind: "action", Action: "send_close", Code: code, Reason: s.ASCII(s.Intn(10))},
				bytesStep(inboundChunk(role, s, WireFrame{Fin: true,
					Opcode: OpcodeClose, Payload: remote})),
			}
			return valid(ScenarioCore{Role: role, InitialState: "open",
				Limits: StandardLimits(), Steps: steps}, closeBasis())
		}},
		{"close-local-then-eof", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			steps := []Step{
				{Kind: "action", Action: "send_close", Code: 1001, Reason: s.ASCII(5)},
				{Kind: "action", Action: "eof"},
			}
			return valid(ScenarioCore{Role: "client", InitialState: "open",
				Limits: StandardLimits(), Steps: steps}, closeBasis())
		}},
		{"eof-abnormal", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			return valid(ScenarioCore{Role: roleFor(i), InitialState: "open",
				Limits: StandardLimits(),
				Steps:  []Step{{Kind: "action", Action: "eof"}}}, closeBasis())
		}},
		{"zero-chunk", 2, func(s *Stream, i int) (ScenarioCore, []string, error) {
			state := "open"
			if i == 1 {
				state = "closed"
			}
			return valid(ScenarioCore{Role: "server", InitialState: state,
				Limits: StandardLimits(),
				Steps:  []Step{bytesStep(nil)}}, stateBasis())
		}},
		{"split-frame", 2, func(s *Stream, i int) (ScenarioCore, []string, error) {
			role := roleFor(i)
			payload := s.Bytes(4 + s.Intn(30))
			chunk := inboundChunk(role, s, WireFrame{Fin: true,
				Opcode: OpcodeBinary, Payload: payload})
			cut := 1 + s.Intn(len(chunk)-1)
			return valid(ScenarioCore{Role: role, InitialState: "open",
				Limits: StandardLimits(),
				Steps:  []Step{bytesStep(chunk[:cut]), bytesStep(chunk[cut:])},
			}, framingBasis())
		}},
		{"payload-16bit", 2, func(s *Stream, i int) (ScenarioCore, []string, error) {
			role := roleFor(i)
			length := 126
			if i == 1 {
				length = 127 + s.Intn(800)
			}
			return valid(singleFrameScenario(role, s, WireFrame{
				Fin: true, Opcode: OpcodeBinary, Payload: s.Bytes(length)}), framingBasis())
		}},
		{"payload-64bit", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			limits := StandardLimits()
			limits.MaxInputBytes = 131072
			limits.MaxBufferedBytes = 131072
			role := "server"
			mask := s.Mask()
			chunk := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeBinary,
				Payload: s.Bytes(65536)}, &mask)
			return valid(ScenarioCore{Role: role, InitialState: "open", Limits: limits,
				Steps: []Step{bytesStep(chunk)}}, framingBasis())
		}},
		{"send-text", 2, func(s *Stream, i int) (ScenarioCore, []string, error) {
			return valid(ScenarioCore{Role: roleFor(i), InitialState: "open",
				Limits: StandardLimits(),
				Steps: []Step{{Kind: "action", Action: "send_text",
					Text: s.UTF8Text(2 + s.Intn(20))}}}, textBasis())
		}},
		{"send-binary", 2, func(s *Stream, i int) (ScenarioCore, []string, error) {
			return valid(ScenarioCore{Role: roleFor(i), InitialState: "open",
				Limits: StandardLimits(),
				Steps: []Step{{Kind: "action", Action: "send_binary",
					DataBase64: base64Std(s.Bytes(1 + s.Intn(40)))}}}, textBasis())
		}},
		{"send-ping", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			return valid(ScenarioCore{Role: roleFor(i), InitialState: "open",
				Limits: StandardLimits(),
				Steps: []Step{{Kind: "action", Action: "send_ping",
					DataBase64: base64Std(s.Bytes(s.Intn(126)))}}}, controlBasis())
		}},
		{"send-pong", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			return valid(ScenarioCore{Role: roleFor(i), InitialState: "open",
				Limits: StandardLimits(),
				Steps: []Step{{Kind: "action", Action: "send_pong",
					DataBase64: base64Std(s.Bytes(s.Intn(126)))}}}, controlBasis())
		}},
		{"send-fragment", 2, func(s *Stream, i int) (ScenarioCore, []string, error) {
			opcode := "text"
			first := base64Std([]byte(s.UTF8Text(4)))
			second := base64Std([]byte(s.UTF8Text(3)))
			if i == 1 {
				opcode = "binary"
				first = base64Std(s.Bytes(5))
				second = base64Std(s.Bytes(4))
			}
			steps := []Step{
				{Kind: "action", Action: "send_fragment", Opcode: opcode,
					Fin: false, DataBase64: first},
				{Kind: "action", Action: "send_fragment", Opcode: opcode,
					Fin: true, DataBase64: second},
			}
			return valid(ScenarioCore{Role: roleFor(i), InitialState: "open",
				Limits: StandardLimits(), Steps: steps}, fragmentBasis())
		}},
		{"multi-frame-chunk", 2, func(s *Stream, i int) (ScenarioCore, []string, error) {
			role := roleFor(i)
			text := s.UTF8Text(4)
			chunk := inboundChunk(role, s, WireFrame{Fin: true,
				Opcode: OpcodeText, Payload: []byte(text)})
			chunk = append(chunk, inboundChunk(role, s, WireFrame{Fin: true,
				Opcode: OpcodeBinary, Payload: s.Bytes(3 + s.Intn(10))})...)
			return valid(ScenarioCore{Role: role, InitialState: "open",
				Limits: StandardLimits(),
				Steps:  []Step{bytesStep(chunk)}}, framingBasis())
		}},
		{"closing-recv-close", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			code := validCloseCodes[s.Intn(len(validCloseCodes))]
			payload := append([]byte{byte(code >> 8), byte(code)}, []byte(s.ASCII(4))...)
			mask := s.Mask()
			chunk := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeClose,
				Payload: payload}, &mask)
			return valid(ScenarioCore{Role: "server", InitialState: "closing",
				Limits: StandardLimits(),
				Steps:  []Step{bytesStep(chunk)}}, closeBasis())
		}},
		{"invalid-utf8-text", 2, func(s *Stream, i int) (ScenarioCore, []string, error) {
			payload := []byte{0xff, 0xfe, 0xfd}
			if i == 1 {
				payload = []byte{0xc0, 0x80} // overlong NUL
			}
			return valid(singleFrameScenario("server", s, WireFrame{
				Fin: true, Opcode: OpcodeText, Payload: payload}), utf8Basis())
		}},
		{"rsv-bit", 3, func(s *Stream, i int) (ScenarioCore, []string, error) {
			frame := WireFrame{Fin: true, Opcode: OpcodeText,
				Payload: []byte(s.ASCII(3))}
			switch i {
			case 0:
				frame.RSV1 = true
			case 1:
				frame.RSV2 = true
			default:
				frame.RSV3 = true
			}
			return valid(singleFrameScenario("server", s, frame), framingBasis())
		}},
		{"bad-opcode", 2, func(s *Stream, i int) (ScenarioCore, []string, error) {
			opcode := Opcode(0x3 + i)
			return valid(singleFrameScenario("server", s, WireFrame{
				Fin: true, Opcode: opcode, Payload: s.Bytes(2)}), framingBasis())
		}},
		{"unexpected-continuation", 2, func(s *Stream, i int) (ScenarioCore, []string, error) {
			return valid(singleFrameScenario("server", s, WireFrame{
				Fin: i == 0, Opcode: OpcodeContinuous, Payload: s.Bytes(3)}), fragmentBasis())
		}},
		{"fragment-restart", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			role := "server"
			steps := []Step{
				bytesStep(inboundChunk(role, s, WireFrame{Fin: false,
					Opcode: OpcodeText, Payload: []byte(s.ASCII(3))})),
				bytesStep(inboundChunk(role, s, WireFrame{Fin: false,
					Opcode: OpcodeText, Payload: []byte(s.ASCII(3))})),
			}
			return valid(ScenarioCore{Role: role, InitialState: "open",
				Limits: StandardLimits(), Steps: steps}, fragmentBasis())
		}},
		{"data-during-fragment", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			role := "server"
			steps := []Step{
				bytesStep(inboundChunk(role, s, WireFrame{Fin: false,
					Opcode: OpcodeText, Payload: []byte(s.ASCII(3))})),
				bytesStep(inboundChunk(role, s, WireFrame{Fin: true,
					Opcode: OpcodeBinary, Payload: s.Bytes(3)})),
			}
			return valid(ScenarioCore{Role: role, InitialState: "open",
				Limits: StandardLimits(), Steps: steps}, fragmentBasis())
		}},
		{"control-oversize", 2, func(s *Stream, i int) (ScenarioCore, []string, error) {
			opcode := OpcodePing
			payload := s.Bytes(126 + s.Intn(40))
			if i == 1 {
				opcode = OpcodeClose
				payload = append([]byte{0x03, 0xe8}, []byte(strings.Repeat("r", 124))...)
			}
			return valid(singleFrameScenario("server", s, WireFrame{
				Fin: true, Opcode: opcode, Payload: payload}), limitBasis())
		}},
		{"control-nonfin", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			return valid(singleFrameScenario("server", s, WireFrame{
				Fin: false, Opcode: OpcodePing, Payload: s.Bytes(4)}), controlBasis())
		}},
		{"frame-limit", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			limits := StandardLimits()
			limits.MaxFrames = 1
			role := "server"
			chunk := inboundChunk(role, s, WireFrame{Fin: true,
				Opcode: OpcodeText, Payload: []byte(s.ASCII(2))})
			chunk = append(chunk, inboundChunk(role, s, WireFrame{Fin: true,
				Opcode: OpcodeBinary, Payload: s.Bytes(2)})...)
			return valid(ScenarioCore{Role: role, InitialState: "open",
				Limits: limits, Steps: []Step{bytesStep(chunk)}}, limitBasis())
		}},
		{"action-limit", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			limits := StandardLimits()
			limits.MaxActions = 1
			steps := []Step{
				{Kind: "action", Action: "send_text", Text: "a"},
				{Kind: "action", Action: "send_text", Text: "b"},
			}
			return valid(ScenarioCore{Role: "client", InitialState: "open",
				Limits: limits, Steps: steps}, limitBasis())
		}},
		{"input-limit", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			limits := StandardLimits()
			limits.MaxInputBytes = 8
			return valid(ScenarioCore{Role: "server", InitialState: "open",
				Limits: limits,
				Steps:  []Step{bytesStep(s.Bytes(9))}}, limitBasis())
		}},
		{"buffer-limit-frame", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			limits := StandardLimits()
			limits.MaxBufferedBytes = 64
			mask := s.Mask()
			chunk := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeBinary,
				Payload: s.Bytes(80)}, &mask)
			return valid(ScenarioCore{Role: "server", InitialState: "open",
				Limits: limits, Steps: []Step{bytesStep(chunk)}}, limitBasis())
		}},
		{"state-send-in-closing", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			return valid(ScenarioCore{Role: "client", InitialState: "closing",
				Limits: StandardLimits(),
				Steps: []Step{{Kind: "action", Action: "send_text",
					Text: s.ASCII(3)}}}, stateBasis())
		}},
		{"state-bytes-in-closed", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			return valid(ScenarioCore{Role: "server", InitialState: "closed",
				Limits: StandardLimits(),
				Steps:  []Step{bytesStep(s.Bytes(3))}}, stateBasis())
		}},
		{"state-eof-in-closed", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			return valid(ScenarioCore{Role: "client", InitialState: "closed",
				Limits: StandardLimits(),
				Steps:  []Step{{Kind: "action", Action: "eof"}}}, stateBasis())
		}},
		{"state-frame-in-closing", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			mask := s.Mask()
			chunk := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeText,
				Payload: []byte(s.ASCII(3))}, &mask)
			return valid(ScenarioCore{Role: "server", InitialState: "closing",
				Limits: StandardLimits(),
				Steps:  []Step{bytesStep(chunk)}}, stateBasis())
		}},
		{"close-code-invalid-wire", 3, func(s *Stream, i int) (ScenarioCore, []string, error) {
			code := invalidCloseCodes[(i*2+s.Intn(2))%len(invalidCloseCodes)]
			payload := []byte{byte(code >> 8), byte(code)}
			return valid(singleFrameScenario("server", s, WireFrame{
				Fin: true, Opcode: OpcodeClose, Payload: payload}), closeCodeBasis())
		}},
		{"close-payload-1", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			return valid(singleFrameScenario("server", s, WireFrame{
				Fin: true, Opcode: OpcodeClose, Payload: []byte{0x03}}), closeCodeBasis())
		}},
		{"send-close-invalid-code", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			return valid(ScenarioCore{Role: "client", InitialState: "open",
				Limits: StandardLimits(),
				Steps: []Step{{Kind: "action", Action: "send_close",
					Code: 999, Reason: "bad"}}}, closeCodeBasis())
		}},
	}
}

// behaviorPlanHeldOut carries the structural boundary families reserved for
// the hidden and sealed tiers.
func behaviorPlanHeldOut(valid func(ScenarioCore, []string) (ScenarioCore, []string, error)) []familySpec {
	closeWith := func(s *Stream, payload []byte) ScenarioCore {
		mask := s.Mask()
		wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeClose, Payload: payload}, &mask)
		return ScenarioCore{Role: "server", InitialState: "open", Limits: StandardLimits(),
			Steps: []Step{bytesStep(wire)}}
	}
	return []familySpec{
		// CloseFrame.isValid accepts 1012-1014 (they sit at or below 1015).
		{"close-code-1012-1014", 3, func(s *Stream, i int) (ScenarioCore, []string, error) {
			code := 1012 + i
			payload := append([]byte{byte(code >> 8), byte(code)}, []byte(s.ASCII(s.Intn(8)))...)
			return valid(closeWith(s, payload), closeCodeBasis())
		}},
		// CloseFrame.isValid rejects 1016-2999 with PROTOCOL_ERROR.
		{"close-code-reserved-range", 3, func(s *Stream, i int) (ScenarioCore, []string, error) {
			code := []int{1016, 2000, 2999}[i]
			payload := []byte{byte(code >> 8), byte(code)}
			return valid(closeWith(s, payload), closeCodeBasis())
		}},
		// Invalid-UTF-8 reason: setPayload nulls the reason and isValid then
		// fails with a NullPointerException (JAVA_RUNTIME_REJECTION).
		{"close-invalid-utf8-reason", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			payload := append([]byte{0x03, 0xe8}, 0xff, 0xfe)
			return valid(closeWith(s, payload), utf8Basis())
		}},
		// Code 1007 with an empty reason trips isValid's first check.
		{"close-1007-empty-reason", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			return valid(closeWith(s, []byte{0x03, 0xef}), closeCodeBasis())
		}},
		// ControlFrame.isValid has no length check on the send side.
		{"send-oversize-ping", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			return valid(ScenarioCore{Role: roleFor(i), InitialState: "open",
				Limits: StandardLimits(),
				Steps: []Step{{Kind: "action", Action: "send_ping",
					DataBase64: base64Std(s.Bytes(126 + s.Intn(75)))}}}, controlBasis())
		}},
		// Draft.continuousFrame: a fin=true first call emits one complete
		// data frame and leaves no open sequence.
		{"send-fragment-single", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			return valid(ScenarioCore{Role: roleFor(i), InitialState: "open",
				Limits: StandardLimits(),
				Steps: []Step{{Kind: "action", Action: "send_fragment",
					Opcode: "text", Fin: true,
					DataBase64: base64Std([]byte(s.UTF8Text(4)))}}}, fragmentBasis())
		}},
		// Cumulative fragment overflow at a NON-FIN continuation trips the
		// adapter accounting (Java only checks at starts and fins).
		{"fragment-overflow-nonfin", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			limits := StandardLimits()
			limits.MaxBufferedBytes = 32
			steps := []Step{
				bytesStep(inboundChunk("server", s, WireFrame{Fin: false,
					Opcode: OpcodeBinary, Payload: s.Bytes(20)})),
				bytesStep(inboundChunk("server", s, WireFrame{Fin: false,
					Opcode: OpcodeContinuous, Payload: s.Bytes(20)})),
			}
			return valid(ScenarioCore{Role: "server", InitialState: "open",
				Limits: limits, Steps: steps}, limitBasis())
		}},
		// Cumulative fragment overflow at a FIN continuation trips Java's
		// checkBufferLimit (1009).
		{"fragment-overflow-fin", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			limits := StandardLimits()
			limits.MaxBufferedBytes = 32
			steps := []Step{
				bytesStep(inboundChunk("server", s, WireFrame{Fin: false,
					Opcode: OpcodeBinary, Payload: s.Bytes(20)})),
				bytesStep(inboundChunk("server", s, WireFrame{Fin: true,
					Opcode: OpcodeContinuous, Payload: s.Bytes(20)})),
			}
			return valid(ScenarioCore{Role: "server", InitialState: "open",
				Limits: limits, Steps: steps}, limitBasis())
		}},
		// setCode(1015) normalizes to 1005 and isValid rejects it (1002).
		{"send-close-1015", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			return valid(ScenarioCore{Role: "client", InitialState: "open",
				Limits: StandardLimits(),
				Steps: []Step{{Kind: "action", Action: "send_close",
					Code: 1015, Reason: s.ASCII(3)}}}, closeCodeBasis())
		}},
		// A truncated UTF-8 tail passes the translate-time DFA and fails the
		// strict decoder at process time, with the frame recorded (1007).
		{"text-truncated-tail", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			payload := append([]byte(s.ASCII(2+s.Intn(6))), 0xc3)
			mask := s.Mask()
			wire := EncodeFrame(WireFrame{Fin: true, Opcode: OpcodeText,
				Payload: payload}, &mask)
			return valid(ScenarioCore{Role: "server", InitialState: "open",
				Limits: StandardLimits(),
				Steps:  []Step{bytesStep(wire)}}, utf8Basis())
		}},
		// A multi-byte character split across fragments assembles cleanly:
		// the truncated-tail start is DFA-accepted and the assembled message
		// validates strictly.
		{"fragment-mid-rune", 1, func(s *Stream, i int) (ScenarioCore, []string, error) {
			prefix := []byte(s.ASCII(1 + s.Intn(4)))
			steps := []Step{
				bytesStep(inboundChunk("server", s, WireFrame{Fin: false,
					Opcode: OpcodeText, Payload: append(prefix, 0xc3)})),
				bytesStep(inboundChunk("server", s, WireFrame{Fin: true,
					Opcode: OpcodeContinuous, Payload: []byte{0xa9, 'z'}})),
			}
			return valid(ScenarioCore{Role: "server", InitialState: "open",
				Limits: StandardLimits(), Steps: steps}, utf8Basis())
		}},
	}
}
