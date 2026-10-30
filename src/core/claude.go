package core

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/shared/constant"
)

// DefaultModel reads advisories. Overridable with --model.
const DefaultModel = "claude-opus-5-5"

// ClaudeAssessor asks Claude to read an advisory and its fix. Uses ANTHROPIC_API_KEY.
type ClaudeAssessor struct {
	Client anthropic.Client
	Model  string
}

// NewClaudeAssessor uses the default client credentials (ANTHROPIC_API_KEY etc).
func NewClaudeAssessor(model string) *ClaudeAssessor {
	if model == "" {
		model = DefaultModel
	}

	return &ClaudeAssessor{Client: anthropic.NewClient(), Model: model}
}

// ID is the model, so assessments from different models are cached separately.
func (c *ClaudeAssessor) ID() string { return c.Model }

const assessPrompt = `You are triaging a dependency vulnerability advisory for a specific project.
Decide what the advisory is actually about and whether this deployment meets its
preconditions. Be precise and conservative: answer "no" for applies only when the
deployment description clearly rules the preconditions out, and "unclear" when it doesn't
say enough. Never assume a fact the deployment description doesn't state.

Package: %s %s
Advisory: %s (%s)
Summary: %s

Details:
%s

Fix (patch from the advisory's FIX reference, may be truncated or absent):
%s

How the project uses the package:
%s
Deployment:
%s
Fill in:
- affects: "code" if specific functions are vulnerable; "data" if the problem is something
  the package ships that every user of the package consumes (e.g. a bundled certificate
  list); "install" if it only bites while installing/building packages; else "unclear".
- affected_symbols: for "code", the vulnerable functions/classes/modules, as dotted names
  within the package (e.g. "ReadWriteLock", "SoftFileLock.acquire", "_soft") - prefer
  names the fix changes. Empty otherwise.
- preconditions: what an attacker needs, short phrases.
- applies: "yes", "no" or "unclear" for this deployment.
- justification: when applies is "no", the OpenVEX justification that fits best -
  "vulnerable_code_not_present" (e.g. platform-specific code for another platform),
  "vulnerable_code_cannot_be_controlled_by_adversary" (e.g. needs a local user who doesn't
  exist) or "inline_mitigations_already_exist". Empty otherwise.
- reasoning: one or two sentences.
- confidence: "high", "medium" or "low".`

var assessmentSchema = json.RawMessage(`{
  "type": "object",
  "additionalProperties": false,
  "required": ["affects", "affected_symbols", "preconditions", "applies", "justification", "reasoning", "confidence"],
  "properties": {
    "affects": {"type": "string", "enum": ["code", "data", "install", "unclear"]},
    "affected_symbols": {"type": "array", "items": {"type": "string"}},
    "preconditions": {"type": "array", "items": {"type": "string"}},
    "applies": {"type": "string", "enum": ["yes", "no", "unclear"]},
    "justification": {"type": "string", "enum": ["", "vulnerable_code_not_present", "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist"]},
    "reasoning": {"type": "string"},
    "confidence": {"type": "string", "enum": ["high", "medium", "low"]}
  }
}`)

// Assess asks Claude for a structured assessment. Advisories describe vulnerabilities, so
// a safety refusal is possible: the request opts into server-side fallbacks, and a refusal
// that survives them is an error (the advisory is left unassessed), never a guess.
func (c *ClaudeAssessor) Assess(ctx context.Context, in AssessInput) (*Assessment, error) {
	prompt := fmt.Sprintf(assessPrompt,
		in.Package, in.Version,
		in.Advisory.ID, strings.Join(in.Advisory.Aliases, ", "),
		in.Advisory.Summary,
		truncate(in.Advisory.Details, 8000),
		orNone(truncate(in.FixPatch, 30000)),
		in.Evidence,
		in.Deployment.Describe(),
	)

	resp, err := c.Client.Beta.Messages.New(ctx, anthropic.BetaMessageNewParams{
		Model:     c.Model,
		MaxTokens: 16000,
		Betas:     []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01},
		Fallbacks: anthropic.BetaFallbacksParamUnion{OfDefault: constant.ValueOf[constant.Default]()},
		OutputConfig: anthropic.BetaOutputConfigParam{
			Format: anthropic.BetaJSONOutputFormatParam{Schema: assessmentSchema},
		},
		Messages: []anthropic.BetaMessageParam{
			anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(prompt)),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("assessing %s: %w", in.Advisory.ID, err)
	}

	if resp.StopReason == anthropic.BetaStopReasonRefusal {
		return nil, fmt.Errorf("assessing %s: declined by the model (%s)", in.Advisory.ID, resp.StopDetails.Category)
	}

	if resp.StopReason == anthropic.BetaStopReasonMaxTokens {
		return nil, fmt.Errorf("assessing %s: response hit max_tokens", in.Advisory.ID)
	}

	var text strings.Builder

	for _, block := range resp.Content {
		if t, ok := block.AsAny().(anthropic.BetaTextBlock); ok {
			text.WriteString(t.Text)
		}
	}

	var a Assessment
	if err := json.Unmarshal([]byte(text.String()), &a); err != nil {
		return nil, fmt.Errorf("assessing %s: unreadable response: %w", in.Advisory.ID, err)
	}

	return &a, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}

	return s[:max] + "\n[truncated]"
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(none available)"
	}

	return s
}
