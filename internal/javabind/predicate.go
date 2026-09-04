package javabind

import (
	"encoding/json"
	"fmt"
)

// PredicateKinds is the closed vocabulary. A predicate outside it is a spec
// error, not an unrecognised-but-tolerated extension.
var PredicateKinds = map[string]bool{
	"outcome":          true,
	"error_code":       true,
	"error_close_code": true,
	"close_code":       true,
	"counts_field":     true,
	"frame_field":      true,
	"frame_count":      true,
	"event_field":      true,
	"event_absent":     true,
}

// Validate checks that a predicate carries exactly the operands its kind needs.
func (p Predicate) Validate() error {
	if !PredicateKinds[p.Kind] {
		return fmt.Errorf("predicate kind %q is outside the closed vocabulary", p.Kind)
	}
	switch p.Kind {
	case "outcome", "error_code":
		if p.String == "" {
			return fmt.Errorf("predicate %q needs a string operand", p.Kind)
		}
	case "error_close_code", "close_code":
		if p.Number == nil {
			return fmt.Errorf("predicate %q needs a number operand", p.Kind)
		}
	case "counts_field":
		if p.Field == "" || p.Number == nil {
			return fmt.Errorf("predicate %q needs a field and a number", p.Kind)
		}
	case "frame_field":
		if p.Direction != "inbound" && p.Direction != "outbound" {
			return fmt.Errorf("predicate %q needs direction inbound or outbound", p.Kind)
		}
		if p.Index == nil || p.Field == "" {
			return fmt.Errorf("predicate %q needs an index and a field", p.Kind)
		}
		if p.Number == nil && p.String == "" {
			return fmt.Errorf("predicate %q needs an expected value", p.Kind)
		}
	case "frame_count":
		if p.Direction != "inbound" && p.Direction != "outbound" || p.Number == nil {
			return fmt.Errorf("predicate %q needs a direction and a number", p.Kind)
		}
	case "event_field":
		if p.EventType == "" || p.Index == nil || p.Field == "" {
			return fmt.Errorf("predicate %q needs an event type, index and field", p.Kind)
		}
		if p.Number == nil && p.String == "" {
			return fmt.Errorf("predicate %q needs an expected value", p.Kind)
		}
	case "event_absent":
		if p.EventType == "" {
			return fmt.Errorf("predicate %q needs an event type", p.Kind)
		}
	}
	return nil
}

// Describe renders a predicate for a human reader without changing its meaning.
func (p Predicate) Describe() string {
	data, err := json.Marshal(p)
	if err != nil {
		return p.Kind
	}
	return string(data)
}

// Evaluate applies the predicate to one byte-exact adapter response line. It
// returns the verdict and an observation string recording what was actually
// seen, so a failing witness reports the observed value rather than only "false".
func (p Predicate) Evaluate(responseLine []byte) (bool, string, error) {
	var response map[string]any
	if err := json.Unmarshal(responseLine, &response); err != nil {
		return false, "", fmt.Errorf("javabind: response is not JSON: %w", err)
	}
	switch p.Kind {
	case "outcome":
		got, _ := response["outcome"].(string)
		return got == p.String, got, nil
	case "error_code":
		got := nestedString(response, "error", "code")
		return got == p.String, got, nil
	case "error_close_code":
		got, ok := nestedNumber(response, "error", "close_code")
		return ok && got == *p.Number, formatNumber(got, ok), nil
	case "close_code":
		got, ok := nestedNumber(response, "close", "code")
		return ok && got == *p.Number, formatNumber(got, ok), nil
	case "counts_field":
		got, ok := nestedNumber(response, "counts", p.Field)
		return ok && got == *p.Number, formatNumber(got, ok), nil
	case "frame_field":
		frames := framesWithDirection(response, p.Direction)
		if *p.Index >= len(frames) {
			return false, fmt.Sprintf("only %d %s frames", len(frames), p.Direction), nil
		}
		return compareField(frames[*p.Index], p)
	case "frame_count":
		frames := framesWithDirection(response, p.Direction)
		return len(frames) == *p.Number, fmt.Sprintf("%d", len(frames)), nil
	case "event_field":
		events := eventsWithType(response, p.EventType)
		if *p.Index >= len(events) {
			return false, fmt.Sprintf("only %d %q events", len(events), p.EventType), nil
		}
		return compareField(events[*p.Index], p)
	case "event_absent":
		events := eventsWithType(response, p.EventType)
		return len(events) == 0, fmt.Sprintf("%d %q events", len(events), p.EventType), nil
	}
	return false, "", fmt.Errorf("javabind: predicate kind %q is not evaluable", p.Kind)
}

func compareField(object map[string]any, p Predicate) (bool, string, error) {
	value, present := object[p.Field]
	if !present {
		return false, "absent", nil
	}
	if p.Number != nil {
		number, ok := value.(float64)
		return ok && int(number) == *p.Number, fmt.Sprintf("%v", value), nil
	}
	text, ok := value.(string)
	return ok && text == p.String, fmt.Sprintf("%v", value), nil
}

func nestedString(response map[string]any, outer, inner string) string {
	object, ok := response[outer].(map[string]any)
	if !ok {
		return ""
	}
	text, _ := object[inner].(string)
	return text
}

func nestedNumber(response map[string]any, outer, inner string) (int, bool) {
	object, ok := response[outer].(map[string]any)
	if !ok {
		return 0, false
	}
	number, ok := object[inner].(float64)
	if !ok {
		return 0, false
	}
	return int(number), true
}

func formatNumber(value int, ok bool) string {
	if !ok {
		return "absent"
	}
	return fmt.Sprintf("%d", value)
}

func framesWithDirection(response map[string]any, direction string) []map[string]any {
	list, _ := response["frames"].([]any)
	out := []map[string]any{}
	for _, entry := range list {
		frame, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if got, _ := frame["direction"].(string); got == direction {
			out = append(out, frame)
		}
	}
	return out
}

func eventsWithType(response map[string]any, eventType string) []map[string]any {
	list, _ := response["events"].([]any)
	out := []map[string]any{}
	for _, entry := range list {
		event, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if got, _ := event["type"].(string); got == eventType {
			out = append(out, event)
		}
	}
	return out
}
