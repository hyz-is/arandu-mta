package mta

import (
	"strings"
)

// BounceType is the top-level kind of a bounce, named as Amazon SES names it
// because the application stores and exposes these names.
type BounceType string

// SES-compatible bounce types.
const (
	BounceUndetermined BounceType = "Undetermined"
	BouncePermanent    BounceType = "Permanent"
	BounceTransient    BounceType = "Transient"
)

// BounceSubType refines a BounceType.
type BounceSubType string

// SES-compatible bounce sub types.
const (
	SubGeneral            BounceSubType = "General"
	SubNoEmail            BounceSubType = "NoEmail"
	SubSuppressed         BounceSubType = "Suppressed"
	SubMailboxFull        BounceSubType = "MailboxFull"
	SubMessageTooLarge    BounceSubType = "MessageTooLarge"
	SubContentRejected    BounceSubType = "ContentRejected"
	SubAttachmentRejected BounceSubType = "AttachmentRejected"
)

// Classification is what a Classifier concludes about one reply.
type Classification struct {
	// Permanent is true when retrying cannot help: the recipient is bounced.
	// False means the failure is temporary and the engine retries.
	Permanent bool
	// Type and SubType describe the bounce in SES terms. For a temporary reply
	// they describe what the bounce would be were the retries to run out.
	Type    BounceType
	SubType BounceSubType
	// Throttle is true when the remote asked the sender to slow down: a 421, a
	// 451 or a 4.7.x reply that is rate limiting rather than a verdict on the
	// message. The engine then backs the destination domain off.
	Throttle bool
}

// DefaultClassifier is the minimal Classifier. It reads the enhanced status
// code first, then the text, then the basic code.
type DefaultClassifier struct{}

// Classify implements Classifier.
func (DefaultClassifier) Classify(code int, enhanced, text string) Classification {
	return ClassifyReply(code, enhanced, text)
}

var (
	noMailboxHints  = []string{"user unknown", "no such user", "unknown user", "does not exist", "doesn't exist", "unknown recipient", "invalid recipient", "recipient rejected", "no mailbox", "mailbox unavailable", "mailbox not found", "address rejected", "no such recipient", "recipient not found", "user not found", "account disabled", "account has been disabled"}
	fullHints       = []string{"mailbox full", "mailbox is full", "over quota", "quota exceeded", "exceeded storage", "insufficient storage", "storage allocation", "out of storage"}
	largeHints      = []string{"message too large", "message size", "too big", "exceeds size", "size limit", "exceeds the limit", "message exceeds"}
	contentHints    = []string{"spam", "blocked", "blacklist", "blocklist", "dnsbl", "reputation", "content rejected", "message content", "policy", "dmarc", "unsolicited", "rejected as", "poor reputation"}
	attachmentHints = []string{"attachment", "executable", "virus", "malware", "infected"}
	throttleHints   = []string{"rate limit", "rate-limit", "ratelimit", "throttl", "too many", "try again later", "temporarily deferred", "temporarily rate", "slow down", "greylist", "greylisted", "come back later", "deferred due to"}
)

func containsAny(lower string, hints []string) bool {
	for _, h := range hints {
		if strings.Contains(lower, h) {
			return true
		}
	}
	return false
}

// ClassifyReply is the function behind DefaultClassifier.
//
// Permanent follows the SMTP class: a 5xx reply is never retried, so the
// recipient is bounced. Type and SubType are the SES names the application
// stores, and they are independent of it: a 552 mailbox-full reply is a
// permanent answer that the application reads as a Transient bounce, one that
// must not suppress the address.
func ClassifyReply(code int, enhanced, text string) Classification {
	lower := strings.ToLower(text)

	class := byte(0)
	switch {
	case len(enhanced) >= 1 && (enhanced[0] == '4' || enhanced[0] == '5' || enhanced[0] == '2'):
		class = enhanced[0]
	case code >= 400 && code < 500:
		class = '4'
	case code >= 500 && code < 600:
		class = '5'
	case code >= 200 && code < 300:
		class = '2'
	}

	if class == '2' {
		return Classification{Type: BounceUndetermined, SubType: SubGeneral}
	}
	if class != '4' && class != '5' {
		return Classification{Type: BounceUndetermined, SubType: SubGeneral}
	}

	c := Classification{Permanent: class == '5', SubType: SubGeneral}
	if c.Permanent {
		c.Type = BouncePermanent
	} else {
		c.Type = BounceTransient
	}

	switch {
	case hasPrefix(enhanced, "5.1.1"), hasPrefix(enhanced, "5.1.2"), hasPrefix(enhanced, "5.1.3"), hasPrefix(enhanced, "5.1.6"), hasPrefix(enhanced, "5.1.10"):
		c.SubType = SubNoEmail
	case hasPrefix(enhanced, "4.2.2"), hasPrefix(enhanced, "5.2.2"):
		c.Type, c.SubType = BounceTransient, SubMailboxFull
	case hasPrefix(enhanced, "5.2.3"), hasPrefix(enhanced, "4.3.4"), hasPrefix(enhanced, "5.3.4"), code == 552 && !containsAny(lower, fullHints) && containsAny(lower, largeHints):
		c.Type, c.SubType = BounceTransient, SubMessageTooLarge
	case hasPrefix(enhanced, "5.6."), hasPrefix(enhanced, "5.7.") && class == '5':
		switch {
		case containsAny(lower, attachmentHints):
			c.SubType = SubAttachmentRejected
		case hasPrefix(enhanced, "5.7.1") || hasPrefix(enhanced, "5.6.") || containsAny(lower, contentHints):
			c.SubType = SubContentRejected
		}
	case class == '5':
		switch {
		case containsAny(lower, fullHints):
			c.Type, c.SubType = BounceTransient, SubMailboxFull
		case containsAny(lower, largeHints):
			c.Type, c.SubType = BounceTransient, SubMessageTooLarge
		case containsAny(lower, noMailboxHints):
			c.SubType = SubNoEmail
		case containsAny(lower, attachmentHints):
			c.SubType = SubAttachmentRejected
		case containsAny(lower, contentHints):
			c.SubType = SubContentRejected
		}
	case class == '4':
		if containsAny(lower, fullHints) {
			c.SubType = SubMailboxFull
		}
	}

	if class == '4' {
		switch {
		case code == 421, code == 451, hasPrefix(enhanced, "4.7."):
			c.Throttle = true
		case (code == 450 || code == 452 || code == 454) && containsAny(lower, throttleHints):
			c.Throttle = true
		case containsAny(lower, throttleHints) && code != 0:
			c.Throttle = true
		}
		// Greylisting asks for a later retry, not for a slower pace.
		if c.Throttle && (hasPrefix(enhanced, "4.2.") || containsAny(lower, []string{"greylist"})) {
			c.Throttle = false
		}
	}
	return c
}

func hasPrefix(s, prefix string) bool {
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	// "5.1.1" must not match "5.1.10" and vice versa: a longer enhanced code
	// has to continue at a boundary.
	return len(s) == len(prefix) || s[len(prefix)] == '.' || prefix[len(prefix)-1] == '.'
}
