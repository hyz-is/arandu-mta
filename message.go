package mta

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Priority orders the messages of one destination domain. A lower value is
// delivered first.
type Priority uint8

const (
	// PriorityTransactional is the mail a person is waiting for: a password
	// reset, a receipt, a sign-in code. It is delivered before marketing mail
	// queued for the same domain.
	PriorityTransactional Priority = 0
	// PriorityMarketing is bulk mail. It never delays transactional mail.
	PriorityMarketing Priority = 1
)

// priorityLevels is the number of distinct priorities the queues keep apart.
const priorityLevels = 2

// String returns "transactional" or "marketing".
func (p Priority) String() string {
	switch p {
	case PriorityTransactional:
		return "transactional"
	case PriorityMarketing:
		return "marketing"
	}
	return fmt.Sprintf("priority(%d)", uint8(p))
}

// ParsePriority reads "transactional" or "marketing", in any case. The empty
// string is PriorityTransactional.
func ParsePriority(s string) (Priority, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "transactional":
		return PriorityTransactional, nil
	case "marketing":
		return PriorityMarketing, nil
	}
	return 0, fmt.Errorf("mta: unknown priority %q", s)
}

// RecipientState is where one recipient of a message stands.
type RecipientState uint8

const (
	// StateQueued means no attempt has been made yet.
	StateQueued RecipientState = iota
	// StateDeferred means a delivery attempt failed with a temporary error and
	// another is scheduled.
	StateDeferred
	// StateDelivered means the remote server answered 250 for the recipient.
	StateDelivered
	// StateBounced means the recipient will never receive the message: a
	// permanent failure, a suppression, or the end of the retry window.
	StateBounced
	// StateFailed means an internal error ended the recipient's delivery.
	StateFailed
	// StateCancelled means the sender cancelled the recipient before delivery.
	StateCancelled
	// StateSending means a delivery attempt is running now. It is never written
	// to the spool: after a restart the recipient is queued again.
	StateSending
)

var recipientStateNames = [...]string{"queued", "deferred", "delivered", "bounced", "failed", "cancelled", "sending"}

// String returns the lower-case name of the state.
func (s RecipientState) String() string {
	if int(s) < len(recipientStateNames) {
		return recipientStateNames[s]
	}
	return fmt.Sprintf("state(%d)", uint8(s))
}

// Terminal reports whether the recipient will not be attempted again.
func (s RecipientState) Terminal() bool {
	return s == StateDelivered || s == StateBounced || s == StateFailed || s == StateCancelled
}

// Pending reports whether the recipient still waits for an attempt.
func (s RecipientState) Pending() bool { return s == StateQueued || s == StateDeferred }

// Recipient is one envelope recipient with its own delivery state.
type Recipient struct {
	// Address is the bare address, local@domain, without angle brackets.
	Address string `json:"a"`
	// Domain is the lower-case domain of Address; Submit fills it.
	Domain string `json:"d,omitempty"`
	// State is where the recipient stands.
	State RecipientState `json:"s,omitempty"`
	// Attempts is how many delivery attempts reached a remote answer or failed
	// for this recipient.
	Attempts int `json:"n,omitempty"`
	// NextAttempt is when the next attempt is due; the zero time when none is.
	NextAttempt time.Time `json:"t,omitzero"`
	// LastCode is the last SMTP code seen for the recipient, 0 when none.
	LastCode int `json:"c,omitempty"`
	// LastEnhanced is the last enhanced status code, such as "5.1.1".
	LastEnhanced string `json:"e,omitempty"`
	// LastText is the text of the last reply.
	LastText string `json:"x,omitempty"`
	// LastMX is the exchanger that gave the last reply.
	LastMX string `json:"m,omitempty"`
	// UpdatedAt is when the state last changed.
	UpdatedAt time.Time `json:"u,omitzero"`
}

// Message is one email in the spool: one envelope, one body, and the state of
// each recipient.
type Message struct {
	// ID identifies the message; it is the application's idempotency key and
	// must be unique within the spool. Letters, digits and "._-" only, because
	// it names a file.
	ID string `json:"id"`
	// Tenant is the organization that owns the message.
	Tenant string `json:"tenant,omitempty"`
	// MailFrom is the envelope sender, the address bounces return to. It may be
	// empty for a null sender.
	MailFrom string `json:"from,omitempty"`
	// Recipients are the envelope recipients.
	Recipients []Recipient `json:"rcpt"`
	// Data is the complete RFC 5322 message, signed when the application signs.
	// The spool keeps it apart from the metadata, and Load returns messages
	// without it.
	Data []byte `json:"-"`
	// Size is len(Data); the spool keeps it with the metadata.
	Size int `json:"size,omitempty"`
	// Priority orders the message among the others queued for a domain.
	Priority Priority `json:"prio,omitempty"`
	// IPPool names the pool whose addresses may send the message.
	IPPool string `json:"pool,omitempty"`
	// DKIMDomain is the domain the Signer signs the message for.
	DKIMDomain string `json:"dkim,omitempty"`
	// Attempts counts the delivery rounds of the message.
	Attempts int `json:"n,omitempty"`
	// NextAttempt is the earliest due time of a pending recipient; the zero time
	// once the message is complete.
	NextAttempt time.Time `json:"next,omitzero"`
	// CreatedAt is when the engine accepted the message.
	CreatedAt time.Time `json:"created"`
	// ExpiresAt is when the engine stops retrying and bounces what is left.
	// Submit sets it to the time of acceptance plus Config.Expiry, unless the
	// caller gave a time.
	ExpiresAt time.Time `json:"expires"`
}

// Clone returns a deep copy of the metadata. Data is shared, never copied: it
// is immutable once spooled.
func (m *Message) Clone() *Message {
	c := *m
	c.Recipients = append([]Recipient(nil), m.Recipients...)
	return &c
}

// Complete reports whether every recipient is in a terminal state.
func (m *Message) Complete() bool {
	for i := range m.Recipients {
		if !m.Recipients[i].State.Terminal() {
			return false
		}
	}
	return true
}

// recompute refreshes NextAttempt from the recipients.
func (m *Message) recompute() {
	var next time.Time
	for i := range m.Recipients {
		r := &m.Recipients[i]
		if !r.State.Pending() {
			continue
		}
		if next.IsZero() || r.NextAttempt.Before(next) {
			next = r.NextAttempt
		}
	}
	m.NextAttempt = next
}

// Errors returned by Submit and the spool.
var (
	// ErrInvalidMessage wraps every reason Submit refuses a message.
	ErrInvalidMessage = errors.New("mta: invalid message")
	// ErrInvalidAddress is an envelope address the engine cannot put on the wire.
	ErrInvalidAddress = errors.New("mta: invalid address")
	// ErrDuplicate means a message with that ID is already queued.
	ErrDuplicate = errors.New("mta: duplicate message id")
	// ErrNotFound means no queued message has that ID.
	ErrNotFound = errors.New("mta: message not found")
	// ErrNotCancellable means every recipient is already in a terminal state.
	ErrNotCancellable = errors.New("mta: message has nothing left to cancel")
	// ErrClosed means the engine no longer accepts messages.
	ErrClosed = errors.New("mta: engine is shut down")
	// ErrNotStarted means Start has not run.
	ErrNotStarted = errors.New("mta: engine is not started")
)

// ValidID reports whether id is usable as a message identifier: 1 to 128 of
// letters, digits, '.', '_' and '-', not starting with '.'.
func ValidID(id string) bool {
	if len(id) == 0 || len(id) > 128 || id[0] == '.' {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// DomainOf returns the lower-case domain of an envelope address, without a
// trailing dot, and false when the address has none. The domain is the text
// after the last '@'.
func DomainOf(addr string) (string, bool) {
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 || at == len(addr)-1 {
		return "", false
	}
	d := addr[at+1:]
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return "", false
	}
	return strings.ToLower(d), true
}

// ValidAddress checks an envelope address, local@domain, for what the wire
// protocol forbids: control characters, spaces, angle brackets, a missing part
// or a part that is too long. It does not judge whether the mailbox exists.
func ValidAddress(addr string) error {
	if len(addr) > 254 {
		return fmt.Errorf("%w: longer than 254 bytes", ErrInvalidAddress)
	}
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 || at == len(addr)-1 {
		return fmt.Errorf("%w: need local@domain", ErrInvalidAddress)
	}
	if at > 64 {
		return fmt.Errorf("%w: local part longer than 64 bytes", ErrInvalidAddress)
	}
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		if c <= ' ' || c == 0x7f || c == '<' || c == '>' || c == '\\' || c == '"' {
			return fmt.Errorf("%w: byte 0x%02x not allowed", ErrInvalidAddress, c)
		}
	}
	domain := addr[at+1:]
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" || len(domain) > 253 || domain[0] == '.' || domain[0] == '-' || strings.Contains(domain, "..") || strings.ContainsAny(domain, "[]@") {
		return fmt.Errorf("%w: bad domain", ErrInvalidAddress)
	}
	return nil
}

// hasNonASCII reports whether s holds a byte outside 7-bit ASCII.
func hasNonASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return true
		}
	}
	return false
}
