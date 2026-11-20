package mta

import (
	"strconv"
	"time"
)

// EventType is what happened to one recipient.
type EventType uint8

const (
	// EventDelivered means the remote exchanger answered 250 to the message.
	EventDelivered EventType = iota + 1
	// EventDeferred means a temporary failure; another attempt is scheduled.
	EventDeferred
	// EventBounced means the recipient will not receive the message: a 5xx
	// answer, a suppression, a null MX, or the end of the retry window.
	EventBounced
	// EventFailed means an internal error ended the delivery.
	EventFailed
)

// String returns the name of the event, as the cluster contract spells it where
// it exists there: DELIVERED, DELIVERY_DELAYED, BOUNCED, FAILED.
func (t EventType) String() string {
	switch t {
	case EventDelivered:
		return "DELIVERED"
	case EventDeferred:
		return "DELIVERY_DELAYED"
	case EventBounced:
		return "BOUNCED"
	case EventFailed:
		return "FAILED"
	}
	return "EVENT(" + strconv.Itoa(int(t)) + ")"
}

// Event reports the outcome of one attempt for one recipient.
type Event struct {
	// ID is unique for the event and stable across a redelivery of it:
	// "<message id>/<recipient index>/<attempt>/<type>".
	ID string
	// Type is the outcome.
	Type EventType
	// MessageID and Tenant identify the message.
	MessageID string
	Tenant    string
	// Recipient is the address the outcome is about.
	Recipient string
	// Time is when the outcome was decided.
	Time time.Time
	// Attempt counts the attempts for this recipient, this one included.
	Attempt int
	// Code, Enhanced and Text are the SMTP reply. Code is 0 when no server
	// answered and the engine has no number to give; Local says so.
	Code     int
	Enhanced string
	Text     string
	// MX is the exchanger that gave the reply; empty when none was reached.
	MX string
	// Local is true when the engine produced the reply itself: a DNS failure, a
	// connection that never opened, a null MX, a suppression, an expired message.
	Local bool
	// NextAttempt is when the next attempt is due; set for EventDeferred.
	NextAttempt time.Time
	// Class is the classification of the reply, set for Deferred and Bounced.
	// For Bounced, Class.Type and Class.SubType are the SES names.
	Class Classification
	// Expired is true for a bounce caused by the end of the retry window.
	Expired bool
	// Suppressed is true for a bounce caused by the SuppressionChecker.
	Suppressed bool
}
