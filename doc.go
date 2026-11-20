// Package mta is the outbound delivery engine of the Arandu mail stack: it
// accepts messages, keeps them durable, and delivers each recipient to the mail
// exchangers of its domain over SMTP, retrying temporary failures until every
// recipient is delivered or bounced.
//
// It is a library. It registers no route, owns no table and decides no
// authorization. Wiring is explicit: an application builds a Config, calls New
// and Start, and hands messages to Submit. What it does not do itself it asks
// for through small interfaces, so nothing here depends on the MIME, DKIM or
// DSN packages that sit beside it.
//
//	spool, err := mta.OpenDiskSpool("/var/lib/mail/spool", mta.DiskSpoolOptions{})
//	eng, err := mta.New(mta.Config{
//		Spool:       spool,
//		EHLOName:    "mx1.mail.example.com",
//		Signer:      dkimSigner,   // mta.Signer
//		Suppression: suppression,  // mta.SuppressionChecker
//		Events:      outbox,       // mta.EventSink
//		MTASTS:      policies,     // mta.MTASTSPolicySource
//		IPs:         pools,        // *mta.IPPools
//	})
//	err = eng.Start(ctx)
//	err = eng.Submit(ctx, &mta.Message{
//		ID: "email_123", Tenant: "org_1", MailFrom: "bounces+123@mail.example.com",
//		Recipients: []mta.Recipient{{Address: "ana@example.org"}},
//		Data: rfc5322, DKIMDomain: "example.com", Priority: mta.PriorityTransactional,
//	})
//	// later
//	err = eng.Shutdown(ctx)
//
// # Guarantees
//
// A message is durable when Submit returns: it is in the Spool. Delivery is
// at least once. A recipient's state is written to the spool before its Event
// is emitted, so a crash can lose an event but never repeat a delivery for that
// reason; a crash between the remote 250 and the write can repeat one, which no
// SMTP client can avoid. A recipient is Delivered only for a 2xx reply to the
// message from a server.
//
// # What happens to a message
//
// Submit validates the envelope, charges the tenant's rate limit, signs the
// message when a DKIM domain is given, writes it to the spool, and schedules one
// item per destination domain. A worker takes an item, resolves the domain's MX
// records, picks a source address from the message's IP pool, and runs one SMTP
// transaction with every recipient of that domain. Each recipient gets its own
// reply: 2xx delivers, 5xx bounces, 4xx defers and is retried on the Backoff
// schedule until the message expires, when it bounces.
//
// # Hooks
//
// Signer, Classifier, SuppressionChecker, EventSink, MTASTSPolicySource and
// DistributedLimiter are the interfaces the cluster plugs in. Each is optional
// except that without an EventSink nobody learns what happened.
package mta
