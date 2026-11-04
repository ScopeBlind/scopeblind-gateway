// Synthetic starter: context is assembled by the trusted adapter, never the model.
// A timeout leaves the outcome unknown. The original deadline never slides.
@id("listen-within-fixed-window")
permit(principal, action == Action::"listen", resource)
when { context.timedOut && context.nowMs < context.deadlineMs && !context.operationsOwned };

@id("lookup-after-fixed-window")
permit(principal, action == Action::"lookup", resource)
when { context.timedOut && context.nowMs >= context.deadlineMs };

// Reserve the attempt atomically in the adapter BEFORE dispatch. An error or
// missing reply never frees that reservation. This policy alone stores nothing.
@id("cancel-once-when-booked")
permit(principal, action == Action::"cancel", resource)
when {
    context.cancellationNeeded && context.recordStatus == "booked" &&
    context.cancelAttempts == 0 && context.eventCount == 0 &&
    !context.operationsOwned
};

// Evidence assertion, not a command to the booking system. Event IDs come only
// from statements counted by the upstream signature/role/binding verifier.
@id("confirm-with-counted-event")
permit(principal, action == Action::"confirm_cancel", resource)
when {
    context.confirmationEvidence && context.eventCount > 0 &&
    !context.cancelSignatureBroken && !context.ledgerClaimUnbacked
};

@id("one-distinct-compensation-event")
permit(principal, action == Action::"assert_single_compensation", resource)
when { context.eventCount == 1 };

@id("same-booking-reference")
forbid(principal, action, resource)
when { context.proposedRef != context.bookingRef };
