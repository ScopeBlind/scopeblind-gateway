/** Current, service-reported attention items. A link is never permission to act. */
export type DecisionKind = 'payment' | 'result' | 'plan' | 'limits' | 'revision' | 'reconcile';
export interface DecisionItem {
  id: string; kind: DecisionKind; room_id: string; principal_key: string;
  title: string; summary: string; action_label: string; href: string;
  target_digest: string; expires_at: string; run_id?: string; session_id?: string;
  operation_id?: string; amount_minor?: number; device_authorization_id?: string;
}
export interface DecisionInbox {
  type: 'scopeblind.coordination.decision-inbox.v1'; device_key: string;
  observed_at: string; items: DecisionItem[]; digest: string; rooms_checked: number;
  truncated: boolean;
}
export const DECISION_ACTIONS = ['decision_inbox','decision_subscribe','decision_unsubscribe','decision_notification_status'] as const;
