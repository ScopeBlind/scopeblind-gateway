/**
 * Prediction Lifecycle Bridge
 *
 * Bridges Veritas Acta prediction receipts to external forecasting
 * platforms (Metaculus, Manifold Markets) for calibration tracking.
 *
 * Status: Experimental
 */

export interface PredictionReceipt {
  receipt_id: string;
  receipt_type: 'prediction';
  issuer_id: string;
  event_time: string;
  payload: {
    claim: string;
    probability: number; // 0.0 to 1.0
    resolution_criteria: string;
    resolution_deadline: string;
    domain?: string;
    tags?: string[];
  };
  signature: string;
}

export interface PredictionResolution {
  receipt_id: string;
  receipt_type: 'resolution';
  parent_receipts: string[]; // references the prediction receipt
  payload: {
    resolved: boolean;
    resolution_value: 'true' | 'false' | 'ambiguous';
    resolution_source: string;
    resolution_time: string;
  };
  signature: string;
}

export interface CalibrationScore {
  total_predictions: number;
  resolved: number;
  brier_score: number; // lower is better, 0.0 = perfect
  calibration_buckets: Array<{
    bucket: string; // e.g., "0.7-0.8"
    predicted_probability: number;
    actual_frequency: number;
    count: number;
  }>;
}

/**
 * Compute Brier score from a set of predictions and their resolutions
 */
export function computeCalibration(
  predictions: PredictionReceipt[],
  resolutions: Map<string, PredictionResolution>
): CalibrationScore {
  let totalSquaredError = 0;
  let resolved = 0;
  const buckets = new Map<string, { sum: number; actual: number; count: number }>();

  for (const pred of predictions) {
    const resolution = resolutions.get(pred.receipt_id);
    if (!resolution || resolution.payload.resolution_value === 'ambiguous') continue;

    resolved++;
    const actual = resolution.payload.resolution_value === 'true' ? 1 : 0;
    const error = (pred.payload.probability - actual) ** 2;
    totalSquaredError += error;

    // Bucket by predicted probability (0.1 increments)
    const bucketKey = `${Math.floor(pred.payload.probability * 10) / 10}-${Math.ceil(pred.payload.probability * 10) / 10}`;
    const bucket = buckets.get(bucketKey) || { sum: 0, actual: 0, count: 0 };
    bucket.sum += pred.payload.probability;
    bucket.actual += actual;
    bucket.count++;
    buckets.set(bucketKey, bucket);
  }

  return {
    total_predictions: predictions.length,
    resolved,
    brier_score: resolved > 0 ? totalSquaredError / resolved : 0,
    calibration_buckets: Array.from(buckets.entries()).map(([bucket, data]) => ({
      bucket,
      predicted_probability: data.sum / data.count,
      actual_frequency: data.actual / data.count,
      count: data.count,
    })),
  };
}

/**
 * Format prediction for Metaculus API submission (placeholder)
 */
export function toMetaculusFormat(prediction: PredictionReceipt): {
  question_url?: string;
  prediction_value: number;
  acta_receipt_id: string;
  acta_signature: string;
} {
  return {
    prediction_value: prediction.payload.probability,
    acta_receipt_id: prediction.receipt_id,
    acta_signature: prediction.signature,
  };
}

/**
 * Format prediction for Manifold Markets API submission (placeholder)
 */
export function toManifoldFormat(prediction: PredictionReceipt): {
  probability: number;
  acta_receipt_id: string;
  acta_signature: string;
} {
  return {
    probability: prediction.payload.probability,
    acta_receipt_id: prediction.receipt_id,
    acta_signature: prediction.signature,
  };
}
