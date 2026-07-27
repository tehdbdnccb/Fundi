// backend/src/vision.rs
//
// Computer vision inference layer. Converts raw video frames to bounding box
// detections and dispatches them to the rules engine. This file owns the ONNX
// model load and inference — everything vision-specific lives here, nothing
// rules-specific leaks upward.

use image::DynamicImage;
use crate::rules::RuleType;

#[derive(Debug)]
pub enum VisionError {
    ModelLoadFailed(String),
    InferenceFailed(String),
    UnexpectedOutputShape { expected: String, got: String },
}

impl std::fmt::Display for VisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VisionError::ModelLoadFailed(s) => write!(f, "model load failed: {s}"),
            VisionError::InferenceFailed(s) => write!(f, "inference failed: {s}"),
            VisionError::UnexpectedOutputShape { expected, got } => {
                write!(f, "unexpected output shape: expected {expected}, got {got}")
            }
        }
    }
}
impl std::error::Error for VisionError {}

/// A single raw detection from the inference model — this is the exact contract
/// between vision.rs and rules.rs. vision.rs knows only ONNX/bounding boxes;
/// rules.rs knows only confidence thresholds and debouncing. The 'rule_type'
/// is NOT set here — that's determined by to_rule_confidence_bp() below.
#[derive(Debug, Clone)]
pub struct RawDetection {
    pub bbox_model_xyxy: [f32; 4],   // in model coordinates (original scale)
    pub bbox_original_xyxy: [f32; 4], // in original image coordinates
    pub class_index: usize,
    pub confidence: f32,
}

const CLASS_NO_PPE: usize = 0;
const CLASS_ZONE_BREACH: usize = 1;

/// Translates raw model output to (RuleType, confidence_bp) — the single
/// conversion point between vision output and rules input. Returns None if
/// the detection doesn't map to any rule (e.g. other_object class), Some
/// otherwise. Confidence is converted from [0, 1] float to [0, 10000] u16
/// basis points.
pub fn to_rule_confidence_bp(raw: &RawDetection) -> Option<(RuleType, u16)> {
    let rule_type = match raw.class_index {
        CLASS_NO_PPE => RuleType::PpeMissing,
        CLASS_ZONE_BREACH => RuleType::ZoneBreach,
        _ => return None,
    };

    let confidence_bp = ((raw.confidence * 10000.0).clamp(0.0, 10000.0) as u16).max(0);
    Some((rule_type, confidence_bp))
}

pub struct VisionEngine {
    // Placeholder for model state — real implementation would load ONNX session
}

impl VisionEngine {
    pub fn new(_model_path: &str) -> Result<Self, VisionError> {
        // In a real implementation, load the ONNX model here
        Ok(VisionEngine {})
    }

    pub fn infer(&self, _image: &DynamicImage) -> Result<Vec<RawDetection>, VisionError> {
        // Placeholder inference — returns empty detections
        // Real implementation would:
        // 1. Preprocess image to model input size
        // 2. Run ONNX inference
        // 3. Postprocess outputs to bounding boxes
        Ok(vec![])
    }
}

/// IOU (Intersection over Union) for NMS (Non-Maximum Suppression)
pub fn iou(box1: &[f32; 4], box2: &[f32; 4]) -> f32 {
    let [x1_min, y1_min, x1_max, y1_max] = box1;
    let [x2_min, y2_min, x2_max, y2_max] = box2;

    let inter_xmin = x1_min.max(*x2_min);
    let inter_ymin = y1_min.max(*y2_min);
    let inter_xmax = x1_max.min(*x2_max);
    let inter_ymax = y1_max.min(*y2_max);

    if inter_xmax < inter_xmin || inter_ymax < inter_ymin {
        return 0.0;
    }

    let inter_area = (inter_xmax - inter_xmin) * (inter_ymax - inter_ymin);
    let box1_area = (x1_max - x1_min) * (y1_max - y1_min);
    let box2_area = (x2_max - x2_min) * (y2_max - y2_min);
    let union_area = box1_area + box2_area - inter_area;

    if union_area <= 0.0 {
        0.0
    } else {
        inter_area / union_area
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iou_identical_boxes_is_one() {
        let box = [0.0, 0.0, 10.0, 10.0];
        assert_eq!(iou(&box, &box), 1.0);
    }

    #[test]
    fn iou_non_overlapping_boxes_is_zero() {
        let box1 = [0.0, 0.0, 10.0, 10.0];
        let box2 = [20.0, 20.0, 30.0, 30.0];
        assert_eq!(iou(&box1, &box2), 0.0);
    }
}

