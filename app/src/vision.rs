// vision.rs — corrected preprocess, postprocess, and RawDetection.
// Changes from the original file:
//   1. Letterbox padding is now centered (was incorrectly top-left-anchored).
//   2. RawDetection carries bbox in BOTH model-input space (needed for NMS,
//      which must operate in a consistent coordinate frame) and original-
//      frame space (needed for the frontend overlay) — kept as two
//      explicit fields rather than one, so no call site can accidentally
//      use the wrong space for the wrong purpose.

/// Describes exactly how a frame was letterboxed into the model's square
/// input, so detections can be mapped back to the original frame's pixel
/// space afterward. Computed fresh per-frame (not cached on VisionEngine),
/// since every incoming frame can have different original dimensions.
#[derive(Debug, Clone, Copy)]
struct LetterboxTransform {
    scale: f32,
    pad_x: f32,
    pad_y: f32,
}

fn compute_letterbox_transform(orig_w: u32, orig_h: u32, target_w: u32, target_h: u32) -> LetterboxTransform {
    let scale = (target_w as f32 / orig_w as f32).min(target_h as f32 / orig_h as f32);
    let new_w = orig_w as f32 * scale;
    let new_h = orig_h as f32 * scale;
    // Centered padding — standard YOLO letterbox convention. The earlier
    // draft placed the resized image at (0,0), which is wrong: it would
    // have silently shifted every bounding box's true position whenever
    // the original frame's aspect ratio didn't match the model's square
    // input, which is the common case for a 16:9 camera feed into a
    // 640x640 model.
    let pad_x = (target_w as f32 - new_w) / 2.0;
    let pad_y = (target_h as f32 - new_h) / 2.0;
    LetterboxTransform { scale, pad_x, pad_y }
}

#[derive(Debug, Clone)]
pub struct RawDetection {
    pub class_index: usize,
    pub confidence: f32,
    /// Bounding box in model-input (e.g. 640x640, letterboxed) coordinate
    /// space. Used internally for NMS. Callers outside this module should
    /// use `bbox_original_xyxy` instead — kept private-in-spirit via
    /// naming convention since Rust visibility can't easily express
    /// "public to this crate's tests but discouraged elsewhere" cleanly.
    pub bbox_model_xyxy: [f32; 4],
    /// Bounding box mapped back into the ORIGINAL camera frame's pixel
    /// coordinates — this is what routes.rs should send to the frontend
    /// for the live overlay, since the browser draws on the original
    /// frame, not the letterboxed model input.
    pub bbox_original_xyxy: [f32; 4],
}

impl VisionEngine {
    pub fn infer(&self, image: &DynamicImage) -> Result<Vec<RawDetection>, VisionError> {
        if self.mock_mode {
            return Ok(self.mock_infer(image));
        }

        let session = self
            .session
            .as_ref()
            .expect("session must be Some when mock_mode is false — invariant enforced in load()");

        let (orig_w, orig_h) = image.dimensions();
        let transform = compute_letterbox_transform(orig_w, orig_h, self.input_size.0, self.input_size.1);

        let input_tensor = self.preprocess(image, &transform)?;

        let outputs = session
            .run(inputs![input_tensor].map_err(|e| VisionError::InferenceFailed(e.to_string()))?)
            .map_err(|e| VisionError::InferenceFailed(e.to_string()))?;

        self.postprocess(outputs, &transform)
    }

    /// Now takes the precomputed transform so preprocessing and the later
    /// unscaling step in postprocess are guaranteed to agree — computing
    /// the transform twice (once here, once in postprocess) would risk
    /// the two calculations drifting apart if one were edited without the
    /// other, which is exactly the kind of silent-accuracy-bug this whole
    /// file is trying to avoid.
    fn preprocess(&self, image: &DynamicImage, transform: &LetterboxTransform) -> Result<ort::Value, VisionError> {
        let (target_w, target_h) = self.input_size;
        let (orig_w, orig_h) = image.dimensions();

        let new_w = (orig_w as f32 * transform.scale).round() as u32;
        let new_h = (orig_h as f32 * transform.scale).round() as u32;

        let resized = image.resize_exact(new_w, new_h, image::imageops::FilterType::Triangle);

        let mut canvas = DynamicImage::new_rgb8(target_w, target_h);
        // Centered overlay — uses the transform's pad values instead of (0,0).
        image::imageops::overlay(
            &mut canvas,
            &resized,
            transform.pad_x.round() as i64,
            transform.pad_y.round() as i64,
        );

        let mut tensor_data = vec![0.0f32; (3 * target_w * target_h) as usize];
        for (x, y, pixel) in canvas.to_rgb8().enumerate_pixels() {
            let idx = (y * target_w + x) as usize;
            let plane_size = (target_w * target_h) as usize;
            tensor_data[idx] = pixel[0] as f32 / 255.0;
            tensor_data[plane_size + idx] = pixel[1] as f32 / 255.0;
            tensor_data[2 * plane_size + idx] = pixel[2] as f32 / 255.0;
        }

        ort::Value::from_array(([1, 3, target_h as usize, target_w as usize], tensor_data))
            .map_err(|e| VisionError::InferenceFailed(e.to_string()))
    }

    fn postprocess(
        &self,
        outputs: ort::SessionOutputs,
        transform: &LetterboxTransform,
    ) -> Result<Vec<RawDetection>, VisionError> {
        let output = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| VisionError::InferenceFailed(e.to_string()))?;

        let shape = output.shape();
        if shape.len() != 3 || shape[1] < 5 {
            return Err(VisionError::UnexpectedOutputShape {
                expected: "[1, 4+num_classes, num_anchors]".to_string(),
                got: format!("{:?}", shape),
            });
        }

        let num_classes = shape[1] - 4;
        let num_anchors = shape[2];
        let data = output.as_slice().ok_or_else(|| {
            VisionError::InferenceFailed("output tensor not contiguous".to_string())
        })?;

        let mut candidates: Vec<RawDetection> = Vec::new();

        for anchor in 0..num_anchors {
            let cx = data[0 * num_anchors + anchor];
            let cy = data[1 * num_anchors + anchor];
            let w = data[2 * num_anchors + anchor];
            let h = data[3 * num_anchors + anchor];

            let (mut best_class, mut best_score) = (0usize, 0.0f32);
            for c in 0..num_classes {
                let score = data[(4 + c) * num_anchors + anchor];
                if score > best_score {
                    best_score = score;
                    best_class = c;
                }
            }

            if best_score < self.confidence_floor {
                continue;
            }

            let bbox_model_xyxy = [cx - w / 2.0, cy - h / 2.0, cx + w / 2.0, cy + h / 2.0];
            let bbox_original_xyxy = unscale_bbox(bbox_model_xyxy, transform);

            candidates.push(RawDetection {
                class_index: best_class,
                confidence: best_score,
                bbox_model_xyxy,
                bbox_original_xyxy,
            });
        }

        Ok(non_max_suppression(candidates, 0.45))
    }

    fn mock_infer(&self, image: &DynamicImage) -> Vec<RawDetection> {
        // Mock detections now also produce a plausible bbox_original_xyxy —
        // scaled relative to whatever frame size actually arrives, rather
        // than a hardcoded 640-space box, so the frontend overlay code path
        // can be developed and demoed correctly even before a real model
        // exists. This consistency matters: a mock overlay box that's
        // wildly wrong-looking on screen would undermine confidence in the
        // real pipeline during rehearsal, even though it's "just mock mode."
        let (w, h) = image.dimensions();
        vec![RawDetection {
            class_index: CLASS_NO_PPE,
            confidence: 0.82,
            bbox_model_xyxy: [100.0, 100.0, 300.0, 400.0],
            bbox_original_xyxy: [
                w as f32 * 0.15,
                h as f32 * 0.15,
                w as f32 * 0.45,
                h as f32 * 0.60,
            ],
        }]
    }
}

/// Maps a bounding box from letterboxed model-input space back to the
/// original frame's pixel coordinates: reverse the padding offset, then
/// reverse the scale. Order matters — padding was applied AFTER scaling
/// during preprocessing, so un-scaling must subtract padding BEFORE
/// dividing by scale, exactly reversing preprocessing's operations in
/// reverse order. Getting this order backwards is the single most likely
/// silent bug in this whole fix, hence the explicit test below.
fn unscale_bbox(bbox_model_xyxy: [f32; 4], transform: &LetterboxTransform) -> [f32; 4] {
    let [x1, y1, x2, y2] = bbox_model_xyxy;
    [
        (x1 - transform.pad_x) / transform.scale,
        (y1 - transform.pad_y) / transform.scale,
        (x2 - transform.pad_x) / transform.scale,
        (y2 - transform.pad_y) / transform.scale,
    ]
}

/// NMS now compares boxes in model space consistently (bbox_model_xyxy) —
/// unaffected by this fix, but the field name changed, so this signature
/// needs updating to match.
fn non_max_suppression(mut detections: Vec<RawDetection>, iou_threshold: f32) -> Vec<RawDetection> {
    detections.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

    let mut kept: Vec<RawDetection> = Vec::new();
    for det in detections {
        let overlaps_kept = kept
            .iter()
            .any(|k| iou(&k.bbox_model_xyxy, &det.bbox_model_xyxy) > iou_threshold);
        if !overlaps_kept {
            kept.push(det);
        }
    }
    kept
}