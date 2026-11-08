use fxprof_processed_profile::{
    CategoryHandle, MarkerFieldFlags, MarkerFieldFormat, MarkerLocations, Profile,
    StaticSchemaMarker, StaticSchemaMarkerField, StringHandle,
};

/// Marks when a process was alive
pub(super) struct ProcessLifetimeMarker {
    pub(super) name: StringHandle,
    pub(super) pid: u32,
}

impl StaticSchemaMarker for ProcessLifetimeMarker {
    const UNIQUE_MARKER_TYPE_NAME: &'static str = "ProcessLifetime";
    // Only the pid fits into the boxes of short-lived processes
    const CHART_LABEL: Option<&'static str> = Some("{marker.data.pid}");
    const TOOLTIP_LABEL: Option<&'static str> = Some("{marker.name} {marker.data.pid}");
    const TABLE_LABEL: Option<&'static str> = Some("{marker.name} {marker.data.pid}");
    const FIELDS: &'static [StaticSchemaMarkerField] = &[StaticSchemaMarkerField {
        key: "pid",
        label: "PID",
        format: MarkerFieldFormat::Integer,
        flags: MarkerFieldFlags::empty(),
    }];

    fn name(&self, _profile: &mut Profile) -> StringHandle {
        self.name
    }

    fn category(&self, _profile: &mut Profile) -> CategoryHandle {
        CategoryHandle::OTHER
    }

    fn string_field_value(&self, _field_index: u32) -> StringHandle {
        unreachable!("the marker has no string fields")
    }

    fn number_field_value(&self, _field_index: u32) -> f64 {
        self.pid as f64
    }
}

/// Marks samples without stacks because capturing them failed. Their resources are still valid.
pub(super) struct StackCaptureFailedMarker {
    pub(super) reason: StringHandle,
    pub(super) details: StringHandle,
}

impl StaticSchemaMarker for StackCaptureFailedMarker {
    const UNIQUE_MARKER_TYPE_NAME: &'static str = "StackCaptureFailed";
    const DESCRIPTION: Option<&'static str> =
        Some("The stacks of these samples could not be captured, only their resources");
    const LOCATIONS: MarkerLocations = MarkerLocations::MARKER_CHART
        .union(MarkerLocations::MARKER_TABLE)
        .union(MarkerLocations::TIMELINE_OVERVIEW);
    const CHART_LABEL: Option<&'static str> = Some("{marker.data.reason}");
    const TOOLTIP_LABEL: Option<&'static str> = Some("Stack capture failed: {marker.data.reason}");
    const TABLE_LABEL: Option<&'static str> = Some("{marker.data.reason}");
    const FIELDS: &'static [StaticSchemaMarkerField] = &[
        StaticSchemaMarkerField {
            key: "reason",
            label: "Reason",
            format: MarkerFieldFormat::String,
            flags: MarkerFieldFlags::SEARCHABLE,
        },
        StaticSchemaMarkerField {
            key: "details",
            label: "Last error",
            format: MarkerFieldFormat::String,
            flags: MarkerFieldFlags::empty(),
        },
    ];

    fn name(&self, profile: &mut Profile) -> StringHandle {
        profile.intern_string("Stack capture failed")
    }

    fn category(&self, _profile: &mut Profile) -> CategoryHandle {
        CategoryHandle::OTHER
    }

    fn string_field_value(&self, field_index: u32) -> StringHandle {
        match field_index {
            0 => self.reason,
            _ => self.details,
        }
    }

    fn number_field_value(&self, _field_index: u32) -> f64 {
        unreachable!("the marker has no number fields")
    }
}

/// Marks samples the profiler skipped because it fell behind, e.g. because capturing the stacks
/// took longer than the interval
pub(super) struct SkippedTicksMarker {
    pub(super) skipped: u64,
}

impl StaticSchemaMarker for SkippedTicksMarker {
    const UNIQUE_MARKER_TYPE_NAME: &'static str = "SkippedTicks";
    const DESCRIPTION: Option<&'static str> =
        Some("The profiler fell behind and took no samples in this range");
    const LOCATIONS: MarkerLocations = MarkerLocations::MARKER_CHART
        .union(MarkerLocations::MARKER_TABLE)
        .union(MarkerLocations::TIMELINE_OVERVIEW);
    const CHART_LABEL: Option<&'static str> = Some("{marker.data.skipped}");
    const TOOLTIP_LABEL: Option<&'static str> = Some("Skipped {marker.data.skipped} samples");
    const TABLE_LABEL: Option<&'static str> = Some("Skipped {marker.data.skipped} samples");
    const FIELDS: &'static [StaticSchemaMarkerField] = &[StaticSchemaMarkerField {
        key: "skipped",
        label: "Skipped samples",
        format: MarkerFieldFormat::Integer,
        flags: MarkerFieldFlags::empty(),
    }];

    fn name(&self, profile: &mut Profile) -> StringHandle {
        profile.intern_string("Skipped samples")
    }

    fn category(&self, _profile: &mut Profile) -> CategoryHandle {
        CategoryHandle::OTHER
    }

    fn string_field_value(&self, _field_index: u32) -> StringHandle {
        unreachable!("the marker has no string fields")
    }

    fn number_field_value(&self, _field_index: u32) -> f64 {
        self.skipped as f64
    }
}
