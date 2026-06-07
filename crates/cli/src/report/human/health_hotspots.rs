use std::path::Path;

use colored::Colorize;

use super::{plural, relative_path, split_dir_filename};

const DOCS_HEALTH: &str = "https://docs.fallow.tools/explanations/health";

fn render_ownership_summary(report: &crate::health_types::HealthReport) -> Option<String> {
    if report.hotspots.len() < 2 {
        return None;
    }
    let with_ownership: Vec<&crate::health_types::OwnershipMetrics> = report
        .hotspots
        .iter()
        .filter_map(|h| h.ownership.as_ref())
        .collect();
    if with_ownership.is_empty() {
        return None;
    }

    let total = with_ownership.len();
    let bus1_count = with_ownership.iter().filter(|o| o.bus_factor == 1).count();

    let mut tally: rustc_hash::FxHashMap<String, u32> = rustc_hash::FxHashMap::default();
    for o in &with_ownership {
        *tally
            .entry(o.top_contributor.identifier.clone())
            .or_insert(0) += 1;
    }
    let mut ranked: Vec<(String, u32)> = tally.into_iter().collect();
    ranked.sort_by_key(|b| std::cmp::Reverse(b.1));
    let top_authors: Vec<String> = ranked
        .iter()
        .take(3)
        .map(|(id, n)| format!("{id} ({n})"))
        .collect();

    let mut segments: Vec<String> = Vec::new();
    if bus1_count > 0 {
        let label = if bus1_count == total {
            format!("all {total} hotspots depend on a single recent contributor")
        } else {
            format!("{bus1_count}/{total} hotspots depend on a single recent contributor")
        };
        segments.push(label.red().bold().to_string());
    }
    if !top_authors.is_empty() {
        segments.push(
            format!("top authors: {}", top_authors.join(", "))
                .dimmed()
                .to_string(),
        );
    }

    if segments.is_empty() {
        None
    } else {
        Some(segments.join("  ·  "))
    }
}

fn handle_matches_owner(identifier: &str, declared_owner: &str) -> bool {
    let owner_handle = declared_owner.trim_start_matches('@');
    if owner_handle.is_empty() || identifier.is_empty() {
        return false;
    }
    let id_handle = identifier.split('@').next().unwrap_or(identifier);
    let id_handle = id_handle.split('+').next_back().unwrap_or(id_handle);
    id_handle.eq_ignore_ascii_case(owner_handle)
}

fn render_ownership_line(
    ownership: &crate::health_types::OwnershipMetrics,
    trend: fallow_core::churn::ChurnTrend,
) -> String {
    let mut parts: Vec<String> = Vec::new();

    let top_share = ownership.top_contributor.share;
    let is_accelerating = matches!(trend, fallow_core::churn::ChurnTrend::Accelerating);
    let is_extreme = top_share >= 0.9 || (ownership.bus_factor == 1 && is_accelerating);
    let bus_str = if top_share >= 0.9999 {
        format!("bus={} (sole author)", ownership.bus_factor)
    } else if ownership.bus_factor <= 1 && is_extreme {
        format!("bus={} (at risk)", ownership.bus_factor)
    } else {
        format!("bus={}", ownership.bus_factor)
    };
    let bus_colored = if is_extreme {
        bus_str.red().bold().to_string()
    } else if ownership.bus_factor <= 1 {
        bus_str.yellow().to_string()
    } else {
        bus_str.dimmed().to_string()
    };
    parts.push(bus_colored);

    let top = &ownership.top_contributor;
    let collapsed = ownership
        .declared_owner
        .as_deref()
        .filter(|owner| handle_matches_owner(&top.identifier, owner));
    if let Some(owner) = collapsed {
        parts.push(
            format!(
                "owned by {} ({:.0}%, declared {})",
                top.identifier,
                top.share * 100.0,
                owner,
            )
            .dimmed()
            .to_string(),
        );
    } else {
        parts.push(
            format!("top={} ({:.0}%)", top.identifier, top.share * 100.0)
                .dimmed()
                .to_string(),
        );
        if let Some(owner) = &ownership.declared_owner {
            parts.push(format!("owner={owner}").dimmed().to_string());
        }
    }

    if ownership.unowned == Some(true) {
        parts.push("unowned".red().to_string());
    }

    if ownership.ownership_state == crate::health_types::OwnershipState::DeclaredInactive {
        parts.push("declared owner inactive".yellow().to_string());
    }

    if ownership.drift {
        parts.push("drift".yellow().to_string());
    }

    parts.join("  ")
}

pub(super) fn render_hotspots(
    lines: &mut Vec<String>,
    report: &crate::health_types::HealthReport,
    root: &Path,
) {
    if report.hotspots.is_empty() {
        return;
    }

    let header = report.hotspot_summary.as_ref().map_or_else(
        || format!("Hotspots ({} files)", report.hotspots.len()),
        |summary| {
            format!(
                "Hotspots ({} files, since {})",
                report.hotspots.len(),
                summary.since,
            )
        },
    );
    lines.push(format!("{} {}", "\u{25cf}".red(), header.red().bold()));
    lines.push(String::new());

    if let Some(summary_line) = render_ownership_summary(report) {
        lines.push(format!("  {summary_line}"));
        lines.push(String::new());
    }

    for entry in &report.hotspots {
        let file_str = relative_path(&entry.path, root).display().to_string();

        let score_str = format!("{:>5.1}", entry.score);
        let score_colored = if entry.score >= 70.0 {
            score_str.red().bold().to_string()
        } else if entry.score >= 30.0 {
            score_str.yellow().to_string()
        } else {
            score_str.green().to_string()
        };

        let (trend_symbol, trend_colored) = match entry.trend {
            fallow_core::churn::ChurnTrend::Accelerating => {
                ("\u{25b2}", "\u{25b2} accelerating".red().to_string())
            }
            fallow_core::churn::ChurnTrend::Cooling => {
                ("\u{25bc}", "\u{25bc} cooling".green().to_string())
            }
            fallow_core::churn::ChurnTrend::Stable => {
                ("\u{2500}", "\u{2500} stable".dimmed().to_string())
            }
        };

        let (dir, filename) = split_dir_filename(&file_str);

        let test_tag = if entry.is_test_path {
            format!(" {}", "[test]".dimmed())
        } else {
            String::new()
        };
        lines.push(format!(
            "  {} {}  {}{}{}",
            score_colored,
            match entry.trend {
                fallow_core::churn::ChurnTrend::Accelerating => trend_symbol.red().to_string(),
                fallow_core::churn::ChurnTrend::Cooling => trend_symbol.green().to_string(),
                fallow_core::churn::ChurnTrend::Stable => trend_symbol.dimmed().to_string(),
            },
            dir.dimmed(),
            filename,
            test_tag,
        ));

        lines.push(format!(
            "         {} commits  {} churn  {} density  {} fan-in  {}",
            format!("{:>3}", entry.commits).dimmed(),
            format!("{:>5}", entry.lines_added + entry.lines_deleted).dimmed(),
            format!("{:.2}", entry.complexity_density).dimmed(),
            format!("{:>2}", entry.fan_in).dimmed(),
            trend_colored,
        ));

        if let Some(ownership) = &entry.ownership {
            lines.push(format!(
                "         {}",
                render_ownership_line(ownership, entry.trend)
            ));
        }

        lines.push(String::new());
    }

    if let Some(ref summary) = report.hotspot_summary
        && summary.files_excluded > 0
    {
        lines.push(format!(
            "  {}",
            format!(
                "{} file{} excluded (< {} commits)",
                summary.files_excluded,
                plural(summary.files_excluded),
                summary.min_commits,
            )
            .dimmed()
        ));
        lines.push(String::new());
    }
    let any_ownership = report.hotspots.iter().any(|h| h.ownership.is_some());
    let no_codeowners_anywhere = report
        .hotspots
        .iter()
        .filter_map(|h| h.ownership.as_ref())
        .all(|o| o.unowned.is_none());
    if any_ownership && no_codeowners_anywhere {
        lines.push(format!(
            "  {}",
            "No CODEOWNERS file discovered, ownership signals limited to change history.".dimmed()
        ));
    }
    lines.push(format!(
        "  {}",
        format!("Files with high churn and high complexity: {DOCS_HEALTH}#hotspot-metrics")
            .dimmed()
    ));
    lines.push(String::new());
}
