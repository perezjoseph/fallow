//! `fallow security` command: opt-in local security-candidate surface.
//!
//! Ships one graph-structural rule, `client-server-leak`. Findings are
//! CANDIDATES for downstream agent verification, NOT verified vulnerabilities.
//! This command is the ONLY surface for security findings: they never appear
//! under bare `fallow` or the `audit` gate. There is no `confidence` or
//! `signal_strength` field; the structural trace is the only honest signal.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fallow_config::{OutputFormat, ProductionAnalysis, Severity};
use fallow_core::results::{SecurityFinding, SecurityFindingKind, TraceHopRole};
use serde::Serialize;

use crate::error::emit_error;
use crate::load_config_for_analysis;

/// The `fallow security --format json` schema version. Independently versioned
/// from the main contract, mirroring `ImpactReportSchemaVersion`.
#[derive(Debug, Clone, Copy, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum SecuritySchemaVersion {
    /// First release of the `fallow security --format json` shape.
    #[serde(rename = "1")]
    V1,
}

/// The `fallow security --format json` envelope. `security_findings` is the
/// unique required field used for untagged narrowing in `FallowOutput`.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SecurityOutput {
    /// Schema version of this envelope.
    pub schema_version: SecuritySchemaVersion,
    /// Security candidates. Paths are project-root-relative, forward-slash.
    pub security_findings: Vec<SecurityFinding>,
    /// In-band blind spot: number of `"use client"` files whose transitive
    /// import cone contains a dynamic `import()` the reachability BFS could not
    /// follow. A leak hidden behind such an edge would not be reported, so a
    /// zero finding count with a non-zero value here is NOT a clean bill.
    pub unresolved_edge_files: usize,
}

/// Options for `fallow security`, mirroring the global CLI flags it honors.
pub struct SecurityOptions<'a> {
    /// Project root.
    pub root: &'a Path,
    /// Explicit config path (global `--config`).
    pub config_path: &'a Option<PathBuf>,
    /// Output format.
    pub output: OutputFormat,
    /// Disable the extraction cache.
    pub no_cache: bool,
    /// Resolved thread-pool size.
    pub threads: usize,
    /// Suppress progress output.
    pub quiet: bool,
    /// Exit with code 1 when candidates are found.
    pub fail_on_issues: bool,
    /// Write SARIF to a sidecar file in addition to the primary output.
    pub sarif_file: Option<&'a Path>,
    /// Show a compact human summary instead of per-finding detail.
    pub summary: bool,
    /// `--changed-since <ref>`: scope findings to files changed since the ref.
    pub changed_since: Option<&'a str>,
    /// Apply the shared `--diff-file` / `--diff-stdin` line filter.
    pub use_shared_diff_index: bool,
    /// `--workspace <patterns...>`: scope findings to selected workspace roots.
    pub workspace: Option<&'a [String]>,
    /// `--changed-workspaces <ref>`: scope to workspaces with changed files.
    pub changed_workspaces: Option<&'a str>,
}

/// Run `fallow security`. Always exits 0 unless the user explicitly raised the
/// `security-client-server-leak` rule to `error` AND findings exist (the rule
/// defaults to `off` and the command forces it to `warn`, so the common case is
/// advisory). Unsupported output formats exit 2.
#[expect(
    deprecated,
    reason = "ADR-008 deprecates fallow_core::analyze externally; the CLI uses the workspace path dependency"
)]
pub fn run(opts: &SecurityOptions<'_>) -> ExitCode {
    if !matches!(
        opts.output,
        OutputFormat::Human | OutputFormat::Json | OutputFormat::Sarif
    ) {
        return emit_error(
            "fallow security supports --format human, json, or sarif only.",
            2,
            opts.output,
        );
    }

    let mut config = match load_config_for_analysis(
        opts.root,
        opts.config_path,
        opts.output,
        opts.no_cache,
        opts.threads,
        None,
        opts.quiet,
        ProductionAnalysis::DeadCode,
    ) {
        Ok(config) => config,
        Err(code) => return code,
    };

    // Respect an explicit user severity; force the rule on (warn) when it is the
    // default off, so the detector runs for this dedicated command.
    let effective_severity = config.rules.security_client_server_leak;
    if effective_severity == Severity::Off {
        config.rules.security_client_server_leak = Severity::Warn;
    }

    let mut results = match fallow_core::analyze(&config) {
        Ok(results) => results,
        Err(err) => return emit_error(&format!("Analysis error: {err}"), 2, opts.output),
    };

    // Workspace scope (mutually exclusive flags resolved by the shared helper).
    let ws_roots = match crate::check::filtering::resolve_workspace_scope(
        opts.root,
        opts.workspace,
        opts.changed_workspaces,
        opts.output,
    ) {
        Ok(roots) => roots,
        Err(code) => return code,
    };
    if let Some(ref roots) = ws_roots {
        crate::check::filtering::filter_to_workspaces(&mut results, roots);
    }

    // Changed-since scope (canonical normalization via the core filter, which
    // now retains security_findings too).
    if let Some(git_ref) = opts.changed_since
        && let Some(changed) = fallow_core::changed_files::get_changed_files(opts.root, git_ref)
    {
        fallow_core::changed_files::filter_results_by_changed_files(&mut results, &changed);
    }
    if opts.use_shared_diff_index
        && let Some(diff_index) = crate::report::ci::diff_filter::shared_diff_index()
    {
        crate::check::filtering::filter_results_by_diff(&mut results, diff_index, opts.root);
    }

    let unresolved_edge_files = results.security_unresolved_edge_files;
    let findings: Vec<SecurityFinding> = std::mem::take(&mut results.security_findings)
        .into_iter()
        .map(|f| relativize_finding(f, &config.root))
        .collect();

    let fail =
        (opts.fail_on_issues || effective_severity == Severity::Error) && !findings.is_empty();

    let output = SecurityOutput {
        schema_version: SecuritySchemaVersion::V1,
        security_findings: findings,
        unresolved_edge_files,
    };

    if let Some(path) = opts.sarif_file
        && let Err(message) = write_sarif_file(&output, path)
    {
        return emit_error(&message, 2, opts.output);
    }

    let rendered = match opts.output {
        OutputFormat::Json => render_json(&output),
        OutputFormat::Sarif => render_sarif(&output),
        _ if opts.summary => render_human_summary(&output),
        _ => render_human(&output),
    };
    println!("{rendered}");

    if fail {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Rewrite a finding's anchor + every trace hop path to be project-root-relative
/// (forward-slash normalization happens at serialize time via `serde_path`).
fn relativize_finding(mut finding: SecurityFinding, root: &Path) -> SecurityFinding {
    finding.path = relativize(&finding.path, root);
    for hop in &mut finding.trace {
        hop.path = relativize(&hop.path, root);
    }
    finding
}

fn relativize(path: &Path, root: &Path) -> PathBuf {
    path.strip_prefix(root)
        .map_or_else(|_| path.to_path_buf(), Path::to_path_buf)
}

/// JSON: the `SecurityOutput` envelope, pretty-printed.
#[must_use]
pub fn render_json(output: &SecurityOutput) -> String {
    let Ok(value) = crate::output_envelope::serialize_root_output(
        crate::output_envelope::FallowOutput::Security(output.clone()),
    ) else {
        return "{\"error\":\"failed to serialize security output\"}".to_owned();
    };
    serde_json::to_string_pretty(&value)
        .unwrap_or_else(|_| "{\"error\":\"failed to serialize security output\"}".to_owned())
}

fn write_sarif_file(output: &SecurityOutput, path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|err| {
            format!(
                "Failed to create directory for SARIF file {}: {err}",
                path.display()
            )
        })?;
    }
    std::fs::write(path, render_sarif(output))
        .map_err(|err| format!("Failed to write SARIF file {}: {err}", path.display()))
}

#[must_use]
fn render_human_summary(output: &SecurityOutput) -> String {
    use crate::report::plural;
    use std::fmt::Write as _;

    let count = output.security_findings.len();
    let mut out = format!(
        "Security candidates: {count} candidate{} found. These are NOT verified vulnerabilities; verify each before acting.\n",
        plural(count),
    );
    if output.unresolved_edge_files > 0 {
        let n = output.unresolved_edge_files;
        let _ = writeln!(
            out,
            "Unresolved dynamic import cones: {n} client file{}.",
            plural(n)
        );
    }
    out
}

/// Human output. Frames findings as candidates and states the next human action
/// per finding; surfaces the unresolved-edge blind spot as a counted line.
#[must_use]
#[expect(
    clippy::format_push_string,
    reason = "small report renderer; readability over avoiding the extra allocation"
)]
pub fn render_human(output: &SecurityOutput) -> String {
    use crate::report::plural;
    use colored::Colorize;

    let mut out = String::new();
    out.push_str("Security candidates (unverified; for agent or human verification)\n\n");

    if output.security_findings.is_empty() {
        out.push_str("No security candidates found.\n");
    } else {
        for finding in &output.security_findings {
            let kind = match finding.kind {
                SecurityFindingKind::ClientServerLeak => "client-server-leak",
            };
            // [I] (info/advisory) is the design-system prefix for off-by-default
            // findings surfaced for review; it deliberately is NOT a severity glyph.
            out.push_str(&format!(
                "{} {kind}  {}:{}\n",
                "[I]".blue().bold(),
                finding.path.to_string_lossy().replace('\\', "/").bold(),
                finding.line,
            ));
            out.push_str(&format!("    {}\n", finding.evidence));
            if !finding.trace.is_empty() {
                out.push_str("    trace:\n");
                for hop in &finding.trace {
                    out.push_str(&format!(
                        "      {}:{} ({})\n",
                        hop.path.to_string_lossy().replace('\\', "/"),
                        hop.line,
                        hop_role_label(hop.role),
                    ));
                }
            }
            out.push_str(
                "    Next: check whether the import is type-only, server-only, or behind a \
                 build-time guard; if the value never ships to the client bundle, this candidate \
                 is a false positive.\n\n",
            );
        }
    }

    if output.unresolved_edge_files > 0 {
        let n = output.unresolved_edge_files;
        out.push_str(&format!(
            "{} {n} client file{} reached a dynamic import the reachability scan could not \
             follow; a leak behind those edges would not be reported, so an empty result is \
             not a clean bill.\n",
            "[I]".blue().bold(),
            plural(n),
        ));
    }

    let count = output.security_findings.len();
    out.push_str(&format!(
        "\nFound {count} security candidate{}. These are NOT verified vulnerabilities; verify \
         each before acting.\n",
        plural(count),
    ));
    out
}

const fn hop_role_label(role: TraceHopRole) -> &'static str {
    match role {
        TraceHopRole::ClientBoundary => "client boundary",
        TraceHopRole::Intermediate => "intermediate",
        TraceHopRole::SecretSource => "secret source",
    }
}

/// SARIF output. Emits `level: "note"` (never error/warning) so the candidate
/// framing survives into the GitHub Security tab, and carries no CWE tag. Trace
/// hops become `relatedLocations` of the single result.
#[must_use]
fn render_sarif(output: &SecurityOutput) -> String {
    let results: Vec<serde_json::Value> = output
        .security_findings
        .iter()
        .map(|finding| {
            let related: Vec<serde_json::Value> = finding
                .trace
                .iter()
                .map(|hop| sarif_location(&hop.path, hop.line, hop.col))
                .collect();
            // Stable dedup key for GHAS: rule + anchor path + line. Without
            // partialFingerprints, every run re-opens previously triaged alerts.
            let fp = format!(
                "security/client-server-leak:{}:{}",
                finding.path.to_string_lossy().replace('\\', "/"),
                finding.line,
            );
            serde_json::json!({
                "ruleId": "security/client-server-leak",
                "level": "note",
                "message": { "text": finding.evidence },
                "locations": [sarif_location(&finding.path, finding.line, finding.col)],
                "relatedLocations": related,
                "partialFingerprints": { "fallowSecurity/v1": fnv_hex(&fp) },
            })
        })
        .collect();

    let sarif = serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": { "driver": {
                "name": "fallow",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/fallow-rs/fallow",
                "rules": [{
                    "id": "security/client-server-leak",
                    "shortDescription": { "text": "Client-server secret leak candidate (unverified)" },
                    "fullDescription": { "text":
                        "Unverified candidate, requires verification: a \"use client\" file \
                         transitively imports a module that reads a non-public process.env \
                         secret. fallow does not prove the secret reaches client-bundled code." },
                    "helpUri": "https://github.com/fallow-rs/fallow",
                    "defaultConfiguration": { "level": "note" }
                }]
            }},
            "results": results,
        }],
    });
    serde_json::to_string_pretty(&sarif)
        .unwrap_or_else(|_| "{\"error\":\"failed to serialize sarif\"}".to_owned())
}

/// Small FNV-1a hex digest for SARIF `partialFingerprints` dedup stability.
fn fnv_hex(input: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in input.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn sarif_location(path: &Path, line: u32, col: u32) -> serde_json::Value {
    serde_json::json!({
        "physicalLocation": {
            "artifactLocation": { "uri": path.to_string_lossy().replace('\\', "/") },
            "region": { "startLine": line.max(1), "startColumn": col.saturating_add(1) }
        }
    })
}
