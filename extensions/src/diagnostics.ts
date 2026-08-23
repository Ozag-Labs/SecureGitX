import * as vscode from "vscode";
import * as path from "path";
import { Finding, Severity } from "./scanner";

const SOURCE = "SecureGitX";
const RULES_DOC = vscode.Uri.parse(
  "https://github.com/Ozag-Labs/SecureGitX/blob/main/docs/guides/rules-format.md"
);

export function applyFindings(
  collection: vscode.DiagnosticCollection,
  findings: Finding[],
  workspaceRoot: string
): void {
  collection.clear();
  if (findings.length === 0) return;

  const byFile = new Map<
    string,
    { uri: vscode.Uri; diags: vscode.Diagnostic[] }
  >();

  for (const finding of findings) {
    const uri = resolveUri(finding.file, workspaceRoot);
    const key = uri.toString();
    const diag = toDiagnostic(finding, uri);

    const bucket = byFile.get(key) ?? { uri, diags: [] };
    bucket.diags.push(diag);
    byFile.set(key, bucket);
  }

  for (const { uri, diags } of byFile.values()) {
    collection.set(uri, diags);
  }
}

// Remove all diagnostics from the collection.
export function clear(collection: vscode.DiagnosticCollection): void {
  collection.clear();
}

// Internal

function toDiagnostic(f: Finding, uri: vscode.Uri): vscode.Diagnostic {
  // line_number is 1-based from Python; VS Code ranged are 0-based
  const line = Math.max(0, (f.line_number ?? 1) - 1);
  const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);

  const diag = new vscode.Diagnostic(
    range,
    `[${f.rule_id}] ${f.reason}`,
    severityFor(f.severity)
  );

  diag.source = SOURCE;
  diag.code = {
    value: f.rule_id,
    target: RULES_DOC,
  };

  // Remediation hint appears in the diagnostic details
  if (f.remediation) {
    diag.relatedInformation = [
      new vscode.DiagnosticRelatedInformation(
        new vscode.Location(uri, range),
        `Remediation: ${f.remediation}`
      ),
    ];
  }

  return diag;
}

function resolveUri(file: string, workspaceRoot: string): vscode.Uri {
  if (path.isAbsolute(file)) {
    return vscode.Uri.file(file);
  }
  return vscode.Uri.file(path.resolve(workspaceRoot, file));
}

function severityFor(severity: Severity): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Warning;
  }
}
