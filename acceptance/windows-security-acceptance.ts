import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

if (process.platform !== "win32") {
  throw new Error("WINDOWS_SECURITY_ACCEPTANCE_REQUIRES_WINDOWS");
}

const repoRoot = path.resolve(process.env.C2C_PRODUCTION_ROOT ?? process.cwd());
const { Workspace, WorkspaceError } = await import(
  pathToFileURL(path.join(repoRoot, "src", "workspace", "manager.ts")).href
);
const { writeAuthState } = await import(
  pathToFileURL(path.join(repoRoot, "src", "auth", "persistence.ts")).href
);

const powershell = path.join(
  process.env.SystemRoot ?? "C:\\Windows",
  "System32",
  "WindowsPowerShell",
  "v1.0",
  "powershell.exe",
);
const systemModules = path.join(
  process.env.SystemRoot ?? "C:\\Windows",
  "System32",
  "WindowsPowerShell",
  "v1.0",
  "Modules",
);
const commonModules = path.join(
  process.env.ProgramFiles ?? "C:\\Program Files",
  "WindowsPowerShell",
  "Modules",
);
assert.ok(fs.existsSync(powershell), "Windows PowerShell 5.1 must be present");
assert.ok(fs.existsSync(systemModules), "Windows PowerShell 5.1 module directory must be present");

// Windows PowerShell 5.1 can inherit a PSModulePath composed for PowerShell 7.
// Give every child process the explicit Windows PowerShell module locations.
const psModulePath = [systemModules, ...(fs.existsSync(commonModules) ? [commonModules] : [])]
  .join(path.delimiter);

type AclRule = {
  sid: string;
  rights: string;
  type: string;
  inherited: boolean;
  inheritanceFlags: string;
  propagationFlags: string;
};

type AclSnapshot = {
  psVersion: string;
  aclCommandSource: string;
  ownerSid: string;
  groupSid: string;
  currentSid: string;
  protected: boolean;
  rules: AclRule[];
};

function quotePowerShell(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}

function runPowerShellJson(body: string): Record<string, unknown> {
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'EXPECTED_WINDOWS_POWERSHELL_5_1' }",
    "Import-Module Microsoft.PowerShell.Security -ErrorAction Stop",
    "if ((Get-Command Get-Acl -ErrorAction Stop).Source -ne 'Microsoft.PowerShell.Security') { throw 'GET_ACL_MODULE_MISMATCH' }",
    body,
  ].join("; ");
  const result = spawnSync(
    powershell,
    ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
    {
      encoding: "utf8",
      windowsHide: true,
      timeout: 30_000,
      env: { ...process.env, PSModulePath: psModulePath },
    },
  );

  if (result.error) throw new Error(`POWERSHELL_START_FAILED: ${result.error.message}`);
  if (result.signal) throw new Error(`POWERSHELL_SIGNAL: ${result.signal}`);
  if (result.status !== 0) {
    throw new Error(`POWERSHELL_EXIT_${String(result.status)}: ${result.stderr.trim() || "no stderr"}`);
  }
  if (result.stderr.trim()) throw new Error(`POWERSHELL_STDERR_NOT_EMPTY: ${result.stderr.trim()}`);

  const output = result.stdout.trim().replace(/^\uFEFF/, "");
  if (!output) throw new Error("POWERSHELL_JSON_MISSING");
  let parsed: unknown;
  try {
    parsed = JSON.parse(output);
  } catch {
    throw new Error("POWERSHELL_JSON_INVALID");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("POWERSHELL_JSON_OBJECT_REQUIRED");
  }
  return parsed as Record<string, unknown>;
}

function inspectAcl(file: string): AclSnapshot {
  const p = quotePowerShell(file);
  const result = runPowerShellJson([
    `$p = ${p}`,
    "$acl = Get-Acl -LiteralPath $p -ErrorAction Stop",
    "$sidType = [Security.Principal.SecurityIdentifier]",
    "$rules = @($acl.Access | ForEach-Object { [ordered]@{ sid = $_.IdentityReference.Translate($sidType).Value; rights = $_.FileSystemRights.ToString(); type = $_.AccessControlType.ToString(); inherited = [bool]$_.IsInherited; inheritanceFlags = $_.InheritanceFlags.ToString(); propagationFlags = $_.PropagationFlags.ToString() } })",
    "$snapshot = [ordered]@{ psVersion = $PSVersionTable.PSVersion.ToString(); aclCommandSource = (Get-Command Get-Acl).Source; ownerSid = $acl.GetOwner($sidType).Value; groupSid = $acl.GetGroup($sidType).Value; currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; protected = [bool]$acl.AreAccessRulesProtected; rules = $rules }",
    "[Console]::Out.WriteLine(($snapshot | ConvertTo-Json -Compress -Depth 8))",
  ].join("; "));

  const requiredStrings = ["psVersion", "aclCommandSource", "ownerSid", "groupSid", "currentSid"] as const;
  for (const field of requiredStrings) {
    assert.equal(typeof result[field], "string", `DACL output field ${field} must be a string`);
    assert.ok((result[field] as string).length > 0, `DACL output field ${field} must not be empty`);
  }
  assert.match(result.psVersion as string, /^5\.1\./, "DACL probe must use Windows PowerShell 5.1");
  assert.equal(result.aclCommandSource, "Microsoft.PowerShell.Security");
  assert.equal(typeof result.protected, "boolean", "DACL protected field must be a boolean");
  assert.ok(Array.isArray(result.rules), "DACL rules field must be an array");
  for (const rule of result.rules) {
    assert.ok(rule && typeof rule === "object" && !Array.isArray(rule), "DACL rule must be an object");
    const record = rule as Record<string, unknown>;
    for (const field of ["sid", "rights", "type", "inheritanceFlags", "propagationFlags"]) {
      assert.equal(typeof record[field], "string", `DACL rule field ${field} must be a string`);
      assert.ok((record[field] as string).length > 0, `DACL rule field ${field} must not be empty`);
    }
    assert.equal(typeof record.inherited, "boolean", "DACL rule inherited field must be a boolean");
  }
  return result as unknown as AclSnapshot;
}

function assertEscapingPathRejected(root: string, relativePath: string): void {
  const workspace = new Workspace(root);
  assert.throws(
    () => workspace.resolve(relativePath),
    error => error instanceof WorkspaceError && error.code === "PATH_OUTSIDE_WORKSPACE",
    `workspace must reject the real symlink escape at ${relativePath}`,
  );
}

const failures: string[] = [];
const passed: string[] = [];

async function check(name: string, body: () => void | Promise<void>): Promise<void> {
  try {
    await body();
    passed.push(name);
    console.log(`PASS ${name}`);
  } catch (error) {
    const detail = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
    failures.push(`${name}: ${detail}`);
    console.error(`FAIL ${name}: ${detail}`);
  }
}

await check("file symlink escape uses a real outside target", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "c2c-file-symlink-"));
  try {
    const root = path.join(temp, "workspace");
    const outside = path.join(temp, "outside");
    fs.mkdirSync(root);
    fs.mkdirSync(outside);
    const target = path.join(outside, "secret.txt");
    const link = path.join(root, "link-out.txt");
    fs.writeFileSync(target, "synthetic outside fixture\n");
    try {
      fs.symlinkSync(target, link, "file");
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code ?? "UNKNOWN";
      throw new Error(`SYMLINK_FIXTURE_CREATE_FAILED kind=file code=${code}`);
    }
    assert.equal(fs.lstatSync(link).isSymbolicLink(), true, "file fixture must be a symbolic link");
    assert.equal(
      path.resolve(fs.realpathSync.native(link)).toLowerCase(),
      path.resolve(target).toLowerCase(),
      "file fixture must resolve to the outside file",
    );
    assertEscapingPathRejected(root, "link-out.txt");
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

await check("directory symlink escape uses a real outside target", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "c2c-dir-symlink-"));
  try {
    const root = path.join(temp, "workspace");
    const outside = path.join(temp, "outside");
    fs.mkdirSync(root);
    fs.mkdirSync(outside);
    fs.writeFileSync(path.join(outside, "secret.txt"), "synthetic outside fixture\n");
    const link = path.join(root, "dir-out");
    try {
      fs.symlinkSync(outside, link, "dir");
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code ?? "UNKNOWN";
      throw new Error(`SYMLINK_FIXTURE_CREATE_FAILED kind=directory code=${code}`);
    }
    assert.equal(fs.lstatSync(link).isSymbolicLink(), true, "directory fixture must be a symbolic link");
    assert.equal(
      path.resolve(fs.realpathSync.native(link)).toLowerCase(),
      path.resolve(outside).toLowerCase(),
      "directory fixture must resolve to the outside directory",
    );
    assertEscapingPathRejected(root, "dir-out/secret.txt");
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

await check("atomic replacement creates and preserves the current-user-only DACL", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "c2c-dacl-"));
  try {
    const file = path.join(temp, "auth.json");
    writeAuthState(file, { generation: 1 });
    const first = inspectAcl(file);
    assert.equal(first.protected, true, "new auth state DACL must be protected");
    assert.equal(first.ownerSid, first.currentSid, "new auth state owner must be the current user");
    assert.equal(first.rules.length, 1, "new auth state must have exactly one explicit ACE");
    assert.deepEqual(first.rules[0], {
      sid: first.currentSid,
      rights: "FullControl",
      type: "Allow",
      inherited: false,
      inheritanceFlags: "None",
      propagationFlags: "None",
    });

    writeAuthState(file, { generation: 2 });
    const afterReplace = inspectAcl(file);
    assert.deepEqual(afterReplace, first, "ReplaceFileW must preserve owner, group, protected DACL and all ACE fields");
    assert.deepEqual(JSON.parse(fs.readFileSync(file, "utf8")), { generation: 2 });
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

await check("unsafe DACL is rejected without changing committed bytes", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "c2c-unsafe-dacl-"));
  try {
    const file = path.join(temp, "auth.json");
    writeAuthState(file, { generation: 1 });
    const setup = [
      `$p = ${quotePowerShell(file)}`,
      "$acl = [IO.File]::GetAccessControl($p, [Security.AccessControl.AccessControlSections]::Access)",
      "$sid = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')",
      "$rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::Read, [Security.AccessControl.AccessControlType]::Allow)",
      "$acl.AddAccessRule($rule)",
      "[IO.File]::SetAccessControl($p, $acl)",
      "$fixture = [ordered]@{ fixture = 'everyone-read-ace-added' }",
      "[Console]::Out.WriteLine(($fixture | ConvertTo-Json -Compress))",
    ].join("; ");
    const setupResult = runPowerShellJson(setup);
    assert.equal(setupResult.fixture, "everyone-read-ace-added");

    const committedBytes = fs.readFileSync(file);
    assert.throws(() => writeAuthState(file, { generation: 2 }), /AUTH_STORE_NATIVE_COMMIT_FAILED/);
    assert.deepEqual(fs.readFileSync(file), committedBytes, "unsafe DACL rejection must preserve committed bytes");
    const unsafeAcl = inspectAcl(file);
    assert.ok(
      unsafeAcl.rules.some(rule => rule.sid === "S-1-1-0" && rule.type === "Allow" && rule.rights.includes("Read")),
      "unsafe fixture must contain the Everyone read ACE that triggered rejection",
    );
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

if (failures.length > 0) {
  console.error(`Windows security acceptance: ${passed.length} passed, ${failures.length} failed, 0 skipped`);
  process.exitCode = 1;
} else {
  console.log(`Windows security acceptance: ${passed.length} passed, 0 failed, 0 skipped`);
}
