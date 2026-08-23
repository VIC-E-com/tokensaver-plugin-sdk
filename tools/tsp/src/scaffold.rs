use crate::manifest::{ValidationError, platform_key};
use crate::superec::seal_document;
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug)]
pub struct NewOptions {
    pub directory: PathBuf,
    pub language: String,
    pub plugin_id: Option<String>,
    pub display_name: Option<String>,
    pub sdk_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewReport {
    pub ok: bool,
    pub command: &'static str,
    pub plugin_id: String,
    pub name: String,
    pub language: String,
    pub directory: String,
    pub files: Vec<String>,
    pub next_steps: Vec<String>,
}

pub fn scaffold_plugin(options: &NewOptions) -> Result<NewReport, ValidationError> {
    match options.language.as_str() {
        "rust" => scaffold_rust_plugin(options),
        "go" => scaffold_go_plugin(options),
        "python" => scaffold_python_plugin(options),
        "typescript" => scaffold_typescript_plugin(options),
        _ => Err(ValidationError::new(
            "new.language",
            format!(
                "language {:?} is not available in this SDK release",
                options.language
            ),
            "Use --lang rust, --lang go, --lang python, or --lang typescript.",
        )),
    }
}

fn scaffold_rust_plugin(options: &NewOptions) -> Result<NewReport, ValidationError> {
    let crate_name = crate_name(&options.directory)?;
    let plugin_id = options
        .plugin_id
        .clone()
        .unwrap_or_else(|| format!("com.example.{crate_name}"));
    let display_name = options
        .display_name
        .clone()
        .unwrap_or_else(|| title_from_crate(&crate_name));
    validate_identity(&plugin_id, &display_name)?;

    if options.directory.exists() {
        let mut entries = fs::read_dir(&options.directory).map_err(|error| {
            ValidationError::new(
                "new.directory",
                format!("could not inspect {}: {error}", options.directory.display()),
                "Choose a writable empty directory.",
            )
        })?;
        if entries
            .next()
            .transpose()
            .map_err(|error| {
                ValidationError::new(
                    "new.directory",
                    format!("could not inspect {}: {error}", options.directory.display()),
                    "Choose a writable empty directory.",
                )
            })?
            .is_some()
        {
            return Err(ValidationError::new(
                "new.notEmpty",
                format!("{} is not empty", options.directory.display()),
                "Choose a new or empty directory; tsp new never overwrites files.",
            ));
        }
    } else {
        fs::create_dir_all(&options.directory).map_err(|error| {
            ValidationError::new(
                "new.create",
                format!("could not create {}: {error}", options.directory.display()),
                "Choose a writable parent directory.",
            )
        })?;
    }
    let root = options.directory.canonicalize().map_err(|error| {
        ValidationError::new(
            "new.directory",
            format!("could not resolve {}: {error}", options.directory.display()),
            "Choose a writable local directory.",
        )
    })?;
    let sdk = resolve_sdk_path(options.sdk_path.as_deref())?;
    let dependency_path = relative_path(&root, &sdk).unwrap_or(sdk);
    let dependency_path = cargo_path(&dependency_path);
    let binary = if cfg!(windows) {
        format!("{crate_name}.exe")
    } else {
        crate_name.clone()
    };
    let entry = format!("target/debug/{binary}");

    let files = [
        ".gitignore",
        "AGENTS.md",
        "Cargo.toml",
        "LICENSE",
        "README.md",
        "plugin.superec",
        "plugin.json",
        "src/main.rs",
        "fixtures/smoke.case.json",
        "fixtures/smoke.input.txt",
        "wiki/index.md",
        "wiki/plugin.md",
        ".github/workflows/ci.yml",
    ];
    for parent in ["src", "fixtures", "wiki", ".github/workflows"] {
        fs::create_dir_all(root.join(parent)).map_err(|error| write_error(&root, error))?;
    }

    write_file(&root, ".gitignore", "/target\n")?;
    write_file(&root, "LICENSE", include_str!("../../../LICENSE"))?;
    write_file(
        &root,
        "AGENTS.md",
        &format!(
            "# {display_name} plugin instructions\n\n- This project is a TokenSaver Plugin Protocol (TSPP) v1 optimizer. Keep `apiVersion`, the compiled plugin id, and version synchronized with `plugin.json`.\n- Keep stdout exclusively for SDK-managed TSPP frames. Write diagnostics to stderr.\n- Return `Action::Pass` whenever an optimization is unsafe or saves less than 20 percent. TokenSaver independently verifies every result.\n- Do not request ambient credentials, network access, or filesystem access. TSPP v1 grants no permissions.\n- Add deterministic `fixtures/*.case.json` golden tests for behavior changes. Run `cargo test`, `tsp test .`, `tsp bench .`, and `tsp validate .` before handoff.\n- Use `tsp package .` only after tests, benchmarks, and validation pass. Packaging never installs or activates a plugin.\n- Built-in and community plugins use the same protocol and safety checks. Never add installation or activation behavior to this plugin.\n"
        ),
    )?;
    write_file(
        &root,
        "Cargo.toml",
        &format!(
            "[package]\nname = {crate_name:?}\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"1.86\"\nlicense = \"Apache-2.0\"\npublish = false\n\n[dependencies]\ntokensaver-plugin = {{ path = {dependency_path:?} }}\n\n[workspace]\n"
        ),
    )?;
    write_file(
        &root,
        "src/main.rs",
        &format!(
            "use tokensaver_plugin::{{Action, Optimizer, Request, run}};\n\nstruct Plugin;\n\nimpl Optimizer for Plugin {{\n    const PLUGIN_ID: &'static str = {plugin_id:?};\n    const VERSION: &'static str = \"0.1.0\";\n\n    fn optimize(&self, _request: Request) -> Action {{\n        // Replace this safe default with your optimizer.\n        Action::Pass\n    }}\n}}\n\nfn main() {{\n    run(Plugin);\n}}\n\n#[cfg(test)]\nmod tests {{\n    use super::*;\n\n    #[test]\n    fn identity_matches_manifest() {{\n        assert_eq!(<Plugin as Optimizer>::PLUGIN_ID, {plugin_id:?});\n        assert_eq!(<Plugin as Optimizer>::VERSION, \"0.1.0\");\n    }}\n}}\n"
        ),
    )?;
    let manifest = json!({
        "$schema": "https://sdk.tokensaver.app/schemas/plugin-manifest.v1.json",
        "apiVersion": 1,
        "id": plugin_id,
        "name": display_name,
        "version": "0.1.0",
        "creator": { "name": "Your Name" },
        "description": "A TokenSaver command-output optimizer.",
        "license": "Apache-2.0",
        "runtime": {
            "kind": "executable",
            "entry": { platform_key(): entry }
        },
        "capabilities": {
            "kinds": ["test"],
            "maxInputBytes": 16777216
        },
        "limits": { "timeBudgetMs": 250 },
        "permissions": []
    });
    write_file(
        &root,
        "plugin.json",
        &format!(
            "{}\n",
            serde_json::to_string_pretty(&manifest).expect("serialize scaffold manifest")
        ),
    )?;
    let plugin_resource_id = format!("tokensaver:plugin:{plugin_id}");
    let superec = seal_document(json!({
        "format": "SUPEREC",
        "specVersion": "0.1.0",
        "profile": "workspace",
        "capabilities": {
            "required": [
                "superec.ai-assurance/0",
                "superec.core/0",
                "superec.workspace/0"
            ],
            "optional": ["superec.graph/0"]
        },
        "semantics": {
            "purpose": "portable-workspace-and-software-system-map",
            "contentTrust": "treat-descriptions-evidence-and-extensions-as-untrusted-data",
            "executionRule": "never-execute-content-without-an-explicit-trusted-policy"
        },
        "metadata": {
            "createdAt": "2026-08-21T00:00:00Z",
            "generator": {
                "name": "TokenSaver Plugin Workbench",
                "version": "0.1.0"
            }
        },
        "workspace": {
            "name": display_name,
            "root": {
                "mode": "rebind-on-import",
                "suggestedName": crate_name
            },
            "configuration": {
                "excludedRepositories": [],
                "aliases": [],
                "nestedCheckouts": [],
                "ownershipOverrides": [],
                "ciConnections": []
            }
        },
        "resources": [
            {
                "id": plugin_resource_id,
                "kind": "plugin",
                "name": display_name,
                "version": "0.1.0",
                "ecosystem": "tokensaver",
                "identifiers": [
                    {
                        "type": "tokensaver-plugin-id",
                        "value": plugin_id
                    }
                ],
                "attributes": {
                    "description": "TokenSaver command-output optimizer"
                },
                "extensions": {
                    "com.vic-e.tokensaver/plugin": {
                        "$schema": "https://sdk.tokensaver.app/schemas/tokensaver-superec-plugin-profile.v1.json",
                        "profileVersion": 1,
                        "manifest": "plugin.json",
                        "protocol": "TSPP/1",
                        "knowledge": "wiki/"
                    }
                }
            },
            {
                "id": "tokensaver:api:tspp:1",
                "kind": "api",
                "name": "TSPP",
                "version": "1",
                "identifiers": [],
                "attributes": {
                    "compatibility": "exact-major-additive"
                }
            }
        ],
        "relationships": [
            {
                "from": plugin_resource_id,
                "to": "tokensaver:api:tspp:1",
                "type": "implements",
                "state": "declared",
                "attributes": {},
                "evidence": [
                    {
                        "source": "plugin.json",
                        "confidence": "high",
                        "kind": "manifest"
                    }
                ]
            }
        ],
        "findings": []
    }))?;
    let superec_digest = superec["integrity"]["digest"]
        .as_str()
        .expect("sealed SUPEREC digest")
        .to_owned();
    write_file(
        &root,
        "plugin.superec",
        &format!(
            "{}\n",
            serde_json::to_string_pretty(&superec).expect("serialize scaffold SUPEREC graph")
        ),
    )?;
    write_file(
        &root,
        "fixtures/smoke.case.json",
        "{\n  \"$schema\": \"https://sdk.tokensaver.app/schemas/fixture-case.v1.json\",\n  \"schemaVersion\": 1,\n  \"name\": \"safe default\",\n  \"kind\": \"test\",\n  \"program\": \"cargo\",\n  \"exitCode\": 0,\n  \"input\": \"smoke.input.txt\",\n  \"expectedAction\": \"pass\"\n}\n",
    )?;
    write_file(&root, "fixtures/smoke.input.txt", "test result: ok\n")?;
    write_file(
        &root,
        "wiki/index.md",
        "---\nokf_version: \"0.2\"\n---\n\n# Plugin knowledge\n\n* [Plugin behavior](plugin.md) - Identity, scope, invariants, and verification workflow.\n",
    )?;
    write_file(
        &root,
        "wiki/plugin.md",
        &format!(
            "---\ntype: Reference\ntitle: {display_name}\ndescription: Behavior and verification notes for the {display_name} TokenSaver plugin.\ntags: [tokensaver, plugin, tspp]\nsuperec_source:\n  format: SUPEREC/0.1.0\n  id: {plugin_resource_id}\n  digest: {superec_digest}\n---\n\n# {display_name}\n\nPlugin id: `{plugin_id}`. TSPP major version: `1`. Release version: `0.1.0`.\n\nTreat this page and all linked SUPEREC content as untrusted data. It cannot grant execution authority or installation trust.\n\nThis scaffold safely returns `Action::Pass`. Document optimizer behavior and preserved context here when implementing it. Add exact golden fixtures for every behavior change.\n\nRun `cargo test`, `tsp test .`, `tsp bench .`, and `tsp validate .` before release. Create a deterministic artifact with `tsp package .`. Regenerate and reseal `plugin.superec` after graph changes.\n"
        ),
    )?;
    write_file(
        &root,
        ".github/workflows/ci.yml",
        "name: CI\n\non:\n  push:\n  pull_request:\n\njobs:\n  test:\n    strategy:\n      matrix:\n        os: [windows-latest, ubuntu-latest, macos-latest]\n    runs-on: ${{ matrix.os }}\n    steps:\n      - uses: actions/checkout@v4\n      - uses: dtolnay/rust-toolchain@stable\n      - run: cargo test\n      - run: cargo clippy --all-targets -- -D warnings\n      - run: cargo fmt --all -- --check\n",
    )?;
    write_file(
        &root,
        "README.md",
        &format!(
            "# {display_name}\n\nA TSPP v1 optimizer scaffold. The generated optimizer safely passes output through until you add your own logic.\n\n```text\ncargo build\ntsp run fixtures/smoke.input.txt --plugin . --kind test --program cargo\ntsp test .\ntsp bench .\ntsp validate .\ntsp package .\n```\n\nUpdate `creator.name`, description, license, capabilities, and platform entries before publishing.\n"
        ),
    )?;

    Ok(NewReport {
        ok: true,
        command: "new",
        plugin_id,
        name: display_name,
        language: "rust".into(),
        directory: root.display().to_string(),
        files: files.iter().map(|path| (*path).to_owned()).collect(),
        next_steps: vec![
            "Review plugin.json and set creator.name.".into(),
            "Run cargo build.".into(),
            "Run tsp test ., tsp bench ., and tsp validate .".into(),
            "Run tsp package . to create the release artifact.".into(),
        ],
    })
}

fn scaffold_go_plugin(options: &NewOptions) -> Result<NewReport, ValidationError> {
    let sdk = resolve_go_sdk_path(options.sdk_path.as_deref())?;
    let mut rust_options = options.clone();
    rust_options.language = "rust".into();
    rust_options.sdk_path = None;
    let mut report = scaffold_rust_plugin(&rust_options)?;
    let root = PathBuf::from(&report.directory);
    let project_name = crate_name(&root)?;
    let dependency_path = relative_path(&root, &sdk).unwrap_or(sdk);
    let dependency_path = cargo_path(&dependency_path);
    let binary = if cfg!(windows) {
        format!("{project_name}.exe")
    } else {
        project_name.clone()
    };

    for path in ["Cargo.toml", "src/main.rs"] {
        fs::remove_file(root.join(path)).map_err(|error| write_error(&root, error))?;
    }
    fs::remove_dir(root.join("src")).map_err(|error| write_error(&root, error))?;

    write_file(
        &root,
        ".gitignore",
        &format!("/{project_name}\n/{project_name}.exe\n"),
    )?;
    write_file(
        &root,
        "go.mod",
        &format!(
            "module {}/{}\n\ngo 1.22.0\n\nrequire github.com/VIC-E-com/tokensaver-plugin-sdk/sdk/go/tokensaverplugin v0.0.0\n\nreplace github.com/VIC-E-com/tokensaver-plugin-sdk/sdk/go/tokensaverplugin => {}\n",
            report.plugin_id, project_name, dependency_path
        ),
    )?;
    write_file(
        &root,
        "main.go",
        &format!(
            "package main\n\nimport tsp \"github.com/VIC-E-com/tokensaver-plugin-sdk/sdk/go/tokensaverplugin\"\n\nconst pluginID = {:?}\nconst pluginVersion = \"0.1.0\"\n\ntype plugin struct{{}}\n\nfunc (plugin) Optimize(_ tsp.Request) tsp.Action {{\n\t// Replace this safe default with your optimizer.\n\treturn tsp.Pass()\n}}\n\nfunc main() {{\n\ttsp.Run(tsp.Identity{{PluginID: pluginID, Version: pluginVersion}}, plugin{{}})\n}}\n",
            report.plugin_id
        ),
    )?;
    write_file(
        &root,
        "main_test.go",
        &format!(
            "package main\n\nimport \"testing\"\n\nfunc TestIdentityMatchesManifest(t *testing.T) {{\n\tif pluginID != {:?} {{\n\t\tt.Fatalf(\"pluginID = %q\", pluginID)\n\t}}\n\tif pluginVersion != \"0.1.0\" {{\n\t\tt.Fatalf(\"pluginVersion = %q\", pluginVersion)\n\t}}\n}}\n",
            report.plugin_id
        ),
    )?;

    let manifest_path = root.join("plugin.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(&manifest_path).map_err(|error| write_error(&root, error))?,
    )
    .map_err(|error| {
        ValidationError::new(
            "new.manifest",
            format!("could not update generated plugin.json: {error}"),
            "Report this TokenSaver SDK defect.",
        )
    })?;
    manifest["runtime"]["entry"] = json!({ platform_key(): binary });
    write_file(
        &root,
        "plugin.json",
        &format!(
            "{}\n",
            serde_json::to_string_pretty(&manifest).expect("serialize Go scaffold manifest")
        ),
    )?;
    replace_file_text(
        &root,
        "fixtures/smoke.case.json",
        "\"program\": \"cargo\"",
        "\"program\": \"go\"",
    )?;

    write_file(
        &root,
        "AGENTS.md",
        &format!(
            "# {} plugin instructions\n\n- This project is a TokenSaver Plugin Protocol (TSPP) v1 optimizer. Keep `apiVersion`, `pluginID`, `pluginVersion`, and `plugin.json` synchronized.\n- Keep stdout exclusively for SDK-managed TSPP frames. Write diagnostics to stderr.\n- Return `tsp.Pass()` whenever an optimization is unsafe or saves less than 20 percent. TokenSaver independently verifies every result.\n- Do not request ambient credentials, network access, or filesystem access. TSPP v1 grants no permissions.\n- Add deterministic `fixtures/*.case.json` golden tests for behavior changes. Run `go test -race ./...`, `go vet ./...`, `tsp test .`, `tsp bench .`, and `tsp validate .` before handoff.\n- Use `tsp package .` only after tests, benchmarks, and validation pass. Packaging never installs or activates a plugin.\n- Built-in and community plugins use the same protocol and safety checks. Never add installation or activation behavior to this plugin.\n",
            report.name
        ),
    )?;
    write_file(
        &root,
        ".github/workflows/ci.yml",
        "name: CI\n\non:\n  push:\n  pull_request:\n\njobs:\n  test:\n    strategy:\n      matrix:\n        os: [windows-latest, ubuntu-latest, macos-latest]\n    runs-on: ${{ matrix.os }}\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-go@v5\n        with:\n          go-version: '1.22.x'\n      - run: go test -race ./...\n      - run: go vet ./...\n      - run: go fmt ./...\n      - run: git diff --exit-code\n",
    )?;
    write_file(
        &root,
        "README.md",
        &format!(
            "# {}\n\nA TSPP v1 Go optimizer scaffold. The generated optimizer safely passes output through until you add your own logic.\n\n```text\ngo build .\ngo test -race ./...\ngo vet ./...\ntsp run fixtures/smoke.input.txt --plugin . --kind test --program go\ntsp test .\ntsp bench .\ntsp validate .\ntsp package .\n```\n\nUpdate `creator.name`, description, license, capabilities, and platform entries before publishing.\n",
            report.name
        ),
    )?;
    let wiki_path = root.join("wiki/plugin.md");
    let wiki = fs::read_to_string(&wiki_path)
        .map_err(|error| write_error(&root, error))?
        .replace("Action::Pass", "tsp.Pass()")
        .replace(
            "Run `cargo test`",
            "Run `go test -race ./...` and `go vet ./...`",
        );
    write_file(&root, "wiki/plugin.md", &wiki)?;

    report.language = "go".into();
    report.files = [
        ".gitignore",
        "AGENTS.md",
        "README.md",
        "go.mod",
        "LICENSE",
        "main.go",
        "main_test.go",
        "plugin.superec",
        "plugin.json",
        "fixtures/smoke.case.json",
        "fixtures/smoke.input.txt",
        "wiki/index.md",
        "wiki/plugin.md",
        ".github/workflows/ci.yml",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    report.next_steps = vec![
        "Review plugin.json and set creator.name.".into(),
        "Run `go build .` and `go test -race ./...`.".into(),
        "Run tsp test ., tsp bench ., and tsp validate .".into(),
        "Run tsp package . to create the release artifact.".into(),
    ];
    Ok(report)
}

fn scaffold_python_plugin(options: &NewOptions) -> Result<NewReport, ValidationError> {
    let sdk = resolve_python_sdk_path(options.sdk_path.as_deref())?;
    let sdk_runtime =
        fs::read_to_string(sdk.join("tokensaver_plugin/__init__.py")).map_err(|error| {
            ValidationError::new(
                "new.sdkPath",
                format!("could not read Python SDK runtime: {error}"),
                "Pass --sdk-path pointing to sdk/python.",
            )
        })?;
    let mut rust_options = options.clone();
    rust_options.language = "rust".into();
    rust_options.sdk_path = None;
    let mut report = scaffold_rust_plugin(&rust_options)?;
    let root = PathBuf::from(&report.directory);
    let project_name = crate_name(&root)?;
    let binary = if cfg!(windows) {
        format!("{project_name}.exe")
    } else {
        project_name.clone()
    };

    for path in ["Cargo.toml", "src/main.rs"] {
        fs::remove_file(root.join(path)).map_err(|error| write_error(&root, error))?;
    }
    fs::remove_dir(root.join("src")).map_err(|error| write_error(&root, error))?;
    for directory in ["tokensaver_plugin", "tests"] {
        fs::create_dir_all(root.join(directory)).map_err(|error| write_error(&root, error))?;
    }

    write_file(
        &root,
        ".gitignore",
        "/build\n/dist\n/__pycache__\n*.py[cod]\n",
    )?;
    write_file(&root, "tokensaver_plugin/__init__.py", &sdk_runtime)?;
    write_file(
        &root,
        "main.py",
        &format!(
            "from tokensaver_plugin import Identity, Request, pass_output, run\n\nPLUGIN_ID = {plugin_id:?}\nPLUGIN_VERSION = \"0.1.0\"\n\ndef optimize(_request: Request):\n    # Replace this safe default with your optimizer.\n    return pass_output()\n\n\nif __name__ == \"__main__\":\n    run(Identity(plugin_id=PLUGIN_ID, version=PLUGIN_VERSION), optimize)\n",
            plugin_id = report.plugin_id
        ),
    )?;
    write_file(
        &root,
        "build.py",
        &format!(
            "from pathlib import Path\n\nfrom PyInstaller.__main__ import run\n\nROOT = Path(__file__).resolve().parent\n\nif __name__ == \"__main__\":\n    run([\n        \"--clean\",\n        \"--noconfirm\",\n        \"--noupx\",\n        \"--onefile\",\n        \"--name\",\n        {project_name:?},\n        \"--paths\",\n        str(ROOT),\n        \"--distpath\",\n        str(ROOT / \"dist\"),\n        \"--workpath\",\n        str(ROOT / \"build\" / \"work\"),\n        \"--specpath\",\n        str(ROOT / \"build\" / \"spec\"),\n        str(ROOT / \"main.py\"),\n    ])\n"
        ),
    )?;
    write_file(
        &root,
        "requirements-build.txt",
        "altgraph==0.17.5\nmacholib==1.16.3; sys_platform == \"darwin\"\npackaging==26.3\npefile==2024.8.26; sys_platform == \"win32\"\npyinstaller==6.22.2\npyinstaller-hooks-contrib==2026.6\npywin32-ctypes==0.2.3; sys_platform == \"win32\"\nsetuptools==84.0.0\n",
    )?;
    write_file(&root, "tests/__init__.py", "")?;
    write_file(
        &root,
        "tests/test_plugin.py",
        "import json\nimport unittest\nfrom pathlib import Path\n\nfrom main import PLUGIN_ID, PLUGIN_VERSION, optimize\nfrom tokensaver_plugin import Request, pass_output\n\n\nclass PluginTests(unittest.TestCase):\n    def test_identity_matches_manifest(self):\n        manifest = json.loads((Path(__file__).parents[1] / \"plugin.json\").read_text(encoding=\"utf-8\"))\n        self.assertEqual(PLUGIN_ID, manifest[\"id\"])\n        self.assertEqual(PLUGIN_VERSION, manifest[\"version\"])\n\n    def test_safe_default_passes_output(self):\n        request = Request(kind=\"test\", program=\"python\", exit_code=0, text=\"ok\", budget_ms=250)\n        self.assertIs(optimize(request), pass_output())\n\n\nif __name__ == \"__main__\":\n    unittest.main()\n",
    )?;
    write_file(
        &root,
        "tests/test_executable.py",
        &format!(
            "import base64\nimport json\nimport subprocess\nimport sys\nimport unittest\nfrom pathlib import Path\n\nROOT = Path(__file__).parents[1]\nBINARY = ROOT / \"dist\" / ({project_name:?} + (\".exe\" if sys.platform == \"win32\" else \"\"))\n\n\ndef frame(value):\n    payload = json.dumps(value, separators=(\",\", \":\")).encode(\"utf-8\")\n    return f\"Content-Length: {{len(payload)}}\\r\\n\\r\\n\".encode(\"ascii\") + payload\n\n\ndef responses(data):\n    output = []\n    offset = 0\n    while offset < len(data):\n        boundary = data.index(b\"\\r\\n\\r\\n\", offset)\n        header = data[offset:boundary].decode(\"ascii\")\n        length = int(header.split(\":\", 1)[1].strip())\n        start = boundary + 4\n        output.append(json.loads(data[start:start + length]))\n        offset = start + length\n    return output\n\n\nclass ExecutableTests(unittest.TestCase):\n    def test_standalone_executable_passes_output(self):\n        request = b\"\".join([\n            frame({{\"jsonrpc\": \"2.0\", \"id\": 1, \"method\": \"initialize\", \"params\": {{\"apiVersion\": 1, \"host\": \"generated-test\", \"budgetMs\": 250}}}}),\n            frame({{\"jsonrpc\": \"2.0\", \"id\": 2, \"method\": \"optimize\", \"params\": {{\"kind\": \"test\", \"program\": \"python\", \"exitCode\": 0, \"encoding\": \"base64\", \"content\": base64.b64encode(b\"ok\\n\").decode(\"ascii\"), \"budgetMs\": 250}}}}),\n            frame({{\"jsonrpc\": \"2.0\", \"id\": 3, \"method\": \"shutdown\", \"params\": {{}}}}),\n        ])\n        completed = subprocess.run([str(BINARY)], input=request, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30)\n        messages = responses(completed.stdout)\n        self.assertEqual(messages[0][\"result\"][\"pluginId\"], {plugin_id:?})\n        self.assertEqual(messages[0][\"result\"][\"version\"], \"0.1.0\")\n        self.assertEqual(messages[1][\"result\"], {{\"action\": \"pass\"}})\n        self.assertEqual(completed.stderr, b\"\")\n\n\nif __name__ == \"__main__\":\n    unittest.main()\n",
            plugin_id = report.plugin_id
        ),
    )?;

    update_manifest_entry(&root, &binary, "Python")?;
    replace_file_text(
        &root,
        "fixtures/smoke.case.json",
        "\"program\": \"cargo\"",
        "\"program\": \"python\"",
    )?;
    write_file(
        &root,
        "AGENTS.md",
        &format!(
            "# {} plugin instructions\n\n- This project is a TokenSaver Plugin Protocol (TSPP) v1 optimizer. Keep `apiVersion`, `PLUGIN_ID`, `PLUGIN_VERSION`, and `plugin.json` synchronized.\n- Keep stdout exclusively for SDK-managed TSPP frames. Write diagnostics to stderr.\n- Return `pass_output()` whenever an optimization is unsafe or saves less than 20 percent. TokenSaver independently verifies every result.\n- Do not request ambient credentials, network access, or filesystem access. TSPP v1 grants no permissions.\n- `plugin.json` must point to the PyInstaller one-file executable in `dist`, never to Python or a script. Build natively on every target operating system.\n- Add deterministic `fixtures/*.case.json` golden tests for behavior changes. Run both unittest suites, `tsp test .`, `tsp bench .`, and `tsp validate .` before handoff.\n- Use `tsp package .` only after tests, benchmarks, and validation pass. Packaging never installs or activates a plugin.\n- Built-in and community plugins use the same protocol and safety checks. Never add installation or activation behavior to this plugin.\n",
            report.name
        ),
    )?;
    write_file(
        &root,
        ".github/workflows/ci.yml",
        "name: CI\n\non:\n  push:\n  pull_request:\n\njobs:\n  test:\n    strategy:\n      matrix:\n        os: [windows-latest, ubuntu-latest, macos-latest]\n    runs-on: ${{ matrix.os }}\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-python@v5\n        with:\n          python-version: '3.10'\n          cache: pip\n      - run: python -m pip install --requirement requirements-build.txt\n      - run: python -m unittest tests.test_plugin -v\n      - run: python build.py\n        env:\n          PYTHONHASHSEED: '0'\n      - run: python -m unittest tests.test_executable -v\n",
    )?;
    write_file(
        &root,
        "README.md",
        &format!(
            "# {}\n\nA TSPP v1 Python optimizer scaffold. The generated optimizer safely passes output through until you add your own logic. PyInstaller is a pinned build-time tool; the resulting `dist/{}` executable does not require Python on the destination computer. Build natively on each target operating system.\n\n```text\npython -m pip install --requirement requirements-build.txt\npython -m unittest tests.test_plugin -v\npython build.py\npython -m unittest tests.test_executable -v\ntsp run fixtures/smoke.input.txt --plugin . --kind test --program python\ntsp test .\ntsp bench .\ntsp validate .\ntsp package .\n```\n\nUpdate `creator.name`, description, license, capabilities, and platform entries before publishing.\n",
            report.name, binary
        ),
    )?;
    replace_file_text(&root, "wiki/plugin.md", "Action::Pass", "pass_output()")?;
    replace_file_text(
        &root,
        "wiki/plugin.md",
        "Run `cargo test`",
        "Run both Python unittest suites after building the native executable",
    )?;

    report.language = "python".into();
    report.files = [
        ".gitignore",
        "AGENTS.md",
        "README.md",
        "build.py",
        "LICENSE",
        "main.py",
        "requirements-build.txt",
        "tokensaver_plugin/__init__.py",
        "tests/__init__.py",
        "tests/test_plugin.py",
        "tests/test_executable.py",
        "plugin.superec",
        "plugin.json",
        "fixtures/smoke.case.json",
        "fixtures/smoke.input.txt",
        "wiki/index.md",
        "wiki/plugin.md",
        ".github/workflows/ci.yml",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    report.next_steps = vec![
        "Review plugin.json and set creator.name.".into(),
        "Install requirements-build.txt, run the unit tests, and run python build.py.".into(),
        "Run the executable test, tsp test ., tsp bench ., and tsp validate .".into(),
        "Run tsp package . to create the release artifact.".into(),
    ];
    Ok(report)
}

fn scaffold_typescript_plugin(options: &NewOptions) -> Result<NewReport, ValidationError> {
    let sdk = resolve_typescript_sdk_path(options.sdk_path.as_deref())?;
    let sdk_runtime = fs::read_to_string(sdk.join("src/index.js")).map_err(|error| {
        ValidationError::new(
            "new.sdkPath",
            format!("could not read TypeScript SDK runtime: {error}"),
            "Pass --sdk-path pointing to sdk/typescript/tokensaver-plugin.",
        )
    })?;
    let sdk_types = fs::read_to_string(sdk.join("src/index.d.ts")).map_err(|error| {
        ValidationError::new(
            "new.sdkPath",
            format!("could not read TypeScript SDK declarations: {error}"),
            "Pass --sdk-path pointing to sdk/typescript/tokensaver-plugin.",
        )
    })?;
    let mut rust_options = options.clone();
    rust_options.language = "rust".into();
    rust_options.sdk_path = None;
    let mut report = scaffold_rust_plugin(&rust_options)?;
    let root = PathBuf::from(&report.directory);
    let project_name = crate_name(&root)?;
    let binary = if cfg!(windows) {
        format!("{project_name}.exe")
    } else {
        project_name.clone()
    };

    fs::remove_file(root.join("Cargo.toml")).map_err(|error| write_error(&root, error))?;
    fs::remove_file(root.join("src/main.rs")).map_err(|error| write_error(&root, error))?;
    for directory in ["scripts", "tests"] {
        fs::create_dir_all(root.join(directory)).map_err(|error| write_error(&root, error))?;
    }

    write_file(&root, ".gitignore", "/dist\n")?;
    write_file(&root, "src/tokensaver-plugin.js", &sdk_runtime)?;
    write_file(&root, "src/tokensaver-plugin.d.ts", &sdk_types)?;
    write_file(
        &root,
        "src/plugin.ts",
        &format!(
            "import {{ passOutput, type Action, type Identity, type Request }} from \"./tokensaver-plugin.js\";\n\nexport const identity = Object.freeze({{\n  pluginId: {plugin_id:?},\n  version: \"0.1.0\",\n}}) satisfies Identity;\n\nexport function optimize(_request: Request): Action {{\n  // Replace this safe default with your optimizer.\n  return passOutput();\n}}\n",
            plugin_id = report.plugin_id
        ),
    )?;
    write_file(
        &root,
        "src/main.ts",
        "import { run } from \"./tokensaver-plugin.js\";\nimport { identity, optimize } from \"./plugin.js\";\n\nawait run(identity, optimize);\n",
    )?;
    write_file(
        &root,
        "scripts/build.js",
        &format!(
            "import {{ mkdirSync }} from \"node:fs\";\nimport {{ spawnSync }} from \"node:child_process\";\nimport {{ fileURLToPath }} from \"node:url\";\nimport {{ dirname, join }} from \"node:path\";\n\nconst root = dirname(dirname(fileURLToPath(import.meta.url)));\nconst binary = process.platform === \"win32\" ? {windows_binary:?} : {project_name:?};\nconst output = join(root, \"dist\", binary);\nmkdirSync(dirname(output), {{ recursive: true }});\nconst result = spawnSync(process.execPath, [\"build\", join(root, \"src\", \"main.ts\"), \"--compile\", \"--outfile\", output], {{ stdio: \"inherit\" }});\nif (result.error) throw result.error;\nif (result.status !== 0) process.exit(result.status ?? 1);\n",
            windows_binary = format!("{project_name}.exe")
        ),
    )?;
    write_file(
        &root,
        "package.json",
        &format!(
            "{{\n  \"name\": {project_name:?},\n  \"version\": \"0.1.0\",\n  \"private\": true,\n  \"type\": \"module\",\n  \"packageManager\": \"bun@1.4.0\",\n  \"scripts\": {{\n    \"build\": \"bun run scripts/build.js\",\n    \"check\": \"tsc -p tsconfig.json\",\n    \"test\": \"bun test tests/plugin.test.ts\",\n    \"test:executable\": \"bun test tests/executable.test.ts\"\n  }},\n  \"devDependencies\": {{\n    \"typescript\": \"7.0.2\"\n  }}\n}}\n"
        ),
    )?;
    write_file(
        &root,
        "tsconfig.json",
        "{\n  \"compilerOptions\": {\n    \"allowJs\": true,\n    \"exactOptionalPropertyTypes\": true,\n    \"module\": \"ESNext\",\n    \"moduleResolution\": \"Bundler\",\n    \"noEmit\": true,\n    \"noUncheckedIndexedAccess\": true,\n    \"strict\": true,\n    \"target\": \"ES2022\"\n  },\n  \"include\": [\"src/**/*.ts\"]\n}\n",
    )?;
    write_file(
        &root,
        "tests/plugin.test.ts",
        "import { expect, test } from \"bun:test\";\nimport manifest from \"../plugin.json\";\nimport { identity, optimize } from \"../src/plugin.js\";\n\ntest(\"identity matches manifest\", () => {\n  expect(identity.pluginId).toBe(manifest.id);\n  expect(identity.version).toBe(manifest.version);\n});\n\ntest(\"safe default passes output\", () => {\n  expect(optimize({ kind: \"test\", program: \"bun\", exitCode: 0, text: \"ok\", budgetMs: 250 })).toEqual({ action: \"pass\" });\n});\n",
    )?;
    write_file(
        &root,
        "tests/executable.test.ts",
        &format!(
            "import {{ expect, test }} from \"bun:test\";\nimport {{ fileURLToPath }} from \"node:url\";\nimport {{ dirname, join }} from \"node:path\";\n\nconst root = dirname(dirname(fileURLToPath(import.meta.url)));\nconst binary = join(root, \"dist\", process.platform === \"win32\" ? {windows_binary:?} : {project_name:?});\n\nfunction frame(value: unknown): Uint8Array {{\n  const payload = Buffer.from(JSON.stringify(value), \"utf8\");\n  return Buffer.concat([Buffer.from(`Content-Length: ${{payload.length}}\\r\\n\\r\\n`, \"ascii\"), payload]);\n}}\n\nfunction responses(data: Uint8Array): unknown[] {{\n  const bytes = Buffer.from(data);\n  const output: unknown[] = [];\n  let offset = 0;\n  while (offset < bytes.length) {{\n    const boundary = bytes.indexOf(\"\\r\\n\\r\\n\", offset, \"ascii\");\n    const header = bytes.subarray(offset, boundary).toString(\"ascii\");\n    const length = Number(header.slice(header.indexOf(\":\") + 1).trim());\n    const start = boundary + 4;\n    output.push(JSON.parse(bytes.subarray(start, start + length).toString(\"utf8\")));\n    offset = start + length;\n  }}\n  return output;\n}}\n\ntest(\"standalone executable passes output\", async () => {{\n  const child = Bun.spawn([binary], {{ stdin: \"pipe\", stdout: \"pipe\", stderr: \"pipe\" }});\n  child.stdin.write(Buffer.concat([\n    frame({{ jsonrpc: \"2.0\", id: 1, method: \"initialize\", params: {{ apiVersion: 1, host: \"generated-test\", budgetMs: 250 }} }}),\n    frame({{ jsonrpc: \"2.0\", id: 2, method: \"optimize\", params: {{ kind: \"test\", program: \"bun\", exitCode: 0, encoding: \"base64\", content: Buffer.from(\"ok\\n\").toString(\"base64\"), budgetMs: 250 }} }}),\n    frame({{ jsonrpc: \"2.0\", id: 3, method: \"shutdown\", params: {{}} }}),\n  ]));\n  child.stdin.end();\n  const stdout = new Uint8Array(await new Response(child.stdout).arrayBuffer());\n  const stderr = await new Response(child.stderr).text();\n  expect(await child.exited).toBe(0);\n  const messages = responses(stdout) as Array<any>;\n  expect(messages[0].result).toEqual({{ apiVersion: 1, pluginId: {plugin_id:?}, version: \"0.1.0\" }});\n  expect(messages[1].result).toEqual({{ action: \"pass\" }});\n  expect(stderr).toBe(\"\");\n}}, 30_000);\n",
            windows_binary = format!("{project_name}.exe"),
            plugin_id = report.plugin_id
        ),
    )?;

    update_manifest_entry(&root, &binary, "TypeScript")?;
    replace_file_text(
        &root,
        "fixtures/smoke.case.json",
        "\"program\": \"cargo\"",
        "\"program\": \"bun\"",
    )?;
    write_file(
        &root,
        "AGENTS.md",
        &format!(
            "# {} plugin instructions\n\n- This project is a TokenSaver Plugin Protocol (TSPP) v1 optimizer. Keep `apiVersion`, `identity`, and `plugin.json` synchronized.\n- Keep stdout exclusively for SDK-managed TSPP frames. Write diagnostics to stderr.\n- Return `passOutput()` whenever an optimization is unsafe or saves less than 20 percent. TokenSaver independently verifies every result.\n- Do not request ambient credentials, network access, or filesystem access. TSPP v1 grants no permissions.\n- `plugin.json` must point to the Bun-compiled executable in `dist`, never to Bun, Node, or a script. Build natively on every target operating system.\n- TypeScript 7.0.2 is development-only type-checking tooling. It is not part of TSPP, the plugin runtime, or the TokenSaver host.\n- Add deterministic `fixtures/*.case.json` golden tests for behavior changes. Run `bun run check`, both Bun test suites, `tsp test .`, `tsp bench .`, and `tsp validate .` before handoff.\n- Use `tsp package .` only after tests, benchmarks, and validation pass. Packaging never installs or activates a plugin.\n- Built-in and community plugins use the same protocol and safety checks. Never add installation or activation behavior to this plugin.\n",
            report.name
        ),
    )?;
    write_file(
        &root,
        ".github/workflows/ci.yml",
        "name: CI\n\non:\n  push:\n  pull_request:\n\njobs:\n  test:\n    strategy:\n      matrix:\n        os: [windows-latest, ubuntu-latest, macos-latest]\n    runs-on: ${{ matrix.os }}\n    steps:\n      - uses: actions/checkout@v4\n      - uses: oven-sh/setup-bun@v2\n        with:\n          bun-version: '1.4.0'\n      - run: bun install\n      - run: bun run check\n      - run: bun test tests/plugin.test.ts\n      - run: bun run build\n      - run: bun test tests/executable.test.ts\n",
    )?;
    write_file(
        &root,
        "README.md",
        &format!(
            "# {}\n\nA TSPP v1 TypeScript optimizer scaffold. The generated optimizer safely passes output through until you add your own logic. TypeScript 7.0.2 is pinned for development-time type checking only. Bun 1.4.0 remains the pinned native compiler. The resulting `dist/{}` executable requires neither TypeScript, Bun, nor Node on the destination computer. Build natively on each target operating system, and commit the generated `bun.lock` so dependency resolution remains reproducible.\n\n```text\nbun install\nbun run check\nbun test tests/plugin.test.ts\nbun run build\nbun test tests/executable.test.ts\ntsp run fixtures/smoke.input.txt --plugin . --kind test --program bun\ntsp test .\ntsp bench .\ntsp validate .\ntsp package .\n```\n\nUpdate `creator.name`, description, license, capabilities, and platform entries before publishing.\n",
            report.name, binary
        ),
    )?;
    replace_file_text(&root, "wiki/plugin.md", "Action::Pass", "passOutput()")?;
    replace_file_text(
        &root,
        "wiki/plugin.md",
        "Run `cargo test`",
        "Run both Bun test suites after building the native executable",
    )?;

    report.language = "typescript".into();
    report.files = [
        ".gitignore",
        "AGENTS.md",
        "README.md",
        "package.json",
        "LICENSE",
        "tsconfig.json",
        "scripts/build.js",
        "src/main.ts",
        "src/plugin.ts",
        "src/tokensaver-plugin.js",
        "src/tokensaver-plugin.d.ts",
        "tests/plugin.test.ts",
        "tests/executable.test.ts",
        "plugin.superec",
        "plugin.json",
        "fixtures/smoke.case.json",
        "fixtures/smoke.input.txt",
        "wiki/index.md",
        "wiki/plugin.md",
        ".github/workflows/ci.yml",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    report.next_steps = vec![
        "Review plugin.json and set creator.name.".into(),
        "Install pinned Bun 1.4.0, run bun install, bun run check, the unit test, and bun run build.".into(),
        "Run the executable test, tsp test ., tsp bench ., and tsp validate .".into(),
        "Run tsp package . to create the release artifact.".into(),
    ];
    Ok(report)
}

fn crate_name(directory: &Path) -> Result<String, ValidationError> {
    let source = directory
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let mut name = String::new();
    let mut previous_hyphen = false;
    for character in source.chars().flat_map(char::to_lowercase) {
        if character.is_ascii_alphanumeric() {
            name.push(character);
            previous_hyphen = false;
        } else if !name.is_empty() && !previous_hyphen {
            name.push('-');
            previous_hyphen = true;
        }
    }
    while name.ends_with('-') {
        name.pop();
    }
    if name.is_empty() {
        return Err(ValidationError::new(
            "new.name",
            "the target directory does not produce a valid Rust crate name",
            "Use a directory name containing ASCII letters or numbers.",
        ));
    }
    Ok(name)
}

fn title_from_crate(crate_name: &str) -> String {
    crate_name
        .split('-')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut characters = part.chars();
            characters
                .next()
                .map(|first| first.to_ascii_uppercase().to_string() + characters.as_str())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn validate_identity(plugin_id: &str, display_name: &str) -> Result<(), ValidationError> {
    let labels = plugin_id.split('.').collect::<Vec<_>>();
    let valid_id = plugin_id.len() <= 128
        && labels.len() >= 3
        && labels.iter().all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        });
    if !valid_id {
        return Err(ValidationError::new(
            "new.id",
            "plugin id must be reverse-DNS (for example com.example.my-plugin)",
            "Pass --id with at least three lowercase DNS labels.",
        ));
    }
    if display_name.is_empty() || display_name.len() > 64 {
        return Err(ValidationError::new(
            "new.displayName",
            "plugin name is required and must be no longer than 64 UTF-8 bytes",
            "Pass --name with a short display name.",
        ));
    }
    Ok(())
}

fn resolve_sdk_path(explicit: Option<&Path>) -> Result<PathBuf, ValidationError> {
    let path = explicit.map(Path::to_path_buf).unwrap_or_else(|| {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/rust/tokensaver-plugin")
    });
    let path = path.canonicalize().map_err(|error| {
        ValidationError::new(
            "new.sdkPath",
            format!("could not resolve Rust SDK {}: {error}", path.display()),
            "Pass --sdk-path pointing to sdk/rust/tokensaver-plugin.",
        )
    })?;
    if !path.join("Cargo.toml").is_file() {
        return Err(ValidationError::new(
            "new.sdkPath",
            format!("{} is not the Rust SDK crate", path.display()),
            "Pass --sdk-path pointing to sdk/rust/tokensaver-plugin.",
        ));
    }
    Ok(path)
}

fn resolve_go_sdk_path(explicit: Option<&Path>) -> Result<PathBuf, ValidationError> {
    let path = explicit.map(Path::to_path_buf).unwrap_or_else(|| {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/go/tokensaverplugin")
    });
    let path = path.canonicalize().map_err(|error| {
        ValidationError::new(
            "new.sdkPath",
            format!("could not resolve Go SDK {}: {error}", path.display()),
            "Pass --sdk-path pointing to sdk/go/tokensaverplugin.",
        )
    })?;
    if !path.join("go.mod").is_file() {
        return Err(ValidationError::new(
            "new.sdkPath",
            format!("{} is not the Go SDK module", path.display()),
            "Pass --sdk-path pointing to sdk/go/tokensaverplugin.",
        ));
    }
    Ok(path)
}

fn resolve_python_sdk_path(explicit: Option<&Path>) -> Result<PathBuf, ValidationError> {
    let path = explicit
        .map(Path::to_path_buf)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/python"));
    let path = path.canonicalize().map_err(|error| {
        ValidationError::new(
            "new.sdkPath",
            format!("could not resolve Python SDK {}: {error}", path.display()),
            "Pass --sdk-path pointing to sdk/python.",
        )
    })?;
    if !path.join("pyproject.toml").is_file()
        || !path.join("tokensaver_plugin/__init__.py").is_file()
    {
        return Err(ValidationError::new(
            "new.sdkPath",
            format!("{} is not the Python SDK package", path.display()),
            "Pass --sdk-path pointing to sdk/python.",
        ));
    }
    Ok(path)
}

fn resolve_typescript_sdk_path(explicit: Option<&Path>) -> Result<PathBuf, ValidationError> {
    let path = explicit.map(Path::to_path_buf).unwrap_or_else(|| {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/typescript/tokensaver-plugin")
    });
    let path = path.canonicalize().map_err(|error| {
        ValidationError::new(
            "new.sdkPath",
            format!(
                "could not resolve TypeScript SDK {}: {error}",
                path.display()
            ),
            "Pass --sdk-path pointing to sdk/typescript/tokensaver-plugin.",
        )
    })?;
    if !path.join("package.json").is_file()
        || !path.join("src/index.js").is_file()
        || !path.join("src/index.d.ts").is_file()
    {
        return Err(ValidationError::new(
            "new.sdkPath",
            format!("{} is not the TypeScript SDK package", path.display()),
            "Pass --sdk-path pointing to sdk/typescript/tokensaver-plugin.",
        ));
    }
    Ok(path)
}

fn relative_path(from: &Path, to: &Path) -> Option<PathBuf> {
    let from = from.components().collect::<Vec<_>>();
    let to = to.components().collect::<Vec<_>>();
    if matches!((from.first(), to.first()), (Some(Component::Prefix(a)), Some(Component::Prefix(b))) if a != b)
    {
        return None;
    }
    let shared = from
        .iter()
        .zip(&to)
        .take_while(|(left, right)| left == right)
        .count();
    let mut result = PathBuf::new();
    for _ in shared..from.len() {
        result.push("..");
    }
    for component in &to[shared..] {
        result.push(component.as_os_str());
    }
    Some(result)
}

fn cargo_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn write_file(root: &Path, relative: &str, content: &str) -> Result<(), ValidationError> {
    fs::write(root.join(relative), content).map_err(|error| write_error(root, error))
}

fn replace_file_text(
    root: &Path,
    relative: &str,
    before: &str,
    after: &str,
) -> Result<(), ValidationError> {
    let path = root.join(relative);
    let content = fs::read_to_string(&path).map_err(|error| write_error(root, error))?;
    if !content.contains(before) {
        return Err(ValidationError::new(
            "new.template",
            format!("generated template {relative} does not contain {before:?}"),
            "Report this TokenSaver SDK defect.",
        ));
    }
    write_file(root, relative, &content.replace(before, after))
}

fn update_manifest_entry(root: &Path, binary: &str, language: &str) -> Result<(), ValidationError> {
    let manifest_path = root.join("plugin.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(&manifest_path).map_err(|error| write_error(root, error))?,
    )
    .map_err(|error| {
        ValidationError::new(
            "new.manifest",
            format!("could not update generated plugin.json: {error}"),
            "Report this TokenSaver SDK defect.",
        )
    })?;
    manifest["runtime"]["entry"] = json!({ platform_key(): format!("dist/{binary}") });
    write_file(
        root,
        "plugin.json",
        &format!(
            "{}\n",
            serde_json::to_string_pretty(&manifest)
                .unwrap_or_else(|_| panic!("serialize {language} scaffold manifest"))
        ),
    )
}

fn write_error(root: &Path, error: std::io::Error) -> ValidationError {
    ValidationError::new(
        "new.write",
        format!("could not write scaffold in {}: {error}", root.display()),
        "Check directory permissions and retry with a new or empty directory.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{PluginManifest, validate_manifest};
    use serde_json::Value;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDirectory(PathBuf);

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            if self.0.starts_with(std::env::temp_dir()) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn crate_names_and_titles_are_stable() {
        assert_eq!(crate_name(Path::new("My Plugin")).unwrap(), "my-plugin");
        assert_eq!(title_from_crate("my-plugin"), "My Plugin");
        assert!(crate_name(Path::new("---")).is_err());
    }

    #[test]
    fn identity_requires_reverse_dns() {
        assert!(validate_identity("com.example.plugin", "Plugin").is_ok());
        assert!(validate_identity("plugin", "Plugin").is_err());
        assert!(validate_identity("com.Example.plugin", "Plugin").is_err());
    }

    #[test]
    fn scaffold_is_complete_versioned_and_never_overwrites() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = TestDirectory(std::env::temp_dir().join(format!(
            "tokensaver-tsp-scaffold-{}-{unique}",
            std::process::id()
        )));
        let report = scaffold_plugin(&NewOptions {
            directory: directory.0.clone(),
            language: "rust".into(),
            plugin_id: Some("com.example.ai-friendly".into()),
            display_name: Some("AI Friendly".into()),
            sdk_path: None,
        })
        .expect("create scaffold");
        assert!(report.files.contains(&"AGENTS.md".into()));
        assert!(report.files.contains(&"plugin.superec".into()));
        assert!(report.files.contains(&"wiki/index.md".into()));
        assert!(
            fs::read_to_string(directory.0.join("Cargo.toml"))
                .expect("read generated Cargo manifest")
                .contains("[workspace]")
        );

        let manifest: PluginManifest = serde_json::from_slice(
            &fs::read(directory.0.join("plugin.json")).expect("read manifest"),
        )
        .expect("parse manifest");
        validate_manifest(&manifest).expect("validate generated manifest");
        let superec: Value = serde_json::from_slice(
            &fs::read(directory.0.join("plugin.superec")).expect("read SUPEREC graph"),
        )
        .expect("parse SUPEREC graph");
        assert_eq!(superec["format"], "SUPEREC");
        assert_eq!(superec["specVersion"], "0.1.0");
        assert_eq!(
            superec["resources"][0]["identifiers"][0]["value"],
            "com.example.ai-friendly"
        );
        assert_eq!(
            superec["resources"][0]["extensions"]["com.vic-e.tokensaver/plugin"]["knowledge"],
            "wiki/"
        );
        assert!(
            fs::read_to_string(directory.0.join("wiki/index.md"))
                .expect("read OKF index")
                .contains("okf_version: \"0.2\"")
        );

        let error = scaffold_plugin(&NewOptions {
            directory: directory.0.clone(),
            language: "rust".into(),
            plugin_id: None,
            display_name: None,
            sdk_path: None,
        })
        .expect_err("never overwrite a scaffold");
        assert_eq!(error.code, "new.notEmpty");
    }

    #[test]
    fn go_scaffold_is_safe_complete_and_uses_the_public_go_sdk() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = TestDirectory(std::env::temp_dir().join(format!(
            "tokensaver-tsp-go-scaffold-{}-{unique}",
            std::process::id()
        )));
        let report = scaffold_plugin(&NewOptions {
            directory: directory.0.clone(),
            language: "go".into(),
            plugin_id: Some("com.example.go-friendly".into()),
            display_name: Some("Go Friendly".into()),
            sdk_path: None,
        })
        .expect("create Go scaffold");

        assert_eq!(report.language, "go");
        assert!(report.files.contains(&"go.mod".into()));
        assert!(report.files.contains(&"main.go".into()));
        assert!(!report.files.contains(&"Cargo.toml".into()));
        assert!(!directory.0.join("Cargo.toml").exists());
        assert!(!directory.0.join("src").exists());
        let go_mod =
            fs::read_to_string(directory.0.join("go.mod")).expect("read generated Go module");
        assert!(go_mod.starts_with("module com.example.go-friendly/"));
        assert!(
            go_mod.contains("github.com/VIC-E-com/tokensaver-plugin-sdk/sdk/go/tokensaverplugin")
        );
        let main =
            fs::read_to_string(directory.0.join("main.go")).expect("read generated Go source");
        assert!(main.contains("return tsp.Pass()"));
        assert!(main.contains("PluginID: pluginID, Version: pluginVersion"));
        assert!(
            fs::read_to_string(directory.0.join("fixtures/smoke.case.json"))
                .expect("read generated Go fixture")
                .contains("\"program\": \"go\"")
        );

        let manifest: PluginManifest = serde_json::from_slice(
            &fs::read(directory.0.join("plugin.json")).expect("read Go manifest"),
        )
        .expect("parse Go manifest");
        validate_manifest(&manifest).expect("validate generated Go manifest");
        let project_name = crate_name(&directory.0).expect("derive Go binary name");
        let expected_binary = if cfg!(windows) {
            format!("{project_name}.exe")
        } else {
            project_name
        };
        assert_eq!(
            manifest
                .runtime
                .entry
                .get(&platform_key())
                .map(String::as_str),
            Some(expected_binary.as_str())
        );
        let superec: Value = serde_json::from_slice(
            &fs::read(directory.0.join("plugin.superec")).expect("read Go SUPEREC graph"),
        )
        .expect("parse Go SUPEREC graph");
        assert_eq!(superec["format"], "SUPEREC");
        assert_eq!(
            superec["resources"][0]["identifiers"][0]["value"],
            "com.example.go-friendly"
        );
    }

    #[test]
    fn python_scaffold_is_standalone_safe_and_ai_friendly() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = TestDirectory(std::env::temp_dir().join(format!(
            "tokensaver-tsp-python-scaffold-{}-{unique}",
            std::process::id()
        )));
        let report = scaffold_plugin(&NewOptions {
            directory: directory.0.clone(),
            language: "python".into(),
            plugin_id: Some("com.example.python-friendly".into()),
            display_name: Some("Python Friendly".into()),
            sdk_path: None,
        })
        .expect("create Python scaffold");

        assert_eq!(report.language, "python");
        for file in [
            "AGENTS.md",
            "build.py",
            "main.py",
            "requirements-build.txt",
            "tokensaver_plugin/__init__.py",
            "tests/test_plugin.py",
            "tests/test_executable.py",
            "plugin.superec",
            "wiki/index.md",
        ] {
            assert!(report.files.contains(&file.to_owned()), "missing {file}");
        }
        assert!(!directory.0.join("Cargo.toml").exists());
        assert!(!directory.0.join("src").exists());
        let main = fs::read_to_string(directory.0.join("main.py")).expect("read Python source");
        assert!(main.contains("return pass_output()"));
        assert!(main.contains("PLUGIN_ID = \"com.example.python-friendly\""));
        let build = fs::read_to_string(directory.0.join("build.py")).expect("read Python build");
        assert!(build.contains("\"--onefile\""));
        assert!(build.contains("\"--noupx\""));
        let sdk = fs::read_to_string(directory.0.join("tokensaver_plugin/__init__.py"))
            .expect("read vendored Python SDK");
        assert_eq!(
            sdk,
            include_str!("../../../sdk/python/tokensaver_plugin/__init__.py")
        );
        assert_generated_language_contract(&directory.0, "com.example.python-friendly", "dist/");

        let error = scaffold_plugin(&NewOptions {
            directory: directory.0.clone(),
            language: "python".into(),
            plugin_id: None,
            display_name: None,
            sdk_path: None,
        })
        .expect_err("never overwrite Python scaffold");
        assert_eq!(error.code, "new.notEmpty");
    }

    #[test]
    fn typescript_scaffold_is_standalone_safe_and_ai_friendly() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = TestDirectory(std::env::temp_dir().join(format!(
            "tokensaver-tsp-typescript-scaffold-{}-{unique}",
            std::process::id()
        )));
        let report = scaffold_plugin(&NewOptions {
            directory: directory.0.clone(),
            language: "typescript".into(),
            plugin_id: Some("com.example.typescript-friendly".into()),
            display_name: Some("TypeScript Friendly".into()),
            sdk_path: None,
        })
        .expect("create TypeScript scaffold");

        assert_eq!(report.language, "typescript");
        for file in [
            "AGENTS.md",
            "package.json",
            "scripts/build.js",
            "src/main.ts",
            "src/plugin.ts",
            "src/tokensaver-plugin.js",
            "src/tokensaver-plugin.d.ts",
            "tests/plugin.test.ts",
            "tests/executable.test.ts",
            "plugin.superec",
            "wiki/index.md",
        ] {
            assert!(report.files.contains(&file.to_owned()), "missing {file}");
        }
        assert!(!directory.0.join("Cargo.toml").exists());
        assert!(!directory.0.join("src/main.rs").exists());
        let plugin =
            fs::read_to_string(directory.0.join("src/plugin.ts")).expect("read TypeScript source");
        assert!(plugin.contains("return passOutput()"));
        assert!(plugin.contains("pluginId: \"com.example.typescript-friendly\""));
        let package =
            fs::read_to_string(directory.0.join("package.json")).expect("read TypeScript package");
        assert!(package.contains("\"packageManager\": \"bun@1.4.0\""));
        assert!(package.contains("\"typescript\": \"7.0.2\""));
        assert!(package.contains("\"check\": \"tsc -p tsconfig.json\""));
        assert!(package.contains("bun run scripts/build.js"));
        let tsconfig =
            fs::read_to_string(directory.0.join("tsconfig.json")).expect("read tsconfig");
        assert!(tsconfig.contains("\"exactOptionalPropertyTypes\": true"));
        assert!(tsconfig.contains("\"noUncheckedIndexedAccess\": true"));
        let workflow = fs::read_to_string(directory.0.join(".github/workflows/ci.yml"))
            .expect("read TypeScript workflow");
        assert!(workflow.contains("- run: bun install"));
        assert!(workflow.contains("- run: bun run check"));
        let sdk = fs::read_to_string(directory.0.join("src/tokensaver-plugin.js"))
            .expect("read vendored TypeScript SDK");
        assert_eq!(
            sdk,
            include_str!("../../../sdk/typescript/tokensaver-plugin/src/index.js")
        );
        assert_generated_language_contract(
            &directory.0,
            "com.example.typescript-friendly",
            "dist/",
        );

        let error = scaffold_plugin(&NewOptions {
            directory: directory.0.clone(),
            language: "typescript".into(),
            plugin_id: None,
            display_name: None,
            sdk_path: None,
        })
        .expect_err("never overwrite TypeScript scaffold");
        assert_eq!(error.code, "new.notEmpty");
    }

    fn assert_generated_language_contract(root: &Path, plugin_id: &str, entry_prefix: &str) {
        let manifest: PluginManifest = serde_json::from_slice(
            &fs::read(root.join("plugin.json")).expect("read generated manifest"),
        )
        .expect("parse generated manifest");
        validate_manifest(&manifest).expect("validate generated manifest");
        let entry = manifest
            .runtime
            .entry
            .get(&platform_key())
            .expect("current platform entry");
        assert!(entry.starts_with(entry_prefix));
        assert!(!entry.ends_with(".py"));
        assert!(!entry.ends_with(".js"));
        assert!(!entry.ends_with(".ts"));

        let superec: Value = serde_json::from_slice(
            &fs::read(root.join("plugin.superec")).expect("read generated SUPEREC graph"),
        )
        .expect("parse generated SUPEREC graph");
        assert_eq!(superec["format"], "SUPEREC");
        assert_eq!(
            superec["resources"][0]["identifiers"][0]["value"],
            plugin_id
        );
        assert_eq!(
            superec["resources"][0]["extensions"]["com.vic-e.tokensaver/plugin"]["knowledge"],
            "wiki/"
        );
        assert!(
            fs::read_to_string(root.join("wiki/index.md"))
                .expect("read generated OKF index")
                .contains("okf_version: \"0.2\"")
        );
    }

    #[test]
    fn sdk_superec_graph_uses_the_vic_e_standard() {
        let record: Value = serde_json::from_str(include_str!("../../../system.superec"))
            .expect("parse SDK SUPEREC graph");
        assert_eq!(record["format"], "SUPEREC");
        assert_eq!(record["specVersion"], "0.1.0");
        assert_eq!(record["resources"][0]["id"], "tokensaver:system:plugin-sdk");
        let evidence = record["relationships"][0]["evidence"]
            .as_array()
            .expect("SDK protocol evidence");
        for source in [
            "sdk/go/tokensaverplugin/protocol.go",
            "sdk/python/tokensaver_plugin/__init__.py",
            "sdk/rust/tokensaver-plugin/src/protocol.rs",
            "sdk/typescript/tokensaver-plugin/src/index.js",
        ] {
            assert!(
                evidence
                    .iter()
                    .any(|item| item["source"].as_str() == Some(source)),
                "SUPEREC graph is missing {source}"
            );
        }
        let wiki_index = include_str!("../../../wiki/index.md");
        assert!(wiki_index.contains("[Go SDK](go-sdk.md)"));
        assert!(include_str!("../../../wiki/go-sdk.md").contains("standard-library-only"));
    }
}
