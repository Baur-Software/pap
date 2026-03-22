# Model Directory Quirk: Platform-Specific Resource Resolution

## The Problem

Papillion bundles GGUF model files (quantized LLaMA weights) inside the Tauri resource directory under `models/`. However, **Tauri's `resource_dir()` behaves very differently across platforms**, and the bundled model directory path is NOT obvious during development.

## Platform-Specific Behavior

### macOS

**Path:** `{app_bundle}/Contents/Resources/models/`

Example:
```
/Applications/Papillion.app/Contents/Resources/models/tinyllama-1.1b.gguf
```

In development (`cargo tauri dev`), the resource directory is the `src-tauri` directory's configured resources path.

### Windows

**Path:** `{exe_dir}/resources/models/`

Example:
```
C:\Users\You\AppData\Local\Papillion\models\tinyllama-1.1b.gguf
```

### Linux

**Path:** `{exe_dir}/../resources/models/` or `/usr/share/papillion/models/` (depends on packaging)

## The Quirk: Development vs. Production

### Development Mode (`cargo tauri dev`)

When running `cargo tauri dev`, Tauri resolves `resource_dir()` to the build output directory, which includes files from `apps/papillion/models/`.

**Action Required:**
Place bundled model files in:
```
apps/papillion/models/
```

This directory is copied into the Tauri resource directory during the build process.

If files don't exist in this directory, `resolve_bundled_model()` will fail with:
```
Error: Bundled model not found: tinyllama-1.1b.gguf (expected at /path/to/resources/models/tinyllama-1.1b.gguf)
```

### Production Build (`cargo tauri build`)

When building for production, Tauri bundles the resource directory according to platform conventions (macOS bundle, Windows binary dir, Linux package).

## Files Required

To use the built-in LLM provider in Papillion, you must have:

1. **Model file** (GGUF weights):
   ```
   {resource_dir}/models/{model_id}.gguf
   ```
   Example: `tinyllama-1.1b.gguf`

2. **Tokenizer file** (shared across all models):
   ```
   {resource_dir}/models/tokenizer.json
   ```

Without either file, the app will fail to load when you select BuiltIn provider with error:
```
Could not save settings — backend unavailable.
```

And console logs will show:
```
Bundled model not found: tinyllama-1.1b.gguf (expected at ...)
Bundled tokenizer not found (expected at ...)
```

## How It's Resolved

### At App Startup (lib.rs)

```rust
let resource_dir = app
    .path()
    .resource_dir()
    .expect("failed to resolve resource dir");
*app_state.resource_dir.write().unwrap() = resource_dir;
```

This is called in the Tauri setup hook **before any commands are available**.

### When Loading Built-In Model (orchestrator.rs)

```rust
if let LlmProvider::BuiltIn { ref model_id } = config.llm_provider {
    let resource_dir = state
        .resource_dir
        .read()
        .map_err(|e| PapillionError::from(e.to_string()))?
        .clone();
    let mut mgr = state.model_manager.lock().await;
    mgr.ensure_loaded(model_id, &resource_dir)
        .map_err(PapillionError::from)?;
}
```

### Bundled Model Resolution (inference.rs)

```rust
pub fn resolve_bundled_model(
    resource_dir: &Path,
    info: &BuiltInModelInfo,
) -> Result<PathBuf, String> {
    let path = resource_dir.join("models").join(&info.filename);
    if path.exists() {
        Ok(path)
    } else {
        Err(format!(
            "Bundled model not found: {} (expected at {})",
            info.filename,
            path.display()
        ))
    }
}
```

## Implications for Development

### Testing Built-In Provider

1. Download the model file(s) to your machine
2. Place them in the correct resource directory for your platform:
   - **macOS:** `apps/papillion/src-tauri/resources/models/`
   - **Windows:** `apps/papillion/src-tauri/resources/models/`
   - **Linux:** `apps/papillion/src-tauri/resources/models/`

3. Also place `tokenizer.json` in the same directory

4. Run `cargo tauri dev`

5. In Papillion: Settings → General → LLM Provider → Built-in (Recommended)

6. Select a model and click Save

7. The orchestrator should transition to Ready state

### Debugging Missing Model

If you see "Could not save settings — backend unavailable":

1. Check console output in your terminal (not the app console):
   ```
   Bundled model not found: tinyllama-1.1b.gguf (expected at ...)
   ```

2. Verify the file exists at the exact path printed

3. Verify file permissions (readable, not corrupted)

4. Try a smaller model first (tinyllama-1.1b is ~2.2GB, suitable for testing)

## Why This Quirk Exists

Tauri's resource bundling is **intentionally platform-native** to follow OS conventions:

- **macOS** expects resources inside app bundles (`.app/Contents/Resources/`)
- **Windows** expects resources beside the executable
- **Linux** follows FHS (Filesystem Hierarchy Standard)

This prevents non-standard "lib" directories that would confuse system-level tooling.

## Recommendations

### For Contributors

- **Document the required directory** in your setup instructions
- **Provide a setup script** that symlinks or copies models to the right place
- **Add a `.gitignore` rule** for `src-tauri/resources/models/` (models are large and shouldn't be in git)

### For Distributions

- **macOS**: Use `.dmg` packaging to bundle models in the app bundle
- **Windows**: Use installer to place models in `ProgramFiles\Papillion\models\`
- **Linux**: Use package manager to place models in `/usr/share/papillion/models/`

### For Production Deployments

- Ensure models are bundled correctly **before** building the app
- Test `cargo tauri build` locally to verify the resource directory is correct
- Use release builds with `--release` flag for better performance

## See Also

- **Tauri Path Resolution**: https://tauri.app/en/reference/rust/tauri/path/
- **GGUF Format**: https://github.com/ggerganov/ggml/blob/master/docs/gguf.md
- **Candle Model Loading**: https://github.com/huggingface/candle/tree/main/candle-core/examples
