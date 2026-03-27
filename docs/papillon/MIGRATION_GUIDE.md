# Service Abstraction Migration Guide

This guide explains how to migrate from direct `bridge::invoke` calls to the new `PapillonService` abstraction layer.

## Overview

The service abstraction layer decouples the frontend from Tauri IPC by providing a trait-based interface. This enables:

1. **Runtime flexibility**: Dispatch to Tauri (desktop) or Web (browser) backend based on availability
2. **Testability**: Mock implementations can be provided for unit tests
3. **Code clarity**: Service methods have clear names and semantics
4. **Maintainability**: Changes to backend operations affect only one place

## Architecture

- **`PapillonService` trait**: Defines all operations
- **`TauriService`**: Delegates to `bridge::invoke` (Tauri)
- **`WebService`**: Delegates to IndexedDB (pure WASM)
- **`use_papillon_service()` hook**: Access service from components

## Step-by-Step Migration

### 1. Replace Direct bridge::invoke Calls

**Before:**
```rust
use crate::bridge;

// In a component or effect
let templates = bridge::invoke_no_args::<Vec<Template>>("get_global_templates").await?;
```

**After:**
```rust
use crate::service::use_papillon_service;

// In a component
let service = use_papillon_service();
let templates = service.get_global_templates().await?;
```

### 2. Update Effects to Use Service

**Before:**
```rust
Effect::new(move || {
    if !bridge::tauri_available() {
        return;
    }
    spawn_local(async move {
        if let Ok(templates) = bridge::invoke_no_args::<Vec<Template>>("get_global_templates").await
        {
            templates_state.global_templates.set(templates);
        }
    });
});
```

**After:**
```rust
Effect::new(move || {
    let service = use_papillon_service();
    spawn_local(async move {
        match service.get_global_templates().await {
            Ok(templates) => {
                templates_state.global_templates.set(templates);
            },
            Err(e) => {
                // handle error
            }
        }
    });
});
```

Note: The service automatically handles `tauri_available()` check internally, so you don't need to check it manually.

### 3. Refactor Template Operations

**Template Fetch:**
```rust
// Old
let templates = bridge::invoke_no_args::<Vec<Template>>("get_global_templates").await?;

// New
let templates = service.get_global_templates().await?;
```

**Template Create:**
```rust
// Old
bridge::invoke::<Value, ()>("create_template", &serde_json::to_value(&template)?)?;

// New
service.create_template(&template).await?;
```

**Template Update:**
```rust
// Old
bridge::invoke::<Value, ()>("update_template", &serde_json::to_value(&template)?)?;

// New
service.update_template(&template).await?;
```

**Template Delete:**
```rust
// Old
bridge::invoke::<Value, ()>("delete_template", &json!({ "template_name": template_name }))?;

// New
service.delete_template(&template_name).await?;
```

**Template Enable/Disable:**
```rust
// Old
bridge::invoke::<Value, ()>(
    "set_template_enabled",
    &json!({ "template_name": template_name, "enabled": enabled }),
)?;

// New
service.set_template_enabled(&template_name, enabled).await?;
```

### 4. Refactor Profile Operations

**List Profiles:**
```rust
// Old
let profiles = bridge::invoke_no_args::<Vec<ProfileMetadata>>("list_profiles").await?;

// New
let profiles = service.list_profiles().await?;
```

**Create Profile:**
```rust
// Old
let profile = bridge::invoke::<Value, ProfileMetadata>("create_profile", &json!({ "name": name }))?;

// New
let profile = service.create_profile(&name).await?;
```

**Switch Profile:**
```rust
// Old
let identity = bridge::invoke::<Value, IdentityInfo>(
    "switch_profile",
    &json!({ "profile_id": profile_id }),
)?;

// New
let identity = service.switch_profile(&profile_id).await?;
```

### 5. Refactor Registry Operations

**Navigate Registry:**
```rust
// Old
let info = bridge::invoke::<Value, RegistryInfo>("navigate_registry", &json!({ "url": url }))?;

// New
let info = service.navigate_registry(&url).await?;
```

**List Registry Agents:**
```rust
// Old
let agents = bridge::invoke::<Value, Vec<AgentInfo>>(
    "list_registry_agents",
    &json!({ "registry_url": registry_url }),
)?;

// New
let agents = service.list_registry_agents(&registry_url).await?;
```

### 6. Refactor Orchestrator Operations

**Get Config:**
```rust
// Old
let config = bridge::invoke_no_args::<OrchestratorConfig>("get_orchestrator_config").await?;

// New
let config = service.get_orchestrator_config().await?;
```

**Configure:**
```rust
// Old
bridge::invoke::<Value, OrchestratorConfig>(
    "configure_orchestrator",
    &serde_json::to_value(&config)?,
)?;

// New
service.configure_orchestrator(&config).await?;
```

**Get Status:**
```rust
// Old
let status = bridge::invoke_no_args::<OrchestratorStatus>("get_orchestrator_status").await?;

// New
let status = service.get_orchestrator_status().await?;
```

### 7. Update App Initialization

The App component should provide the service to all child components:

```rust
use crate::service::init_papillon_service;

#[component]
pub fn App() -> impl IntoView {
    // Initialize service on app startup
    spawn_local(async move {
        let service = init_papillon_service().await;
        provide_context(service);
    });

    // Rest of app setup...
}
```

## Service Method Reference

### Templates
- `get_global_templates() -> Result<Vec<Template>, String>`
- `get_profile_templates(principal_did: &str) -> Result<Vec<Template>, String>`
- `create_template(template: &Template) -> Result<(), String>`
- `update_template(template: &Template) -> Result<(), String>`
- `delete_template(template_name: &str) -> Result<(), String>`
- `set_template_enabled(template_name: &str, enabled: bool) -> Result<(), String>`

### Profiles
- `list_profiles() -> Result<Vec<ProfileMetadata>, String>`
- `create_profile(name: &str) -> Result<ProfileMetadata, String>`
- `switch_profile(profile_id: &str) -> Result<IdentityInfo, String>`

### Identity
- `get_identity() -> Result<IdentityInfo, String>`

### Registry & Agents
- `navigate_registry(url: &str) -> Result<RegistryInfo, String>`
- `list_registry_agents(registry_url: &str) -> Result<Vec<AgentInfo>, String>`

### Orchestrator
- `get_orchestrator_config() -> Result<OrchestratorConfig, String>`
- `configure_orchestrator(config: &OrchestratorConfig) -> Result<OrchestratorConfig, String>`
- `get_orchestrator_status() -> Result<OrchestratorStatus, String>`

### Setup
- `get_setup_state() -> Result<SetupState, String>`

### Scenarios
- `list_scenarios() -> Result<Vec<ScenarioCard>, String>`
- `list_completed_runs() -> Result<Vec<ScenarioRunResult>, String>`
- `run_scenario(scenario_id: &str, params: &Value) -> Result<ScenarioRunResult, String>`

### Agent Profiles
- `list_agent_profiles() -> Result<Vec<AgentProfileInfo>, String>`
- `create_agent_profile(name: &str, agent_did: &str) -> Result<AgentProfileInfo, String>`
- `update_agent_profile(profile: &AgentProfileInfo) -> Result<(), String>`
- `delete_agent_profile(profile_id: &str) -> Result<(), String>`

## Error Handling

Both implementations return `Result<T, String>` for simplicity. When an operation fails:

```rust
match service.get_global_templates().await {
    Ok(templates) => {
        // use templates
    },
    Err(e) => {
        eprintln!("Failed to load templates: {}", e);
        // show error UI or fallback behavior
    }
}
```

## WebService Implementation Status

The `WebService` implementation is currently a placeholder. To fully implement it:

1. Add IndexedDB bindings (via `web-sys`, `wasm-bindgen`, or a dedicated crate)
2. Implement each CRUD method with actual database calls
3. For operations requiring backend compute (orchestrator, scenario execution),
   return appropriate errors or stubs

## Testing

To mock the service in tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct MockService {
        // test data
    }

    #[async_trait::async_trait(?Send)]
    impl PapillonService for MockService {
        async fn get_global_templates(&self) -> Result<Vec<Template>, String> {
            Ok(vec![
                // test templates
            ])
        }
        // ... other methods
    }

    #[tokio::test]
    async fn test_with_mock() {
        let service: Arc<dyn PapillonService> = Arc::new(MockService {
            // ...
        });
        provide_context(service);

        // run your component tests
    }
}
```

## Files to Update (Priority Order)

1. **templates_tab/mod.rs** - Heavy template CRUD operations
2. **settings.rs** - Settings and profile operations
3. **app.rs** - Initial data loading
4. **components/topbar.rs** - Profile switching
5. **components/address_bar.rs** - Registry navigation
6. **pages/activity.rs** - Episode list
7. **pages/dashboard.rs** - Dashboard data
8. **pages/home.rs** - Scenario list
9. **pages/scenario.rs** - Scenario execution
10. **pages/canvas.rs** - Canvas state operations

## Rollout Strategy

1. Create the service module (✓ done)
2. Update App.rs to provide service context
3. Migrate template operations first (highest usage)
4. Migrate profile/identity operations
5. Migrate registry operations
6. Migrate orchestrator operations
7. Migrate remaining operations
8. Remove direct bridge usage from codebase
9. Deprecate bridge module or convert to pure internal utility

## FAQs

**Q: Do I need to check `tauri_available()` anymore?**
A: No! The service handles that internally. Both TauriService and WebService check availability.

**Q: What if I'm running outside Tauri?**
A: The service will automatically dispatch to WebService. Currently it returns errors for unimplemented operations. Implement WebService methods with IndexedDB backing.

**Q: Can I still use bridge directly?**
A: Yes, but it's discouraged. The service provides a better abstraction. Direct bridge usage should be limited to internal bridge module code only.

**Q: How do I add a new operation?**
A: 1. Add method to `PapillonService` trait
   2. Implement in both `TauriService` and `WebService`
   3. Update this guide
   4. Update any backend commands as needed
