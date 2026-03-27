# Example: Refactoring Templates Tab to Use Service

This document shows a concrete example of migrating `pages/settings/templates_tab/mod.rs` from `bridge::invoke` to the new `PapillonService`.

## Current State (Before Refactoring)

The `TemplatesTab` component currently uses direct `bridge::invoke` calls scattered throughout the file. Here's a representative snippet:

```rust
// Current approach - direct Tauri IPC calls
let create_error = RwSignal::new(None::<String>);
let create_success = RwSignal::new(false);

// In an event handler
match bridge::invoke::<serde_json::Value, ()>(
    "create_template",
    &serde_json::to_value(&template).unwrap(),
).await {
    Ok(_) => {
        create_success.set(true);
        // Reload templates
        if let Ok(global) = bridge::invoke_no_args::<Vec<Template>>("get_global_templates").await
        {
            templates_state.global_templates.set(global);
        }
    },
    Err(e) => {
        create_error.set(Some(e));
    }
}
```

**Issues with current approach:**
- Direct bridge calls scattered throughout
- No abstraction of service operations
- Tightly coupled to Tauri
- Duplication of invoke patterns
- Error handling is verbose

## Refactored State (After Service Integration)

### Step 1: Update Imports

```rust
// Remove these:
// use crate::bridge;

// Add this:
use crate::service::use_papillon_service;
use wasm_bindgen_futures::spawn_local;
```

### Step 2: Get Service Reference

At the start of the component function:

```rust
#[component]
pub fn TemplatesTab() -> impl IntoView {
    let templates_state = expect_context::<TemplatesState>();
    let service = use_papillon_service();  // ← Add this line

    // Rest of the component...
}
```

### Step 3: Refactor Template Creation

**Before:**
```rust
let handle_create = move |_| {
    let template_data = template_to_create.get();
    let name = new_name.get();
    let schema_type = new_schema_type.get();
    let config = new_config.get();

    let template = Template {
        template_name: name.clone(),
        schema_type: schema_type.clone(),
        template_config: config.clone(),
        enabled: true,
        principal_did: None,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    spawn_local(async move {
        match bridge::invoke::<serde_json::Value, ()>(
            "create_template",
            &serde_json::to_value(&template).unwrap(),
        ).await {
            Ok(_) => {
                create_success.set(true);
                new_name.set(String::new());
                new_schema_type.set(String::new());
                new_config.set(String::new());

                // Reload
                if let Ok(global) = bridge::invoke_no_args::<Vec<Template>>("get_global_templates").await {
                    templates_state.global_templates.set(global);
                }
            },
            Err(e) => {
                create_error.set(Some(e));
            }
        }
    });
};
```

**After:**
```rust
let handle_create = {
    let service = service.clone();  // Clone Arc for move closure
    let templates_state = templates_state;

    move |_| {
        let template_data = template_to_create.get();
        let name = new_name.get();
        let schema_type = new_schema_type.get();
        let config = new_config.get();

        let template = Template {
            template_name: name.clone(),
            schema_type: schema_type.clone(),
            template_config: config.clone(),
            enabled: true,
            principal_did: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        };

        let service = service.clone();
        spawn_local(async move {
            match service.create_template(&template).await {
                Ok(_) => {
                    create_success.set(true);
                    new_name.set(String::new());
                    new_schema_type.set(String::new());
                    new_config.set(String::new());

                    // Reload
                    match service.get_global_templates().await {
                        Ok(templates) => {
                            templates_state.global_templates.set(templates);
                        },
                        Err(e) => {
                            eprintln!("Failed to reload templates: {}", e);
                        }
                    }
                },
                Err(e) => {
                    create_error.set(Some(e));
                }
            }
        });
    }
};
```

**Improvements:**
- Service method call is clearer: `service.create_template(&template)`
- Error handling is explicit
- No JSON serialization boilerplate
- Service handles all dispatch logic

### Step 4: Refactor Template Update

**Before:**
```rust
match bridge::invoke::<serde_json::Value, ()>(
    "update_template",
    &serde_json::to_value(&template).unwrap(),
).await {
    Ok(_) => { /* ... */ },
    Err(e) => { /* ... */ }
}
```

**After:**
```rust
match service.update_template(&template).await {
    Ok(_) => { /* ... */ },
    Err(e) => { /* ... */ }
}
```

### Step 5: Refactor Template Delete

**Before:**
```rust
match bridge::invoke::<serde_json::Value, ()>(
    "delete_template",
    &serde_json::json!({ "template_name": template_name }),
).await {
    Ok(_) => { /* ... */ },
    Err(e) => { /* ... */ }
}
```

**After:**
```rust
match service.delete_template(&template_name).await {
    Ok(_) => { /* ... */ },
    Err(e) => { /* ... */ }
}
```

### Step 6: Refactor Template Enable/Disable

**Before:**
```rust
let _ = bridge::invoke::<serde_json::Value, ()>(
    "set_template_enabled",
    &serde_json::json!({
        "template_name": template_name,
        "enabled": !enabled
    }),
).await;
```

**After:**
```rust
let service = service.clone();
spawn_local(async move {
    match service.set_template_enabled(&template_name, !enabled).await {
        Ok(_) => {
            // Refresh templates
            if let Ok(templates) = service.get_global_templates().await {
                templates_state.global_templates.set(templates);
            }
        },
        Err(e) => {
            eprintln!("Failed to toggle template: {}", e);
        }
    }
});
```

## Complete Example: Refactored Function

Here's how the complete refactored create handler would look:

```rust
let handle_create_template = {
    let service = service.clone();
    let templates_state = templates_state;
    let new_name = new_name;
    let new_schema_type = new_schema_type;
    let new_config = new_config;
    let new_config_error = new_config_error;
    let create_error = create_error;
    let create_success = create_success;

    move |_| {
        let name = new_name.get().trim().to_string();
        let schema_type = new_schema_type.get().trim().to_string();
        let config_str = new_config.get().trim().to_string();

        // Validate inputs
        if name.is_empty() || schema_type.is_empty() || config_str.is_empty() {
            create_error.set(Some("All fields are required".into()));
            return;
        }

        // Parse JSON config
        let config = match serde_json::from_str::<TemplateConfig>(&config_str) {
            Ok(c) => c,
            Err(e) => {
                new_config_error.set(Some(format!("Invalid JSON: {}", e)));
                return;
            }
        };

        // Build template
        let template = Template {
            template_name: name.clone(),
            schema_type: schema_type.clone(),
            template_config: config,
            enabled: true,
            principal_did: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        };

        // Dispatch async operation
        let service = service.clone();
        spawn_local(async move {
            match service.create_template(&template).await {
                Ok(_) => {
                    create_success.set(true);
                    new_name.set(String::new());
                    new_schema_type.set(String::new());
                    new_config.set(String::new());
                    new_config_error.set(None);
                    create_error.set(None);

                    // Refresh the template list
                    match service.get_global_templates().await {
                        Ok(templates) => {
                            templates_state.global_templates.set(templates);
                        },
                        Err(e) => {
                            eprintln!("Failed to refresh templates: {}", e);
                            create_error.set(Some(format!("Created but failed to refresh: {}", e)));
                        }
                    }
                },
                Err(e) => {
                    create_error.set(Some(e));
                    create_success.set(false);
                }
            }
        });
    }
};
```

## Summary of Changes

| Aspect | Before | After | Benefit |
|--------|--------|-------|---------|
| **Imports** | `use crate::bridge;` | `use crate::service::use_papillon_service;` | Explicit about abstraction |
| **Getting service** | N/A | `let service = use_papillon_service();` | Single point of access |
| **Create op** | `bridge::invoke(..., "create_template", ...)` | `service.create_template(&template)` | Type-safe, clear intent |
| **Update op** | `bridge::invoke(..., "update_template", ...)` | `service.update_template(&template)` | Type-safe, clear intent |
| **Delete op** | `bridge::invoke(..., "delete_template", ...)` | `service.delete_template(&name)` | Type-safe, simpler API |
| **Fetch op** | `bridge::invoke_no_args(..., "get_global_templates")` | `service.get_global_templates()` | Cleaner, less boilerplate |
| **Error handling** | Manual string conversions | Native `Result<T, String>` | Idiomatic Rust |
| **JSON serialization** | `serde_json::to_value(&obj)?` | Automatic | Less boilerplate |
| **Testability** | Only with full Tauri setup | Can mock `PapillonService` | Easier unit tests |

## Testing the Refactored Component

With the service abstraction, you can now test the component with a mock:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct MockTemplateService {
        templates: Vec<Template>,
    }

    #[async_trait::async_trait(?Send)]
    impl PapillonService for MockTemplateService {
        async fn get_global_templates(&self) -> Result<Vec<Template>, String> {
            Ok(self.templates.clone())
        }

        async fn create_template(&self, _template: &Template) -> Result<(), String> {
            Ok(())
        }

        // ... other methods return Ok(()) or empty defaults
    }

    #[wasm_bindgen_test]
    fn test_template_creation() {
        let service = Arc::new(MockTemplateService {
            templates: vec![],
        });
        provide_context(service);

        // Now test the TemplatesTab component
        // with predictable mock behavior
    }
}
```

## Files to Update (In Order)

1. Remove `use crate::bridge;`
2. Add `use crate::service::use_papillon_service;`
3. Add `let service = use_papillon_service();` at component start
4. Replace each `bridge::invoke*` call with equivalent service method
5. Simplify error handling with service-provided `Result<T, String>`
6. Test with mock service

## Checklist for Component Refactoring

- [ ] Update imports (remove bridge, add service)
- [ ] Get service reference with `use_papillon_service()`
- [ ] Replace all `bridge::invoke` calls with service methods
- [ ] Simplify JSON serialization/deserialization
- [ ] Update error handling to use service errors
- [ ] Test with mock service
- [ ] Verify all operations work identically to before
- [ ] Remove any unused bridge imports
