use leptos::prelude::*;
use papillon_shared::types::{FieldMapping, LayoutConfig, TemplateConfig};

/// Pre-built template example
#[derive(Clone, Debug, PartialEq)]
pub struct TemplateExample {
    pub name: String,
    pub schema_type: String,
    pub description: String,
    pub config: TemplateConfig,
}

/// Get the library of pre-built template examples
pub fn get_template_library() -> Vec<TemplateExample> {
    vec![
        TemplateExample {
            name: "Flight Reservation".to_string(),
            schema_type: "FlightReservation".to_string(),
            description: "Display flight booking details with departure/arrival times".to_string(),
            config: TemplateConfig {
                version: 1,
                layout: LayoutConfig {
                    r#type: "grid".to_string(),
                    columns: Some(2),
                    direction: None,
                    spacing: Some("md".to_string()),
                },
                fields: vec![
                    FieldMapping {
                        path: "reservationNumber".to_string(),
                        label: Some("Confirmation".to_string()),
                        display: "text".to_string(),
                        condition: None,
                        style: None,
                    },
                    FieldMapping {
                        path: "reservationFor.flightNumber".to_string(),
                        label: Some("Flight".to_string()),
                        display: "text".to_string(),
                        condition: None,
                        style: None,
                    },
                    FieldMapping {
                        path: "reservationFor.departureAirport.name".to_string(),
                        label: Some("From".to_string()),
                        display: "text".to_string(),
                        condition: None,
                        style: None,
                    },
                    FieldMapping {
                        path: "reservationFor.arrivalAirport.name".to_string(),
                        label: Some("To".to_string()),
                        display: "text".to_string(),
                        condition: None,
                        style: None,
                    },
                ],
            },
        },
        TemplateExample {
            name: "Hotel Reservation".to_string(),
            schema_type: "LodgingReservation".to_string(),
            description: "Display hotel booking with check-in/check-out dates".to_string(),
            config: TemplateConfig {
                version: 1,
                layout: LayoutConfig {
                    r#type: "grid".to_string(),
                    columns: Some(2),
                    direction: None,
                    spacing: Some("md".to_string()),
                },
                fields: vec![
                    FieldMapping {
                        path: "reservationNumber".to_string(),
                        label: Some("Confirmation".to_string()),
                        display: "text".to_string(),
                        condition: None,
                        style: None,
                    },
                    FieldMapping {
                        path: "reservationFor.name".to_string(),
                        label: Some("Hotel".to_string()),
                        display: "title".to_string(),
                        condition: None,
                        style: None,
                    },
                    FieldMapping {
                        path: "checkinDate".to_string(),
                        label: Some("Check-In".to_string()),
                        display: "date".to_string(),
                        condition: None,
                        style: None,
                    },
                    FieldMapping {
                        path: "checkoutDate".to_string(),
                        label: Some("Check-Out".to_string()),
                        display: "date".to_string(),
                        condition: None,
                        style: None,
                    },
                ],
            },
        },
        TemplateExample {
            name: "Product".to_string(),
            schema_type: "Product".to_string(),
            description: "Display product information with name, price, and image".to_string(),
            config: TemplateConfig {
                version: 1,
                layout: LayoutConfig {
                    r#type: "flex".to_string(),
                    columns: None,
                    direction: Some("column".to_string()),
                    spacing: Some("md".to_string()),
                },
                fields: vec![
                    FieldMapping {
                        path: "name".to_string(),
                        label: Some("Product".to_string()),
                        display: "title".to_string(),
                        condition: None,
                        style: None,
                    },
                    FieldMapping {
                        path: "description".to_string(),
                        label: None,
                        display: "text".to_string(),
                        condition: None,
                        style: None,
                    },
                    FieldMapping {
                        path: "offers.0.price".to_string(),
                        label: Some("Price".to_string()),
                        display: "price".to_string(),
                        condition: None,
                        style: None,
                    },
                ],
            },
        },
        TemplateExample {
            name: "Event".to_string(),
            schema_type: "Event".to_string(),
            description: "Display event details with date, time, and location".to_string(),
            config: TemplateConfig {
                version: 1,
                layout: LayoutConfig {
                    r#type: "grid".to_string(),
                    columns: Some(2),
                    direction: None,
                    spacing: Some("md".to_string()),
                },
                fields: vec![
                    FieldMapping {
                        path: "name".to_string(),
                        label: Some("Event".to_string()),
                        display: "title".to_string(),
                        condition: None,
                        style: None,
                    },
                    FieldMapping {
                        path: "startDate".to_string(),
                        label: Some("Start".to_string()),
                        display: "date".to_string(),
                        condition: None,
                        style: None,
                    },
                    FieldMapping {
                        path: "endDate".to_string(),
                        label: Some("End".to_string()),
                        display: "date".to_string(),
                        condition: None,
                        style: None,
                    },
                    FieldMapping {
                        path: "location.name".to_string(),
                        label: Some("Location".to_string()),
                        display: "text".to_string(),
                        condition: None,
                        style: None,
                    },
                ],
            },
        },
        TemplateExample {
            name: "Recipe".to_string(),
            schema_type: "Recipe".to_string(),
            description: "Display recipe with ingredients and cooking time".to_string(),
            config: TemplateConfig {
                version: 1,
                layout: LayoutConfig {
                    r#type: "flex".to_string(),
                    columns: None,
                    direction: Some("column".to_string()),
                    spacing: Some("md".to_string()),
                },
                fields: vec![
                    FieldMapping {
                        path: "name".to_string(),
                        label: Some("Recipe".to_string()),
                        display: "title".to_string(),
                        condition: None,
                        style: None,
                    },
                    FieldMapping {
                        path: "author.name".to_string(),
                        label: Some("Chef".to_string()),
                        display: "text".to_string(),
                        condition: None,
                        style: None,
                    },
                    FieldMapping {
                        path: "prepTime".to_string(),
                        label: Some("Prep Time".to_string()),
                        display: "text".to_string(),
                        condition: None,
                        style: None,
                    },
                    FieldMapping {
                        path: "cookTime".to_string(),
                        label: Some("Cook Time".to_string()),
                        display: "text".to_string(),
                        condition: None,
                        style: None,
                    },
                ],
            },
        },
    ]
}

#[component]
pub fn TemplateLibrary(
    is_open: RwSignal<bool>,
    on_select: Callback<TemplateExample>,
) -> impl IntoView {
    let library = RwSignal::new(get_template_library());

    view! {
        <Show when=move || is_open.get()>
            <div style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0, 0, 0, 0.5); display: flex; align-items: center; justify-content: center; z-index: 1001;">
                <div style="background: var(--bg-1); border: 1px solid var(--border); border-radius: 8px; padding: 20px; max-width: 700px; width: 95%; max-height: 80vh; overflow-y: auto; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);">
                    <h3 style="font-size: 16px; font-weight: 600; margin-bottom: 16px;">
                        "Template Library"
                    </h3>

                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px;">
                        <For
                            each=move || library.get()
                            key=|t| t.name.clone()
                            children=move |template| {
                                let on_select = on_select;
                                let name = template.name.clone();
                                let schema_type = template.schema_type.clone();
                                let description = template.description.clone();
                                view! {
                                    <div style="border: 1px solid var(--border); border-radius: 8px; padding: 12px; display: flex; flex-direction: column; gap: 8px; background: var(--bg-tertiary);">
                                        <div style="font-weight: 600; font-size: 13px;">
                                            {name}
                                        </div>
                                        <div style="font-size: 11px; color: var(--text-2);">
                                            {schema_type}
                                        </div>
                                        <div style="font-size: 12px; color: var(--text-2); flex: 1;">
                                            {description}
                                        </div>
                                        <button
                                            class="btn"
                                            on:click=move |_| {
                                                on_select.run(template.clone());
                                                is_open.set(false);
                                            }
                                            style="padding: 8px 16px; background: var(--teal); color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;"
                                        >
                                            "Copy & Customize"
                                        </button>
                                    </div>
                                }
                            }
                        />
                    </div>

                    <div style="display: flex; justify-content: flex-end; margin-top: 16px;">
                        <button
                            class="btn"
                            on:click=move |_| is_open.set(false)
                            style="padding: 8px 16px; background: var(--bg-tertiary); color: var(--text-1); border: 1px solid var(--border); border-radius: 8px; cursor: pointer; font-size: 13px;"
                        >
                            "Close"
                        </button>
                    </div>
                </div>
            </div>
        </Show>
    }
}
