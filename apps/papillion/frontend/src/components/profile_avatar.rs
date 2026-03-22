use leptos::prelude::*;

/// Profile avatar sizes
#[derive(Clone, Copy, Debug)]
pub enum AvatarSize {
    Sm, // 24px
    Md, // 32px
    Lg, // 48px
}

impl AvatarSize {
    fn class_name(&self) -> &'static str {
        match self {
            AvatarSize::Sm => "profile-avatar-sm",
            AvatarSize::Md => "profile-avatar-md",
            AvatarSize::Lg => "profile-avatar-lg",
        }
    }
}

/// Generate deterministic color based on profile name
/// Uses 6-color palette from design system
fn profile_color(name: &str) -> &'static str {
    let hash = name.chars().map(|c| c as u32).sum::<u32>() as usize;
    let colors = [
        "var(--purple)", // #6c5ce7 - Brand, identity
        "var(--teal)",   // #2ec4a0 - Trust confirmed
        "var(--gold)",   // #f0a030 - In-progress
        "var(--coral)",  // #e8706a - Alert
        "var(--blue)",   // #5098e0 - Information
        "var(--rose)",   // #e060a0 - Delight
    ];
    colors[hash % colors.len()]
}

/// Generate 2-letter initials from profile name
fn profile_initials(name: &str) -> String {
    name.split_whitespace()
        .take(2)
        .filter_map(|word| word.chars().next())
        .map(|c| c.to_uppercase().to_string())
        .collect::<String>()
}

#[component]
pub fn ProfileAvatar(
    /// Profile name used for color and initials generation
    name: String,
    /// Avatar size (default: Md)
    #[prop(default = AvatarSize::Md)]
    size: AvatarSize,
) -> impl IntoView {
    let initials = profile_initials(&name);
    let color = profile_color(&name);
    let class_name = size.class_name();

    view! {
        <div
            class=format!("profile-avatar {}", class_name)
            style=format!("background-color: {}", color)
            title=name
        >
            {initials}
        </div>
    }
}
