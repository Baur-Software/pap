#!/usr/bin/env python3
"""
Add configurable_properties to all catalog agents based on URL template analysis.

Agents advertise their settings as schema.org PropertyValueSpecification objects.
This script reads each agent TOML, identifies tunable parameters from the URL
template, and appends appropriate [[configurable_properties]] entries.

Properties added:
1. results_per_page — universal for any agent with pagination params
2. language — for agents with language/lang params
3. sort_by — for agents with sort params
4. safe_search — for search-category agents
5. units — for weather agents
6. include_adult — for entertainment/media agents with adult content potential
"""

import os
import re
import sys
from pathlib import Path

CATALOG_DIR = Path(__file__).parent.parent / "crates" / "pap-agents" / "catalog"

# Pagination parameter patterns in URL templates
PAGINATION_PATTERNS = [
    (r'[?&]per_page=(\d+)', 'per_page'),
    (r'[?&]pageSize=(\d+)', 'pageSize'),
    (r'[?&]page_size=(\d+)', 'page_size'),
    (r'[?&]limit=(\d+)', 'limit'),
    (r'[?&]size=(\d+)', 'size'),
    (r'[?&]rows=(\d+)', 'rows'),
    (r'[?&]count=(\d+)', 'count'),
    (r'[?&]num=(\d+)', 'num'),
    (r'[?&]max_results=(\d+)', 'max_results'),
    (r'[?&]maxResults=(\d+)', 'maxResults'),
    (r'[?&]retmax=(\d+)', 'retmax'),
    (r'[?&]hitsPerPage=(\d+)', 'hitsPerPage'),
    (r'[?&]maxRows=(\d+)', 'maxRows'),
    (r'[?&]ps=(\d+)', 'ps'),
    (r'[?&]per-page=(\d+)', 'per-page'),
    (r'[?&]mrv=(\d+)', 'mrv'),
    (r'[?&]n=(\d+)', 'n'),
    (r'[?&]top=(\d+)', 'top'),
    (r'[?&]number=(\d+)', 'number'),
    (r'page\[size\]=(\d+)', 'page[size]'),
    (r'[?&]_limit=(\d+)', '_limit'),
    (r'[?&]amount=(\d+)', 'amount'),
    (r'[?&]results=(\d+)', 'results'),
    (r'[?&]rpp=(\d+)', 'rpp'),
    (r'[?&]items=(\d+)', 'items'),
    (r'[?&]numOfRows=(\d+)', 'numOfRows'),
    (r'[?&]resultCount=(\d+)', 'resultCount'),
]

LANGUAGE_PATTERNS = [
    r'[?&]language=([^&]+)',
    r'[?&]lang=([^&]+)',
    r'[?&]locale=([^&]+)',
    r'[?&]hl=([^&]+)',
]

SORT_PATTERNS = [
    r'[?&]sort=([^&]+)',
    r'[?&]sort_by=([^&]+)',
    r'[?&]sortBy=([^&]+)',
    r'[?&]order=([^&]+)',
    r'[?&]orderBy=([^&]+)',
]


def find_pagination(url_template):
    """Find pagination parameter and its default value."""
    for pattern, param_name in PAGINATION_PATTERNS:
        m = re.search(pattern, url_template)
        if m:
            return param_name, int(m.group(1))
    return None, None


def has_language_param(url_template):
    """Check if URL template has a language parameter."""
    for pattern in LANGUAGE_PATTERNS:
        if re.search(pattern, url_template):
            return True
    return False


def find_sort_param(url_template):
    """Find sort parameter and its current value."""
    for pattern in SORT_PATTERNS:
        m = re.search(pattern, url_template)
        if m:
            val = m.group(1)
            # Skip if it's a template variable like {sort}
            if '{' in val:
                continue
            return val
    return None


def already_has_configurable_properties(content):
    """Check if the file already has configurable_properties."""
    return '[[configurable_properties]]' in content


def build_properties_block(category, url_template):
    """Build the configurable_properties TOML block for an agent."""
    properties = []

    # 1. Results per page (universal)
    param_name, default_val = find_pagination(url_template)
    if param_name:
        max_val = 50 if default_val and default_val <= 10 else 100
        properties.append({
            'type': 'PropertyValueSpecification',
            'valueName': 'results_per_page',
            'name': 'Results Per Page',
            'description': 'Maximum number of results to return per query',
            'defaultValue': default_val or 5,
            'minValue': 1,
            'maxValue': max_val,
        })

    # 2. Language (if present in URL)
    if has_language_param(url_template):
        properties.append({
            'type': 'PropertyValueSpecification',
            'valueName': 'language',
            'name': 'Language',
            'description': 'Preferred language for results',
            'defaultValue': 'en',
        })

    # 3. Sort (if present in URL)
    sort_val = find_sort_param(url_template)
    if sort_val:
        # Build sort options based on category
        sort_options = get_sort_options(category, sort_val)
        if sort_options:
            properties.append({
                'type': 'PropertyValueSpecification',
                'valueName': 'sort_by',
                'name': 'Sort Order',
                'description': 'How to order results',
                'defaultValue': sort_val,
                'valuePattern': sort_options,
            })

    # 4. Category-specific properties
    category_props = get_category_specific_properties(category, url_template)
    properties.extend(category_props)

    return properties


def get_sort_options(category, current_val):
    """Get sort options based on category."""
    category_sorts = {
        'search': 'relevance|date|popularity',
        'developer': 'relevance|stars|updated|downloads',
        'entertainment': 'relevance|rating|date|popularity',
        'education': 'relevance|date|citations',
        'science': 'relevance|date|citations',
        'media': 'relevance|hot|top|new',
        'finance': 'relevance|date|volume',
        'commerce': 'relevance|price|popularity|newest',
        'arts': 'relevance|date|artist',
        'jobs': 'relevance|date|salary',
        'sports': 'relevance|date|score',
        'health': 'relevance|date|enrollment',
        'social': 'relevance|recent|popular',
    }
    options = category_sorts.get(category)
    if options and current_val not in options:
        options = f"{current_val}|{options}"
    return options


def get_category_specific_properties(category, url_template):
    """Get category-specific configurable properties."""
    props = []

    if category == 'weather':
        # Units (metric/imperial)
        if 'units=' in url_template or 'unitGroup=' in url_template:
            props.append({
                'type': 'PropertyValueSpecification',
                'valueName': 'units',
                'name': 'Units',
                'description': 'Measurement system for temperature and wind',
                'defaultValue': 'metric',
                'valuePattern': 'metric|imperial',
            })
        # Forecast days
        if 'forecast_days=' in url_template:
            props.append({
                'type': 'PropertyValueSpecification',
                'valueName': 'forecast_days',
                'name': 'Forecast Days',
                'description': 'Number of days to forecast ahead',
                'defaultValue': 2,
                'minValue': 1,
                'maxValue': 16,
            })

    elif category == 'search':
        # Safe search
        props.append({
            'type': 'PropertyValueSpecification',
            'valueName': 'safe_search',
            'name': 'Safe Search',
            'description': 'Filter explicit content from results',
            'defaultValue': True,
        })

    elif category in ('entertainment', 'media', 'social'):
        # Include adult/NSFW content
        props.append({
            'type': 'PropertyValueSpecification',
            'valueName': 'include_adult_content',
            'name': 'Include Adult Content',
            'description': 'Show results that may contain mature content',
            'defaultValue': False,
        })

    elif category in ('education', 'science'):
        # Open access only
        if category == 'education':
            props.append({
                'type': 'PropertyValueSpecification',
                'valueName': 'open_access_only',
                'name': 'Open Access Only',
                'description': 'Only return freely accessible publications',
                'defaultValue': False,
            })

    elif category == 'developer':
        # Include deprecated
        props.append({
            'type': 'PropertyValueSpecification',
            'valueName': 'include_deprecated',
            'name': 'Include Deprecated',
            'description': 'Show deprecated or archived packages',
            'defaultValue': False,
        })

    elif category == 'jobs':
        # Remote only
        props.append({
            'type': 'PropertyValueSpecification',
            'valueName': 'remote_only',
            'name': 'Remote Only',
            'description': 'Show only remote-friendly positions',
            'defaultValue': False,
        })

    elif category == 'arts':
        # Require images
        if 'hasImages=' in url_template or 'imgonly=' in url_template:
            props.append({
                'type': 'PropertyValueSpecification',
                'valueName': 'require_images',
                'name': 'Require Images',
                'description': 'Only return items that have images',
                'defaultValue': True,
            })

    elif category == 'food':
        # Dietary restrictions (text input for now)
        props.append({
            'type': 'PropertyValueSpecification',
            'valueName': 'dietary_filter',
            'name': 'Dietary Filter',
            'description': 'Filter by dietary category',
            'defaultValue': '',
            'valuePattern': 'none|vegetarian|vegan|gluten-free',
        })

    elif category == 'travel':
        # Open now
        props.append({
            'type': 'PropertyValueSpecification',
            'valueName': 'open_now',
            'name': 'Open Now',
            'description': 'Only show currently open venues',
            'defaultValue': False,
        })

    return props


def format_toml_value(val):
    """Format a Python value as TOML."""
    if isinstance(val, bool):
        return 'true' if val else 'false'
    elif isinstance(val, int):
        return str(val)
    elif isinstance(val, float):
        return str(val)
    elif isinstance(val, str):
        return f'"{val}"'
    else:
        return str(val)


def format_property_toml(prop):
    """Format a single property as TOML [[configurable_properties]] block."""
    lines = ['[[configurable_properties]]']
    lines.append('"@type" = "PropertyValueSpecification"')
    lines.append(f'valueName = "{prop["valueName"]}"')
    lines.append(f'name = "{prop["name"]}"')
    lines.append(f'description = "{prop["description"]}"')
    lines.append(f'defaultValue = {format_toml_value(prop["defaultValue"])}')

    if 'minValue' in prop:
        lines.append(f'minValue = {prop["minValue"]}')
    if 'maxValue' in prop:
        lines.append(f'maxValue = {prop["maxValue"]}')
    if 'valuePattern' in prop:
        lines.append(f'valuePattern = "{prop["valuePattern"]}"')

    return '\n'.join(lines)


def process_agent(filepath, dry_run=False):
    """Process a single agent TOML file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Skip if already has configurable_properties
    if already_has_configurable_properties(content):
        return 'skip', 0

    # Extract category from path
    category = filepath.parent.name

    # Find URL template
    url_match = re.search(r'url_template\s*=\s*"([^"]+)"', content)
    if not url_match:
        return 'no_url', 0

    url_template = url_match.group(1)

    # Build properties
    properties = build_properties_block(category, url_template)

    if not properties:
        return 'no_props', 0

    # Deduplicate by valueName
    seen = set()
    deduped = []
    for p in properties:
        if p['valueName'] not in seen:
            seen.add(p['valueName'])
            deduped.append(p)
    properties = deduped

    # Format TOML blocks
    blocks = []
    for prop in properties:
        blocks.append(format_property_toml(prop))

    props_text = '\n\n'.join(blocks)
    new_content = content.rstrip() + '\n\n# Agent-advertised configurable properties (schema.org PropertyValueSpecification)\n' + props_text + '\n'

    if not dry_run:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)

    return 'updated', len(properties)


def main():
    dry_run = '--dry-run' in sys.argv
    verbose = '--verbose' in sys.argv or '-v' in sys.argv

    if dry_run:
        print("=== DRY RUN — no files will be modified ===\n")

    stats = {'updated': 0, 'skip': 0, 'no_url': 0, 'no_props': 0, 'total_props': 0}
    category_stats = {}

    for toml_path in sorted(CATALOG_DIR.rglob('*.toml')):
        category = toml_path.parent.name
        result, prop_count = process_agent(toml_path, dry_run=dry_run)

        stats[result] += 1
        stats['total_props'] += prop_count

        if category not in category_stats:
            category_stats[category] = {'updated': 0, 'skip': 0, 'total_props': 0}
        category_stats[category][result if result in ('updated', 'skip') else 'skip'] += 1
        category_stats[category]['total_props'] += prop_count

        if verbose and result == 'updated':
            print(f"  {toml_path.relative_to(CATALOG_DIR)} — {prop_count} properties")

    print(f"\n{'DRY RUN ' if dry_run else ''}SUMMARY")
    print(f"  Updated:       {stats['updated']} agents")
    print(f"  Already done:  {stats['skip']} agents")
    print(f"  No URL:        {stats['no_url']} agents")
    print(f"  No properties: {stats['no_props']} agents")
    print(f"  Total props:   {stats['total_props']} PropertyValueSpecification entries")

    print(f"\nBy category:")
    for cat in sorted(category_stats.keys()):
        cs = category_stats[cat]
        if cs['updated'] > 0:
            print(f"  {cat:20s}: {cs['updated']:3d} updated, {cs['total_props']:3d} properties")


if __name__ == '__main__':
    main()
