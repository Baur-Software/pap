export interface ScopeAction {
  action: string;
  object?: string;
  conditions: Record<string, unknown>;
}

/** Scope defines permitted actions (deny-by-default). */
export class Scope {
  constructor(public readonly actions: ScopeAction[]) {}

  /** Deny-all scope: no actions permitted. */
  static denyAll(): Scope {
    return new Scope([]);
  }

  /** Check if a specific action type is permitted. */
  permits(action: string): boolean {
    return this.actions.some((a) => a.action === action);
  }

  /**
   * Check if a child scope is contained by this (parent) scope.
   * For every child action, parent must have a matching action
   * where child doesn't broaden the object constraint.
   */
  contains(child: Scope): boolean {
    return child.actions.every((childAction) =>
      this.actions.some((parentAction) => {
        if (childAction.action !== parentAction.action) return false;
        // If parent constrains object, child must match exactly
        if (parentAction.object != null && childAction.object !== parentAction.object) return false;
        return true;
      }),
    );
  }

  toJSON(): { actions: ScopeAction[] } {
    return { actions: this.actions };
  }
}

export interface DisclosureEntry {
  type: string;
  permitted_properties: string[];
  prohibited_properties: string[];
  session_only?: boolean;
  no_retention?: boolean;
}

/** Disclosure set defines context classes and sharing conditions. */
export class DisclosureSet {
  constructor(public readonly entries: DisclosureEntry[]) {}

  static empty(): DisclosureSet {
    return new DisclosureSet([]);
  }

  /** Returns true if any entry has no_retention: true (requires TEE). */
  requiresTee(): boolean {
    return this.entries.some((e) => e.no_retention === true);
  }

  /** Property references in "schema:Type.schema:property" format. */
  propertyRefs(): string[] {
    const refs: string[] = [];
    for (const entry of this.entries) {
      for (const prop of entry.permitted_properties) {
        refs.push(`${entry.type}.${prop}`);
      }
    }
    return refs;
  }

  toJSON(): { entries: DisclosureEntry[] } {
    return { entries: this.entries };
  }
}
