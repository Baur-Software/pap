import { describe, it, expect } from 'vitest';
import { Scope, DisclosureSet } from '../src/scope.js';
import type { ScopeAction, DisclosureEntry } from '../src/scope.js';

describe('Scope', () => {
  const searchAction: ScopeAction = { action: 'schema:SearchAction', conditions: {} };
  const payAction: ScopeAction = { action: 'schema:PayAction', conditions: {} };
  const flightSearch: ScopeAction = { action: 'schema:SearchAction', object: 'schema:Flight', conditions: {} };

  it('denyAll permits nothing', () => {
    const scope = Scope.denyAll();
    expect(scope.permits('schema:SearchAction')).toBe(false);
    expect(scope.actions).toHaveLength(0);
  });

  it('permits checks action type', () => {
    const scope = new Scope([searchAction]);
    expect(scope.permits('schema:SearchAction')).toBe(true);
    expect(scope.permits('schema:PayAction')).toBe(false);
  });

  it('contains: child subset of parent', () => {
    const parent = new Scope([searchAction, payAction]);
    const child = new Scope([searchAction]);
    expect(parent.contains(child)).toBe(true);
  });

  it('contains: child not subset', () => {
    const parent = new Scope([searchAction]);
    const child = new Scope([searchAction, payAction]);
    expect(parent.contains(child)).toBe(false);
  });

  it('contains: empty child is always contained', () => {
    const parent = new Scope([searchAction]);
    const child = Scope.denyAll();
    expect(parent.contains(child)).toBe(true);
  });

  it('contains: object constraint narrowing', () => {
    // Parent has no object constraint, child narrows to Flight
    const parent = new Scope([searchAction]);
    const child = new Scope([flightSearch]);
    expect(parent.contains(child)).toBe(true);
  });

  it('contains: child cannot broaden object constraint', () => {
    // Parent constrains to Flight, child tries to remove constraint
    const parent = new Scope([flightSearch]);
    const child = new Scope([searchAction]); // no object = broader
    expect(parent.contains(child)).toBe(false);
  });

  it('serializes to JSON', () => {
    const scope = new Scope([searchAction]);
    const json = JSON.parse(JSON.stringify(scope));
    expect(json.actions[0].action).toBe('schema:SearchAction');
  });
});

describe('DisclosureSet', () => {
  it('empty set', () => {
    const ds = DisclosureSet.empty();
    expect(ds.entries).toHaveLength(0);
    expect(ds.requiresTee()).toBe(false);
    expect(ds.propertyRefs()).toEqual([]);
  });

  it('propertyRefs formats correctly', () => {
    const ds = new DisclosureSet([
      {
        type: 'schema:Person',
        permitted_properties: ['schema:name', 'schema:nationality'],
        prohibited_properties: ['schema:email'],
      },
    ]);
    expect(ds.propertyRefs()).toEqual([
      'schema:Person.schema:name',
      'schema:Person.schema:nationality',
    ]);
  });

  it('requiresTee detects no_retention', () => {
    const ds = new DisclosureSet([
      {
        type: 'schema:Person',
        permitted_properties: ['schema:name'],
        prohibited_properties: [],
        no_retention: true,
      },
    ]);
    expect(ds.requiresTee()).toBe(true);
  });

  it('requiresTee false when no no_retention', () => {
    const ds = new DisclosureSet([
      {
        type: 'schema:Person',
        permitted_properties: ['schema:name'],
        prohibited_properties: [],
        session_only: true,
      },
    ]);
    expect(ds.requiresTee()).toBe(false);
  });
});
