# Manual QA Checklist: Multi-Profile Identity Support

**Branch:** `vk/02a2-multi-profile-id`
**Test Date:** ___________
**Tester:** ___________
**Status:** ☐ PASS ☐ FAIL

---

## Pre-QA Setup

- [ ] Clean build: `cd apps/papillion && cargo tauri dev`
- [ ] Delete existing profile database: `rm ~/Library/Application\ Support/Papillion/profiles.db`
- [ ] Launch Papillion
- [ ] Verify app loads without console errors
- [ ] DevTools console open (monitor for errors during testing)

---

## Test Suite 1: Profile Creation & Listing

### TC-001: First Launch (Default Profile Creation)
- [ ] App launches successfully
- [ ] Profile menu shows 1 profile with avatar
- [ ] Profile avatar displays with deterministic color
- [ ] Active profile marked with checkmark ✓
- [ ] No console errors
- **Evidence:** Screenshot of profile menu

**Result:** ☐ PASS ☐ FAIL | Notes: ________________

---

### TC-002: Create New Profile
- [ ] Navigate to Settings → Profiles tab
- [ ] Enter profile name "Work"
- [ ] Click Create button
- [ ] New profile appears in list
- [ ] Profile has unique avatar color
- [ ] Shows "Created" timestamp
- [ ] Delete button enabled (not active)
- **Evidence:** Screenshot of settings tab

**Result:** ☐ PASS ☐ FAIL | Notes: ________________

---

### TC-003: List Profiles Shows All
- [ ] Create 3-4 more profiles (e.g., "Personal", "Testing", "Dev")
- [ ] All profiles visible in Settings tab
- [ ] All profiles visible in TopBar menu
- [ ] Exactly 1 profile has checkmark
- [ ] Each profile has consistent avatar
- **Evidence:** Screenshot of settings tab + TopBar menu

**Result:** ☐ PASS ☐ FAIL | Notes: ________________

---

## Test Suite 2: Profile Switching & State Isolation

### TC-004: Switch Profile - Verify DID Changes
- [ ] Note current DID in TopBar (e.g., "did...abc")
- [ ] Open profile menu
- [ ] Click on different profile
- [ ] Menu closes automatically
- [ ] DID changes (new abbreviation e.g., "did...xyz")
- [ ] Avatar button updates with new profile
- [ ] No console errors
- **Evidence:** Screenshot of DID before/after

**Result:** ☐ PASS ☐ FAIL | Notes: ________________

---

### TC-005: Canvas Reset After Profile Switch
- [ ] On Profile A, create 2-3 canvases
- [ ] Name them distinctly ("Canvas Work 1", "Canvas Work 2", etc.)
- [ ] Switch to Profile B (different profile)
- [ ] Profile B workspace is EMPTY (no canvases visible)
- [ ] Can create new canvases on Profile B
- [ ] **CRITICAL:** Canvas list does NOT show Profile A's canvases
- **Evidence:** Screenshot of empty canvas list on Profile B

**Result:** ☐ PASS ☐ FAIL | Notes: ________________

---

### TC-006: Registry State Cleared After Switch
- [ ] On Profile A, go to Browse Registries
- [ ] Enter a registry URL and browse agents
- [ ] Note agents are loaded
- [ ] Switch to Profile B
- [ ] Go to Browse Registries
- [ ] Registry URL is EMPTY (not retained)
- [ ] Agent list is empty
- [ ] Filters/searches are cleared
- **Evidence:** Screenshot of empty registry state

**Result:** ☐ PASS ☐ FAIL | Notes: ________________

---

### TC-007: Switch Back to Original Profile
- [ ] Switch back to Profile A
- [ ] Original canvases reappear ("Canvas Work 1", "Canvas Work 2", etc.)
- [ ] Same names and order (durable per profile)
- [ ] DID matches what it was before
- **Evidence:** Screenshot matching TC-005 original state

**Result:** ☐ PASS ☐ FAIL | Notes: ________________

---

## Test Suite 3: Profile Management

### TC-008: Delete Profile with Confirmation
- [ ] Go to Settings → Profiles tab
- [ ] Click Delete on a non-active profile
- [ ] Confirmation dialog appears
- [ ] Dialog shows profile name in text
- [ ] Dialog text explains "Episodes tied to this profile won't be deleted"
- [ ] Click "Delete Profile" to confirm
- [ ] Profile removed from list
- [ ] Profile removed from TopBar menu
- **Evidence:** Screenshot of confirmation dialog + final list

**Result:** ☐ PASS ☐ FAIL | Notes: ________________

---

### TC-009: Cannot Delete Active Profile
- [ ] Go to Settings → Profiles tab
- [ ] Find profile marked as active (checkmark)
- [ ] Attempt to click Delete button
- [ ] Delete button is DISABLED (greyed out)
- [ ] Button not clickable
- [ ] Profile remains in list
- **Evidence:** Screenshot of disabled delete button

**Result:** ☐ PASS ☐ FAIL | Notes: ________________

---

### TC-010: Create Profile with Special Names
- [ ] Create profile with single-word name: "Dev"
- [ ] Create profile with multi-word name: "Testing Environment"
- [ ] Create profile with numbers: "Workspace 2025"
- [ ] "Dev" shows avatar "D"
- [ ] "Testing Environment" shows avatar "TE"
- [ ] "Workspace 2025" shows avatar "W2"
- [ ] Each has unique deterministic color
- **Evidence:** Screenshot of all profiles in list

**Result:** ☐ PASS ☐ FAIL | Notes: ________________

---

## Test Suite 4: Avatar Component

### TC-011: Avatar Determinism
- [ ] In one session, note "Alice" profile avatar color
- [ ] In another session (or rebuild), create "Alice" again
- [ ] Avatar colors match exactly
- [ ] Both show "A" initials
- [ ] Color is deterministic (reproducible)
- **Evidence:** Screenshots from multiple sessions

**Result:** ☐ PASS ☐ FAIL | Notes: ________________

---

### TC-012: Avatar Size Consistency
- [ ] Open Settings → Profiles tab
- [ ] Note avatar size in profile list (should be ~32px)
- [ ] Open TopBar profile menu
- [ ] Note avatar size in menu items (should be ~32px)
- [ ] TopBar profile button avatar (should be smaller ~24px)
- [ ] All avatars render clearly without pixelation
- [ ] Initials readable at all sizes
- **Evidence:** Screenshots of multiple locations

**Result:** ☐ PASS ☐ FAIL | Notes: ________________

---

## Test Suite 5: UX & Flows

### TC-013: Profile Menu Flow
- [ ] TopBar profile menu closed (normal state)
- [ ] Click profile avatar button
- [ ] Menu opens showing all profiles
- [ ] Active profile has checkmark ✓
- [ ] Hover over profile (highlighting works)
- [ ] Click outside menu
- [ ] Menu closes
- [ ] Can reopen menu multiple times
- **Evidence:** Multiple screenshots of opening/closing

**Result:** ☐ PASS ☐ FAIL | Notes: ________________

---

### TC-014: Settings Tab Navigation
- [ ] Click "Profiles" tab in Settings
- [ ] Profiles tab content visible (list + create form)
- [ ] Click "General" tab
- [ ] General tab content visible
- [ ] Click back to "Profiles" tab
- [ ] Profiles state preserved (no flicker, no reload)
- [ ] Tab highlighting correct
- **Evidence:** Screenshot of tab switching

**Result:** ☐ PASS ☐ FAIL | Notes: ________________

---

## Test Suite 6: Edge Cases

### TC-015: Create Profile with Empty Name
- [ ] Go to Settings → Profiles tab
- [ ] Leave profile name field empty
- [ ] Click "Create" button
- [ ] Error message appears: "Profile name cannot be empty"
- [ ] Profile NOT created
- [ ] Form remains open for retry
- **Evidence:** Screenshot of error message

**Result:** ☐ PASS ☐ FAIL | Notes: ________________

---

### TC-016: Rapid Profile Switching
- [ ] Create 3 profiles (A, B, C)
- [ ] Switch to Profile A
- [ ] Immediately switch to Profile B (before any operations)
- [ ] Immediately switch to Profile C
- [ ] All switches complete without errors
- [ ] Final active profile is C
- [ ] DID reflects Profile C
- [ ] Profile menu updates correctly
- **Evidence:** Screenshot after final switch

**Result:** ☐ PASS ☐ FAIL | Notes: ________________

---

### TC-017: Launch with Missing Profile DB
- [ ] Close Papillion
- [ ] Delete `~/.../Papillion/profiles.db` manually
- [ ] Relaunch Papillion
- [ ] App creates new database
- [ ] Default profile auto-created
- [ ] No crashes or errors
- [ ] App fully functional
- **Evidence:** Screenshot of recovered app state

**Result:** ☐ PASS ☐ FAIL | Notes: ________________

---

## Test Suite 7: Console & Errors

### TC-018: No Console Errors After All Operations
- [ ] Perform all tests TC-001 through TC-017
- [ ] Monitor DevTools console throughout
- [ ] **No JavaScript errors**
- [ ] **No Tauri IPC errors**
- [ ] **No async/await warnings**
- [ ] **No memory leaks** (profile switch multiple times)
- [ ] App remains responsive
- **Evidence:** Screenshot of clean console

**Result:** ☐ PASS ☐ FAIL | Notes: ________________

---

## Performance Checks

### TC-019: Profile Switch Performance
- [ ] Measure profile switch time (click profile → DID changes)
- [ ] Expected: <500ms total
- [ ] No noticeable lag or loading spinner
- [ ] App remains responsive during switch
- **Evidence:** Observation + screenshot

**Result:** ☐ PASS ☐ FAIL | Performance: ____ ms

---

### TC-020: Memory Stability
- [ ] Switch profiles 10+ times
- [ ] Create/delete profiles multiple times
- [ ] Monitor for memory growth in DevTools
- [ ] No visible memory leaks
- [ ] App remains responsive
- **Evidence:** Final console state screenshot

**Result:** ☐ PASS ☐ FAIL | Notes: ________________

---

## Summary

### Passed Tests
**Count:** _____ / 20 tests passed

### Failed Tests
**List:**
1. ________________
2. ________________
3. ________________

### Critical Issues (Blocks Release)
- [ ] None found

### High Priority Issues (Should Fix)
- [ ] None found
- [ ] Issue: ________________

### Medium Priority Issues (Nice to Fix)
- [ ] None found
- [ ] Issue: ________________

### Low Priority Issues (Defer)
- [ ] None found
- [ ] Issue: ________________

---

## Overall Assessment

**Code Quality:** ✅ Excellent (from code review)
**Functionality:** ☐ Fully Working ☐ Partial ☐ Broken
**UX/Usability:** ☐ Excellent ☐ Good ☐ Needs Work
**Performance:** ☐ Fast (<500ms) ☐ Acceptable ☐ Slow

**Recommendation:** ☐ APPROVED FOR MERGE ☐ NEEDS FIXES ☐ NEEDS REVIEW

---

## Sign-Off

**Tester:** _________________________
**Date:** _________________________
**Time Spent:** _________________________

**Notes:**
```
_________________________________________________________________

_________________________________________________________________

_________________________________________________________________
```

---

## Regression Testing (Next Release)

Use baseline.json in `.gstack/qa-reports/baseline.json` to track:
- ✅ All 20 tests pass
- ✅ Health score: 95+
- ✅ Zero console errors
- ✅ No regressions from this release

---

**For questions about this checklist, see:** `.gstack/qa-reports/qa-report-papillion-multi-profile-2026-03-21.md`
