# Fixes Applied to `codex-papillon-canvas-browser-runtime` Branch

## 🐛 Issues Fixed

### 1. Silent Approval Errors → Block Stuck Forever
**Symptom**: Clicking "Authorize" on approval gates does nothing, block stays stuck  
**Root Cause**: `approve_block()` and `reject_block()` were silently discarding backend errors with `let _ = invoke(...).await`  
**Fix**: Added proper error handling with match statements, error logging, and state cleanup  
**Commit**: `a450be42`

### 2. Silent Persistence Failures → Orphaned Blocks
**Symptom**: Backend returns "Block not found: 19deb3f4cfa-721e55c5"  
**Root Cause**: `canvas_block_create` failed silently → block only in UI memory, not DB  
**Fix**: Added error logging for persistence failures, continues gracefully  
**Commit**: `a450be42`

### 3. Orphaned Blocks → Retry Fails
**Symptom**: "Try again" button triggers `canvas_retry` which fails with "no definitions found"  
**Root Cause**: Retry attempts to use block ID that was never persisted to DB  
**Fix**: Auto-recovery system that detects orphaned blocks, deletes them, and creates fresh prompts  
**Commit**: `ae93a38c`

### 4. Setup Overlay Blocks All Clicks
**Symptom**: `.setup-overlay` intercepts pointer events across entire screen  
**Root Cause**: Missing `pointer-events: none` on overlay, causing it to block clicks behind it  
**Fix**: Added `pointer-events: none` to overlay, `pointer-events: auto` to wizard  
**Commit**: `a693c8f3`  
**Discovered By**: Playwright automated testing

---

## ✅ What Works Now

### Error Visibility
```javascript
// Console now shows:
ERROR approve_block failed for abc-123: Block not found
ERROR Failed to persist block abc-123 to DB: [reason]. Block will remain in memory only.
WARN Approval already in flight for abc-123, ignoring duplicate request
WARN Retry failed because block not in DB. Creating fresh prompt instead.
```

### Auto-Recovery
1. User clicks "Try again" on failed block
2. System detects "Block not found" error
3. Orphaned UI block is automatically deleted
4. Fresh prompt is created with same text
5. Workflow continues without manual intervention

### UI Interaction
- Setup wizard overlay no longer blocks clicks outside the wizard box
- Can interact with workflow view even when wizard is present

---

## 🧪 Testing

### Manual Test
1. Start Papillon: `just papillon`
2. Open http://127.0.0.1:1420/
3. Enter workflow: "research airline tickets to cabo"
4. Click "Try again" if it fails
5. Check browser console (F12) for error messages

### Automated Test
```bash
node test-papillon.js
```
Screenshots saved to:
- `papillon-01-initial.png` - Initial load
- `papillon-02-setup-overlay.png` - Setup wizard if present
- `papillon-03-*.png` - Workflow interactions
- etc.

---

## 📊 Impact

**Before**: Silent failures, stuck blocks, no way to recover  
**After**: Clear error messages, automatic recovery, graceful degradation

**Commits**:
- `a450be42` - Error handling for approval/persistence  
- `ae93a38c` - Auto-recovery from orphaned blocks  
- `a693c8f3` - Setup overlay click-through fix  
- `47381d8a` - Playwright test infrastructure

**Files Changed**:
- `apps/papillon/frontend/src/state/canvas.rs` (+104 lines)
- `apps/papillon/frontend/styles/main.css` (+2 lines)
- `test-papillon.js` (new file)

---

## 🎯 Next Steps

1. **Test the fixes** - Run Papillon and verify retry works
2. **Monitor console** - Check for new error patterns
3. **Consider merging** - These fixes should go to main branch
4. **Add tests** - Unit tests for error handling paths
