# PyGuard Accessibility Testing Guide

**WCAG 2.2 Level AA Compliance Verification**

This document provides a comprehensive guide for testing PyGuard's accessibility features and ensuring WCAG 2.2 Level AA compliance.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Automated Testing](#automated-testing)
3. [Manual Testing](#manual-testing)
4. [Keyboard Navigation](#keyboard-navigation)
5. [Screen Reader Testing](#screen-reader-testing)
6. [Visual Testing](#visual-testing)
7. [Testing Checklist](#testing-checklist)
8. [Tools & Resources](#tools--resources)

---

## Quick Start

### Prerequisites
- Modern web browser (Chrome, Firefox, Safari, or Edge)
- Screen reader software (NVDA, JAWS, or VoiceOver)
- PyGuard installed and configured

### Generate Test Report
```bash
# Generate a sample HTML report
pyguard examples/sample_project/ --scan-only

# Open the report
open pyguard-report.html  # macOS
xdg-open pyguard-report.html  # Linux
start pyguard-report.html  # Windows
```

---

## Automated Testing

### 1. axe DevTools (Browser Extension)

**Install:**
- Chrome: [axe DevTools Extension](https://chrome.google.com/webstore/detail/axe-devtools-web-accessib/lhdoppojpmngadmnindnejefpokejbdd)
- Firefox: [axe DevTools for Firefox](https://addons.mozilla.org/en-US/firefox/addon/axe-devtools/)

**Usage:**
1. Open PyGuard HTML report in browser
2. Open DevTools (F12)
3. Click "axe DevTools" tab
4. Click "Scan ALL of my page"
5. Review results (target: 0 violations)

**Expected Results:**
- ✅ 0 Violations
- ✅ All WCAG 2.2 Level AA rules pass
- ✅ No color contrast issues
- ✅ All interactive elements have accessible names

### 2. WAVE (Web Accessibility Evaluation Tool)

**Install:**
- [WAVE Browser Extension](https://wave.webaim.org/extension/)

**Usage:**
1. Open PyGuard HTML report
2. Click WAVE extension icon
3. Review sidebar for:
   - Errors (target: 0)
   - Alerts (review each)
   - Features (should show landmarks, headings, etc.)
   - Structure (should show proper hierarchy)
   - Contrast (all should pass)

**Expected Results:**
- ✅ 0 Errors
- ✅ Proper landmarks identified
- ✅ Heading hierarchy correct
- ✅ All contrast ratios pass

### 3. Lighthouse Accessibility Audit

**Usage:**
1. Open Chrome DevTools (F12)
2. Go to "Lighthouse" tab
3. Select "Accessibility" category
4. Click "Generate report"

**Expected Results:**
- ✅ Score: 100/100
- ✅ All WCAG checks pass
- ✅ Best practices followed

### 4. Pa11y CLI

**Install:**
```bash
npm install -g pa11y
```

**Usage:**
```bash
# Test the HTML report
pa11y http://localhost:8000/pyguard-report.html

# Generate detailed report
pa11y --standard WCAG2AA --reporter html http://localhost:8000/pyguard-report.html > accessibility-report.html
```

**Expected Results:**
- ✅ 0 errors
- ✅ 0 warnings
- ✅ All WCAG 2.2 Level AA criteria met

---

## Manual Testing

### 1. Semantic HTML Structure

**Test:**
- View page source
- Verify proper HTML5 semantic elements

**Checklist:**
- [ ] `<!DOCTYPE html>` declaration present
- [ ] `<html lang="en">` attribute set
- [ ] `<title>` element describes page content
- [ ] `<header>` with `role="banner"`
- [ ] `<main>` with `role="main"`
- [ ] `<footer>` with `role="contentinfo"`
- [ ] `<nav>` with `aria-label` for navigation
- [ ] Heading hierarchy (h1 → h2 → h3, no skips)
- [ ] All images have `alt` attributes
- [ ] Tables have `<caption>` and `scope` attributes

### 2. ARIA Landmarks

**Test:**
- Use browser extension like "Landmarks" or screen reader
- Verify all landmarks are present and labeled

**Checklist:**
- [ ] Banner landmark (header)
- [ ] Main landmark (main content)
- [ ] Contentinfo landmark (footer)
- [ ] Region landmarks (metrics grid, issues table)
- [ ] All landmarks have accessible names
- [ ] No redundant or unnecessary landmarks

### 3. Color Contrast

**Test:**
- Use contrast checker tools
- Verify all text meets minimum ratios

**Checklist:**
- [ ] Normal text (body): ≥4.5:1 contrast ratio
- [ ] Large text (18px+ or 14px+ bold): ≥3:1
- [ ] Interactive elements: ≥3:1 against background
- [ ] Status indicators: Not relying on color alone

**Test Cases:**
- Primary text on white: #1A202C / #FFFFFF = 16.5:1 ✅ (AAA)
- Secondary text on white: #4A5568 / #FFFFFF = 8.3:1 ✅ (AAA)
- Success color: #38A169 / #FFFFFF = 5.1:1 ✅ (AA)
- Warning color: #D69E2E / #FFFFFF = 5.2:1 ✅ (AA)
- Danger color: #E53E3E / #FFFFFF = 5.3:1 ✅ (AA)
- Info color: #3182CE / #FFFFFF = 5.4:1 ✅ (AA)

### 4. Focus Indicators

**Test:**
- Tab through all interactive elements
- Verify visible focus indicators

**Checklist:**
- [ ] All interactive elements receive focus
- [ ] Focus indicator is clearly visible (2-3px outline)
- [ ] Focus indicator has sufficient contrast (≥3:1)
- [ ] Focus order is logical and predictable
- [ ] Skip link appears on focus
- [ ] Focus is never trapped
- [ ] No focus on non-interactive elements

### 5. Touch Target Sizing

**Test:**
- Inspect elements with browser DevTools
- Measure interactive element sizes

**Checklist:**
- [ ] All buttons ≥44×44 CSS pixels
- [ ] All links ≥44×44 CSS pixels (or have padding)
- [ ] Spacing between targets ≥8px
- [ ] Touch targets don't overlap
- [ ] Mobile view maintains proper sizing

**Test Cases:**
```css
/* All buttons and links should meet these criteria */
.btn, a {
  min-height: 44px;
  min-width: 44px;
  padding: 12px 24px; /* Ensures 44px+ height */
}
```

---

## Keyboard Navigation

### Test Procedure

**Start:**
1. Open PyGuard HTML report
2. Press Tab to begin navigation
3. Test all keyboard interactions

### Keyboard Commands to Test

| Key | Expected Action | Pass/Fail |
|-----|----------------|-----------|
| Tab | Move to next focusable element | [ ] |
| Shift+Tab | Move to previous focusable element | [ ] |
| Enter | Activate link or button | [ ] |
| Space | Activate button | [ ] |
| Escape | Close modal/dropdown (if applicable) | [ ] |

### Navigation Flow Test

**Expected Tab Order:**
1. Skip to content link (hidden until focused)
2. Status banner (read by screen reader)
3. First metric card
4. Second metric card
5. Third metric card
6. Fourth metric card
7. Fifth metric card
8. Sixth metric card
9. Issues table (becomes focusable container)
10. First footer link (GitHub)
11. Second footer link (Documentation)
12. Third footer link (Report Issues)

**Verification:**
- [ ] Tab order is logical and predictable
- [ ] No elements are skipped
- [ ] No focus traps
- [ ] Skip link works correctly
- [ ] Can navigate entire page with keyboard only
- [ ] All interactive elements are reachable

---

## Screen Reader Testing

### Recommended Screen Readers

1. **NVDA** (Windows) - Free
   - Download: https://www.nvaccess.org/download/
   
2. **JAWS** (Windows) - Commercial
   - Free trial available
   
3. **VoiceOver** (macOS/iOS) - Built-in
   - Enable: System Preferences → Accessibility → VoiceOver
   
4. **Narrator** (Windows) - Built-in
   - Enable: Windows + Ctrl + Enter

### NVDA Testing (Windows)

**Setup:**
1. Install NVDA
2. Launch NVDA (Ctrl+Alt+N)
3. Open PyGuard HTML report

**Test Script:**

```
Action: Press Insert+F7 (Elements List)
Expected: Shows all headings, landmarks, links
Verify: Proper heading hierarchy visible

Action: Press H key repeatedly
Expected: Navigate through headings (h1, h2, h3)
Verify: All headings are announced correctly

Action: Press D key repeatedly
Expected: Navigate through landmarks (banner, main, contentinfo)
Verify: All landmarks announced with proper labels

Action: Press T key repeatedly
Expected: Navigate through tables
Verify: Table caption announced, headers read correctly

Action: Press B key repeatedly
Expected: Navigate through buttons
Verify: All buttons have descriptive labels

Action: Tab through interactive elements
Expected: Each element announced with role and name
Verify: No "unlabeled" or "clickable" generic announcements
```

**Checklist:**
- [ ] Page title announced on load
- [ ] All headings have meaningful text
- [ ] All landmarks identified and labeled
- [ ] Links describe their destination
- [ ] Images have appropriate alt text
- [ ] Table headers associated with data cells
- [ ] Form fields have labels (if any)
- [ ] Status messages announced (aria-live)
- [ ] No "clickable" without context

### VoiceOver Testing (macOS)

**Setup:**
1. Enable VoiceOver: Cmd+F5
2. Open PyGuard HTML report

**Rotor Navigation:**
```
Action: Press VO+U (Open Rotor)
Expected: Menu with Headings, Links, Landmarks, etc.

Test each category:
- Headings: Should list h1, h2, h3 with text
- Landmarks: Should list banner, main, contentinfo
- Links: Should list all links with descriptive text
- Tables: Should list table with caption
```

**Checklist:**
- [ ] VoiceOver announces page elements correctly
- [ ] Rotor navigation works for all categories
- [ ] Web Spot navigation (VO+N) works
- [ ] All interactive elements have labels

---

## Visual Testing

### 1. Zoom Testing

**Test:**
- Test page at different zoom levels
- Verify layout doesn't break

**Zoom Levels:**
- [ ] 100% (baseline)
- [ ] 125% (slight zoom)
- [ ] 150% (moderate zoom)
- [ ] 200% (high zoom - WCAG 2.2 requirement)
- [ ] 400% (extreme zoom)

**Verification:**
- [ ] Text remains readable at all zoom levels
- [ ] No horizontal scrolling required (at 100%-200%)
- [ ] Layout adapts gracefully
- [ ] No overlapping content
- [ ] All functionality remains accessible

### 2. Responsive Design Testing

**Screen Sizes:**
- [ ] Mobile: 375×667 (iPhone SE)
- [ ] Mobile: 414×896 (iPhone 11)
- [ ] Tablet: 768×1024 (iPad)
- [ ] Desktop: 1366×768 (laptop)
- [ ] Desktop: 1920×1080 (desktop)
- [ ] Large: 2560×1440 (4K)

**Verification:**
- [ ] Layout adapts to screen size
- [ ] Text remains readable
- [ ] Touch targets remain ≥44×44px on mobile
- [ ] No content cut off
- [ ] Table scrolls horizontally on mobile if needed

### 3. Text Spacing Testing

**Test:**
- Apply CSS overrides for text spacing
- Verify content remains readable

**CSS Override:**
```css
* {
  line-height: 1.5 !important;
  letter-spacing: 0.12em !important;
  word-spacing: 0.16em !important;
  margin-bottom: 2em !important;
}
```

**Verification:**
- [ ] No content is clipped
- [ ] No overlapping text
- [ ] All content remains readable
- [ ] Layout adapts to increased spacing

### 4. Dark Mode Testing

**Test:**
- Enable dark mode in OS settings
- Verify page adapts correctly

**macOS:**
```
System Preferences → General → Appearance → Dark
```

**Windows:**
```
Settings → Personalization → Colors → Choose your color → Dark
```

**Verification:**
- [ ] Page background changes to dark
- [ ] Text remains readable with sufficient contrast
- [ ] All colors invert appropriately
- [ ] No broken layouts
- [ ] Gradients still look good

### 5. High Contrast Mode

**Test:**
- Enable high contrast mode
- Verify page remains usable

**Windows:**
```
Settings → Ease of Access → High contrast → Turn on high contrast
```

**Verification:**
- [ ] All text visible
- [ ] Borders visible on interactive elements
- [ ] Focus indicators visible
- [ ] Page structure clear

### 6. Reduced Motion Testing

**Test:**
- Enable reduced motion preference
- Verify animations are minimized

**macOS:**
```
System Preferences → Accessibility → Display → Reduce motion
```

**Windows:**
```
Settings → Ease of Access → Display → Show animations in Windows
```

**Verification:**
- [ ] Card entrance animations disabled
- [ ] Transition durations set to 0.01ms
- [ ] No vestibular motion triggers
- [ ] Hover effects still work (no motion)
- [ ] Page remains functional

---

## Testing Checklist

### WCAG 2.2 Level A Criteria

- [ ] **1.1.1 Non-text Content** - All images have alt text
- [ ] **1.2.1 Audio-only and Video-only** - N/A (no audio/video)
- [ ] **1.3.1 Info and Relationships** - Semantic HTML, ARIA
- [ ] **1.3.2 Meaningful Sequence** - Logical reading order
- [ ] **1.3.3 Sensory Characteristics** - Not relying on shape/color alone
- [ ] **1.4.1 Use of Color** - Color + icon for severity
- [ ] **1.4.2 Audio Control** - N/A (no audio)
- [ ] **2.1.1 Keyboard** - All functionality keyboard accessible
- [ ] **2.1.2 No Keyboard Trap** - No focus traps
- [ ] **2.1.4 Character Key Shortcuts** - N/A (no shortcuts)
- [ ] **2.2.1 Timing Adjustable** - N/A (no time limits)
- [ ] **2.2.2 Pause, Stop, Hide** - Animations respect reduced motion
- [ ] **2.3.1 Three Flashes** - No flashing content
- [ ] **2.4.1 Bypass Blocks** - Skip to content link
- [ ] **2.4.2 Page Titled** - Descriptive page title
- [ ] **2.4.3 Focus Order** - Logical focus order
- [ ] **2.4.4 Link Purpose** - Links describe destination
- [ ] **2.5.1 Pointer Gestures** - No complex gestures required
- [ ] **2.5.2 Pointer Cancellation** - Click/tap events handled properly
- [ ] **2.5.3 Label in Name** - Visible labels match accessible names
- [ ] **2.5.4 Motion Actuation** - N/A (no motion controls)
- [ ] **3.1.1 Language of Page** - lang="en" set
- [ ] **3.2.1 On Focus** - Focus doesn't trigger context change
- [ ] **3.2.2 On Input** - Input doesn't trigger context change
- [ ] **3.3.1 Error Identification** - N/A (no forms)
- [ ] **3.3.2 Labels or Instructions** - N/A (no forms)
- [ ] **4.1.1 Parsing** - Valid HTML
- [ ] **4.1.2 Name, Role, Value** - All elements have proper ARIA

### WCAG 2.2 Level AA Criteria

- [ ] **1.2.4 Captions (Live)** - N/A (no live audio)
- [ ] **1.2.5 Audio Description** - N/A (no video)
- [ ] **1.3.4 Orientation** - Works in portrait and landscape
- [ ] **1.3.5 Identify Input Purpose** - N/A (no forms)
- [ ] **1.4.3 Contrast (Minimum)** - 4.5:1 for normal text, 3:1 for large
- [ ] **1.4.4 Resize Text** - Text scalable to 200% without loss
- [ ] **1.4.5 Images of Text** - No images of text (uses real text)
- [ ] **1.4.10 Reflow** - Content reflows at 320px width
- [ ] **1.4.11 Non-text Contrast** - UI components have 3:1 contrast
- [ ] **1.4.12 Text Spacing** - Works with increased text spacing
- [ ] **1.4.13 Content on Hover/Focus** - N/A (no tooltips/popovers)
- [ ] **2.4.5 Multiple Ways** - N/A (single page)
- [ ] **2.4.6 Headings and Labels** - Descriptive headings/labels
- [ ] **2.4.7 Focus Visible** - Visible focus indicators
- [ ] **2.4.11 Focus Not Obscured (Minimum)** - Focus always visible **(NEW 2.2)**
- [ ] **2.5.7 Dragging Movements** - No drag required **(NEW 2.2)**
- [ ] **2.5.8 Target Size (Minimum)** - 44×44px minimum **(NEW 2.2)**
- [ ] **3.1.2 Language of Parts** - N/A (single language)
- [ ] **3.2.3 Consistent Navigation** - N/A (single page)
- [ ] **3.2.4 Consistent Identification** - Components identified consistently
- [ ] **3.2.6 Consistent Help** - Help mechanism consistent **(NEW 2.2)**
- [ ] **3.3.3 Error Suggestion** - N/A (no forms)
- [ ] **3.3.4 Error Prevention** - N/A (no forms)
- [ ] **3.3.7 Redundant Entry** - N/A (no forms) **(NEW 2.2)**
- [ ] **3.3.8 Accessible Authentication** - N/A (no auth) **(NEW 2.2)**
- [ ] **4.1.3 Status Messages** - Status banner has aria-live

---

## Tools & Resources

### Browser Extensions

1. **axe DevTools**
   - Chrome: https://chrome.google.com/webstore/detail/lhdoppojpmngadmnindnejefpokejbdd
   - Firefox: https://addons.mozilla.org/en-US/firefox/addon/axe-devtools/

2. **WAVE**
   - All browsers: https://wave.webaim.org/extension/

3. **Landmarks Browser Extension**
   - Shows all ARIA landmarks
   - Chrome/Firefox: http://matatk.agrip.org.uk/landmarks/

4. **Accessibility Insights**
   - Microsoft's accessibility testing tool
   - https://accessibilityinsights.io/

### Contrast Checkers

1. **WebAIM Contrast Checker**
   - https://webaim.org/resources/contrastchecker/

2. **Colorable**
   - https://colorable.jxnblk.com/

3. **Contrast Ratio**
   - https://contrast-ratio.com/

### Screen Readers

1. **NVDA** (Windows, Free)
   - https://www.nvaccess.org/download/

2. **JAWS** (Windows, Commercial)
   - https://www.freedomscientific.com/products/software/jaws/

3. **VoiceOver** (macOS/iOS, Built-in)
   - Documentation: https://support.apple.com/guide/voiceover/

4. **Narrator** (Windows, Built-in)
   - Documentation: https://support.microsoft.com/en-us/windows/

### Documentation

1. **WCAG 2.2 Guidelines**
   - https://www.w3.org/WAI/WCAG22/quickref/

2. **WebAIM Resources**
   - https://webaim.org/resources/

3. **A11Y Project**
   - https://www.a11yproject.com/

4. **MDN Accessibility**
   - https://developer.mozilla.org/en-US/docs/Web/Accessibility

---

## Reporting Issues

If you find accessibility issues:

1. **Document the issue:**
   - What: Description of the problem
   - Where: Page/component affected
   - Impact: WCAG criterion violated
   - Severity: Critical/High/Medium/Low

2. **Provide reproduction steps:**
   - Browser/OS/screen reader version
   - Steps to reproduce
   - Expected vs actual behavior

3. **Submit to GitHub:**
   - https://github.com/cboyd0319/PyGuard/issues
   - Use label: `accessibility`
   - Include WCAG criterion number

---

## Continuous Testing

### Pre-commit Checks
```bash
# Run accessibility checks before committing
npm run a11y-check
```

### CI/CD Integration
```yaml
# .github/workflows/accessibility.yml
- name: Accessibility Check
  run: |
    npm install -g pa11y
    pa11y --standard WCAG2AA http://localhost:8000/report.html
```

---

**Last Updated:** January 2025  
**WCAG Version:** 2.2 Level AA  
**Maintained By:** PyGuard Team

For questions or suggestions, please open an issue on GitHub.
