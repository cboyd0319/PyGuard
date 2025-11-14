# Bug Tracking and Management Guide

**Status:** ✅ System Established
**Goal:** Zero critical bugs for 90 days (v1.0.0)
**Priority:** HIGH - Quality metric

---

## Overview

This guide defines PyGuard's bug tracking system, including severity levels, SLAs (Service Level Agreements), and resolution processes.

### Goals

- **Transparency:** Clear bug status and priorities
- **Accountability:** Defined response times
- **Quality:** Zero critical bugs milestone
- **User Trust:** Reliable, responsive issue handling

---

## Severity Levels

### Critical (P0)

**Definition:** Security vulnerabilities, data loss, crashes, complete functionality loss

**Examples:**
- Security vulnerability allowing code execution
- PyGuard crashes and cannot run
- Auto-fix corrupts or deletes files
- Memory leak causing system crash
- Data loss or corruption

**SLA:**
- **Acknowledgment:** 24 hours
- **First Response:** 48 hours
- **Resolution Target:** 7 days
- **Workaround:** ASAP (within 48 hours if possible)

**Priority:** Drop everything, fix immediately

**Labels:**
- `severity: critical`
- `bug`
- `priority: urgent`

**Notification:**
- Immediately alert maintainers
- Pin issue to repository
- Consider emergency release

### High (P1)

**Definition:** Major functionality broken, difficult or no workaround

**Examples:**
- Core feature completely non-functional
- False negative (security issue not detected)
- Major framework support broken
- Auto-fix creates incorrect code
- Performance regression (>50% slower)

**SLA:**
- **Acknowledgment:** 48 hours
- **First Response:** 5 days
- **Resolution Target:** 14 days
- **Workaround:** Within 7 days

**Priority:** High, schedule for next sprint

**Labels:**
- `severity: high`
- `bug`
- `priority: high`

### Medium (P2)

**Definition:** Functionality impaired but workaround available

**Examples:**
- Feature partially works but has edge cases
- False positive (safe code flagged)
- Minor performance regression (<50%)
- UI/UX issue affecting usability
- Non-critical documentation error

**SLA:**
- **Acknowledgment:** 7 days
- **First Response:** 14 days
- **Resolution Target:** 30 days
- **Workaround:** Document workaround

**Priority:** Normal, include in regular releases

**Labels:**
- `severity: medium`
- `bug`
- `priority: normal`

### Low (P3)

**Definition:** Minor issues, cosmetic problems, easy workarounds

**Examples:**
- Typo in error message
- Cosmetic UI issue
- Minor documentation inconsistency
- Edge case with trivial impact
- Enhancement disguised as bug

**SLA:**
- **Acknowledgment:** 14 days
- **First Response:** 30 days
- **Resolution Target:** 90 days (or next convenient release)
- **Workaround:** N/A (issue is minor)

**Priority:** Low, fix when convenient

**Labels:**
- `severity: low`
- `bug`
- `priority: low`

---

## Bug Lifecycle

### 1. Submission

User reports bug using GitHub issue template:
- Bug report auto-labeled: `bug`, `needs-triage`
- User selects severity (guidance provided)
- Issue appears in triage queue

### 2. Triage (Within SLA Acknowledgment Time)

Maintainer reviews and:
1. **Verify severity** - Adjust if user's assessment incorrect
2. **Check duplicates** - Link to existing issue if duplicate
3. **Reproduce** - Attempt to reproduce the bug
4. **Add labels:**
   - Severity: `severity: critical|high|medium|low`
   - Category: `security`, `performance`, `false-positive`, etc.
   - Component: `auto-fix`, `rule-engine`, `framework: django`, etc.
5. **Assign priority** - Based on severity + impact
6. **Comment** - Acknowledge and provide initial assessment

### 3. Investigation

Developer assigned to investigate:
1. **Root cause analysis** - Understand why it happens
2. **Impact assessment** - How many users affected?
3. **Workaround** - Can users work around it?
4. **Fix complexity** - How hard to fix?
5. **Document findings** - Add to issue comments

### 4. Fix Development

Developer creates fix:
1. **Create branch** - `fix/issue-123-description`
2. **Write tests** - Reproduce bug, verify fix
3. **Implement fix** - Minimal, focused change
4. **Test thoroughly** - Unit, integration, manual
5. **Update docs** - If user-facing change
6. **Create PR** - Link to issue

### 5. Review and Merge

PR review process:
1. **Code review** - Maintainer reviews code
2. **CI tests** - All tests pass
3. **Security scan** - No new vulnerabilities
4. **Approve and merge** - Merge to main
5. **Close issue** - Reference PR in closing comment

### 6. Release

Fix released to users:
1. **Version bump** - Patch for critical/high, minor for others
2. **Changelog** - Document fix in release notes
3. **Release** - Publish to PyPI, Homebrew, Docker
4. **Notify** - Comment on issue with release version
5. **Follow-up** - Verify no regression

### 7. Verification

Post-release verification:
1. **Monitor** - Watch for related issues
2. **User confirmation** - Ask reporter to verify fix
3. **Close** - Mark as `verified` or `fixed-but-unverified`

---

## SLA Tracking

### Metrics to Track

1. **Time to Acknowledgment**
   - Measure: Time from issue creation to first maintainer comment
   - Target: Within SLA for severity level

2. **Time to First Response**
   - Measure: Time from creation to substantive response (not just "thanks, we'll look")
   - Target: Within SLA for severity level

3. **Time to Resolution**
   - Measure: Time from creation to issue closed with fix released
   - Target: Within SLA for severity level

4. **Time to Workaround**
   - Measure: Time from creation to documented workaround (if needed)
   - Target: Within SLA for severity level

### Automated Tracking

Use GitHub Actions to track SLA compliance:

```yaml
# .github/workflows/sla-tracker.yml
name: SLA Tracker

on:
  issues:
    types: [opened, labeled, closed]
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours

jobs:
  track-sla:
    runs-on: ubuntu-latest
    steps:
      - name: Check SLA compliance
        uses: actions/github-script@v7
        with:
          script: |
            // Get all open bugs
            const bugs = await github.rest.issues.listForRepo({
              owner: context.repo.owner,
              repo: context.repo.repo,
              labels: 'bug',
              state: 'open'
            });

            const now = new Date();

            for (const bug of bugs.data) {
              const created = new Date(bug.created_at);
              const ageHours = (now - created) / (1000 * 60 * 60);

              // Determine severity and SLA
              let sla_hours = 24 * 14; // Default: Medium (14 days)
              if (bug.labels.some(l => l.name === 'severity: critical')) {
                sla_hours = 24; // 24 hours acknowledgment
              } else if (bug.labels.some(l => l.name === 'severity: high')) {
                sla_hours = 48; // 48 hours acknowledgment
              } else if (bug.labels.some(l => l.name === 'severity: medium')) {
                sla_hours = 24 * 7; // 7 days acknowledgment
              }

              // Check if acknowledged (has maintainer comment)
              const comments = await github.rest.issues.listComments({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: bug.number
              });

              const hasResponse = comments.data.length > 0;

              // If overdue and not acknowledged, add warning
              if (!hasResponse && ageHours > sla_hours) {
                await github.rest.issues.addLabels({
                  owner: context.repo.owner,
                  repo: context.repo.repo,
                  issue_number: bug.number,
                  labels: ['sla-warning']
                });

                await github.rest.issues.createComment({
                  owner: context.repo.owner,
                  repo: context.repo.repo,
                  issue_number: bug.number,
                  body: `⚠️ **SLA Warning**: This issue has exceeded the acknowledgment SLA (${sla_hours}h). Maintainers have been notified.`
                });
              }
            }
```

### Manual SLA Review

Weekly review of SLA metrics:

```bash
# Get SLA metrics for the week
gh issue list --label bug --json number,title,createdAt,labels,comments \
  | jq -r '.[] | "\(.number)\t\(.title)\t\(.createdAt)\t\(.labels | map(.name) | join(","))\t\(.comments | length)"'
```

---

## Zero Critical Bugs Goal

### v1.0.0 Success Criteria

**Goal:** Zero critical bugs open for 90 consecutive days

**Definition of "Critical Bug":**
- Has `severity: critical` label
- Is `open` state
- Is `bug` type (not feature request or enhancement)

### Tracking

```bash
# Check critical bugs count
gh issue list --label "severity: critical" --label bug --state open --json number,title

# Check days since last critical bug
gh issue list --label "severity: critical" --label bug --state closed \
  --json number,closedAt --limit 1 \
  | jq -r '.[0].closedAt | fromdateiso8601 | (now - .) / 86400 | floor'
```

### Automation

```yaml
# .github/workflows/critical-bug-dashboard.yml
name: Critical Bug Dashboard

on:
  schedule:
    - cron: '0 0 * * *'  # Daily
  workflow_dispatch:

jobs:
  update-dashboard:
    runs-on: ubuntu-latest
    steps:
      - name: Count critical bugs
        id: count
        uses: actions/github-script@v7
        with:
          script: |
            const { data: bugs } = await github.rest.issues.listForRepo({
              owner: context.repo.owner,
              repo: context.repo.repo,
              labels: 'severity: critical,bug',
              state: 'open'
            });

            return bugs.length;

      - name: Update README badge
        run: |
          COUNT=${{ steps.count.outputs.result }}
          if [ $COUNT -eq 0 ]; then
            echo "✅ Zero Critical Bugs!"
          else
            echo "⚠️ $COUNT Critical Bugs Open"
          fi
```

### Recovery Plan

If critical bug opens:
1. **Immediate Response** - Acknowledge within 24h
2. **Emergency Sprint** - Prioritize fix over all other work
3. **Daily Updates** - Update issue daily with progress
4. **Expedited Release** - Release patch ASAP
5. **Post-Mortem** - Analyze root cause, prevent recurrence

---

## Bug Metrics Dashboard

### Key Metrics to Track

1. **Open Bugs by Severity**
   ```bash
   gh issue list --label bug --state open --json labels | \
     jq -r '.[].labels[].name' | grep "severity:" | sort | uniq -c
   ```

2. **Mean Time to Resolution (MTTR)**
   ```bash
   # Calculate average days from creation to closure
   gh issue list --label bug --state closed --limit 100 \
     --json number,createdAt,closedAt | \
     jq '[.[] | ((.closedAt | fromdateiso8601) - (.createdAt | fromdateiso8601)) / 86400] | add / length'
   ```

3. **SLA Compliance Rate**
   - Percentage of bugs acknowledged within SLA
   - Percentage of bugs resolved within SLA

4. **Bug Velocity**
   - Bugs opened per week
   - Bugs closed per week
   - Net change (opened - closed)

5. **Regression Rate**
   - Bugs that reopen
   - Bugs caused by fixes

### Visualization

Use GitHub Projects for visual tracking:
- Board view: To-Do → In Progress → Done
- Table view: All bugs with severity, assignee, age
- Roadmap view: Critical bugs timeline

---

## Bug Report Quality

### Good Bug Reports

**Required elements:**
- ✅ Clear, specific title
- ✅ Steps to reproduce
- ✅ Expected vs actual behavior
- ✅ Code sample (if applicable)
- ✅ Environment details
- ✅ PyGuard version

**Optional but helpful:**
- ✅ Screenshots/videos
- ✅ Relevant logs
- ✅ Proposed solution
- ✅ Workaround (if found)

### Template Compliance

Our bug report template enforces quality:
- Required fields must be filled
- Severity must be selected
- Checklist must be acknowledged

### Handling Low-Quality Reports

If report is incomplete:
1. Add `needs-more-info` label
2. Comment asking for specific details
3. Wait 7 days for response
4. If no response, add `stale` label
5. Close if stale for 14 days

---

## Special Bug Categories

### Security Vulnerabilities

Process:
1. **Private reporting** - Use GitHub Security Advisories
2. **No public disclosure** - Until patched
3. **Expedited fix** - Critical priority
4. **Coordinated disclosure** - 90 days or patch release
5. **CVE assignment** - If appropriate

See: `SECURITY.md` for full process

### False Positives

Process:
1. Label: `false-positive`
2. Verify: Is it actually a false positive?
3. Document pattern: What rule triggered?
4. Fix rule: Adjust detection logic
5. Add test: Prevent regression
6. Release: Document in changelog

See: `docs/development/FALSE_POSITIVE_BENCHMARKING.md`

### Performance Regressions

Process:
1. Label: `performance`
2. Benchmark: Measure impact
3. Bisect: Find commit that caused it
4. Fix: Optimize or revert
5. Test: Add performance test
6. Monitor: Track in CI

See: `tools/benchmark_performance.py`

---

## Communication

### User Communication

**Acknowledgment:**
```markdown
Thanks for reporting this! I've triaged this as a {severity} issue.

**Status:** {Investigating|Working on fix|Fix in review|Fixed in vX.Y.Z}

{Brief assessment of issue}

{Workaround if available}

{Timeline estimate}
```

**Fix Released:**
```markdown
This has been fixed in v{X.Y.Z}!

**Fix:** {Brief description}
**PR:** #{pr_number}
**Release:** {release_link}

Please update to the latest version and let me know if you still encounter this issue.

Thank you for reporting this!
```

**Cannot Reproduce:**
```markdown
I've attempted to reproduce this issue but haven't been successful.

**Attempted:**
- {Step 1}
- {Step 2}

Could you provide more details:
- Complete PyGuard output (with --verbose)
- Minimal code sample that triggers the issue
- {Any other specific info needed}

Adding the `needs-more-info` label. Please respond within 7 days, otherwise this will be marked as stale.
```

---

## References

- **Bug Report Template:** `.github/ISSUE_TEMPLATE/bug_report.yml`
- **Security Policy:** `SECURITY.md`
- **Contributing Guide:** `CONTRIBUTING.md`
- **Issue Tracker:** https://github.com/cboyd0319/PyGuard/issues

---

**Status:** System established and documented
**Next Action:** Begin tracking metrics, review weekly
**Owner:** PyGuard Core Team
**Last Updated:** 2025-11-14
