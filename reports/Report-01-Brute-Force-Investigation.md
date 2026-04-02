# Week 1 – Authentication Attacks & Windows Security Logs  
## Report #1 – Brute Force / Password Guessing Investigation

---

## Goals

- Understand failed vs successful authentication and what patterns indicate brute force.
- Learn to filter and correlate Windows Security log events (4624 vs 4625).
- Produce an investigation report structured like a SOC ticket.

---

## Lab Setup Summary

- Environment: Windows 10 VM (VMware)
- Log Source: Windows Security Logs
- Event IDs Analyzed:
  - 4625 – Failed Logon
  - 4624 – Successful Logon

---

## Practical Execution (Step-by-Step)

1. Created a local test account named `labuser`.
2. Attempted 10–15 failed login attempts using an incorrect password, spacing each attempt 2–3 seconds apart.
3. Logged in successfully once using the correct password.
4. Opened **Event Viewer → Windows Logs → Security**.
5. Filtered the current log for **Event ID 4625** (failed logons).
6. Exported relevant 4625 events for analysis.
7. Filtered the log for **Event ID 4624** (successful logon).
8. Identified the successful authentication that occurred after the failed attempts.
9. Extracted the following fields from each 4625 event:
   - Account Name  
   - Logon Type  
   - Failure Reason  
   - Source Network Address  
10. Built a timeline correlating failed attempts and successful login.
11. Determined verdict based on volume, timing, and source.

---

## Evidence Collected

### Failed Logon Events (Event ID 4625)

| Time       | Account Name | Logon Type | Source IP   | Failure Reason                          |
|------------|-------------|------------|------------|------------------------------------------|
| 23:09:44   | labuser     | 2          | 127.0.0.1  | Unknown user name or bad password       |
| 23:09:53   | labuser     | 2          | 127.0.0.1  | Unknown user name or bad password       |
| 23:10:05   | labuser     | 2          | 127.0.0.1  | Unknown user name or bad password       |
| (additional attempts omitted for brevity) |

### Successful Logon (Event ID 4624)

| Time       | Account Name | Logon Type | Source IP   |
|------------|-------------|------------|------------|
| 23:10:18   | labuser     | 2          | 127.0.0.1  |

---

## Timeline Reconstruction

| Time       | Activity |
|------------|----------|
| 23:09:44   | First failed login attempt |
| 23:09:53   | Second failed login attempt |
| 23:10:05   | Third failed login attempt |
| 23:10:18   | Successful authentication |

---

## Analysis

### Pattern Observed

- Multiple failed login attempts in short time window.
- All attempts originated from **127.0.0.1 (localhost)**.
- Logon Type = **2 (Interactive / keyboard login)**.
- A successful authentication followed shortly after failures.

### Brute Force Indicators (What We Look For)

- High-volume attempts (50+ attempts typical in real attack)
- Attempts from remote or multiple IP addresses
- Multiple usernames targeted
- No successful login afterward

### Observed Behavior

- Limited number of attempts (controlled lab simulation)
- Same local machine source
- Immediate successful login afterward
- No additional suspicious activity detected

---

## Verdict

**False Positive – User Authentication Error**

The pattern indicates manual password entry error rather than automated brute force activity. The successful authentication immediately following failed attempts supports this assessment.

---

## Containment & Recommendations

No containment required in this case.

Recommendations for production environments:

- Implement account lockout policy after X failed attempts.
- Configure SIEM alert for excessive 4625 events within defined time threshold.
- Monitor for repeated authentication failures from external IP addresses.

---

## Lessons Learned

- Always correlate 4625 (failures) with 4624 (success).
- Logon Type is critical in determining attack method.
- Source IP context prevents false escalation.
- Volume and distribution patterns distinguish brute force from user error.

---

### Skills Demonstrated

- Windows Security Log analysis
- Event ID correlation (4624 vs 4625)
- Authentication pattern recognition
- Timeline reconstruction
- SOC-style documentation
