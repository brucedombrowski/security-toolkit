# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in the Security Verification Toolkit,
please **DO NOT** open a public GitHub issue or discussion.

Instead, please report via GitHub Security Advisories:
https://github.com/brucedombrowski/Security/security/advisories/new

## What to Include

When reporting a security vulnerability, please provide:

1. **Vulnerability Description**
   - What is the vulnerability?
   - What component(s) are affected?
   - How could it be exploited?

2. **Affected Versions**
   - Which versions of the toolkit are affected?
   - Is it present in the main branch?

3. **Steps to Reproduce**
   - Detailed steps to reproduce the issue
   - Proof-of-concept code (if applicable)

4. **Potential Impact**
   - What data could be compromised?
   - What systems could be affected?
   - What is the risk level?

5. **Suggested Fix** (optional)
   - If you have a suggested fix, please include it

## Responsible Disclosure Timeline

We follow coordinated vulnerability disclosure:

1. **Day 0:** You report vulnerability via GitHub Security Advisory
2. **Day 1:** We acknowledge receipt and assign severity level
3. **Day 7:** We provide initial assessment or request clarification
4. **Day 30:** We provide patch/workaround or timeline to fix
5. **Day 90:** We release public fix (if you have not already disclosed)

If you disclose the vulnerability before our patch is available, we may
accelerate our timeline.

## Security Acknowledgments

We recognize and appreciate researchers who responsibly disclose vulnerabilities.
After a fix is released, we will:

- Acknowledge your contribution (with your permission)
- Credit you in CHANGELOG.md
- Add you to our Security Contributors list (optional)

## Scope

### In Scope

- Remote code execution vulnerabilities
- Privilege escalation
- Authentication/authorization bypasses
- Data exposure or leakage
- Denial of service (DoS)
- Cryptographic weaknesses
- Injection vulnerabilities (command, LaTeX, template, etc.)
- Insecure file operations (symlinks, permissions, etc.)

### Out of Scope

- Social engineering
- Phishing
- Physical security
- Issues in dependencies (report to upstream)
- Performance issues without security implications
- Missing documentation
- Feature requests

## Security Updates

We will release security patches:

- **Critical:** Within 24 hours of verification
- **High:** Within 7 days of verification
- **Medium:** Within 30 days of verification
- **Low:** Within 90 days or next regular release

All security updates will be tagged with `[SECURITY]` in commit messages
and detailed in CHANGELOG.md.

## Vulnerability Disclosure FAQ

**Q: How long should I wait before disclosing publicly?**
A: We ask for a 90-day embargo from initial report. After 90 days, you may
disclose publicly if we haven't released a patch. We will coordinate the
release to minimize impact.

**Q: Will you provide a CVE?**
A: For critical vulnerabilities with broad impact, we may request a CVE through
GitHub's security advisory feature.

**Q: What if I don't hear back?**
A: If you don't receive acknowledgment within 48 hours, please resend your
email.

**Q: Can I publish my research after the fix is released?**
A: Yes! We encourage responsible security research. After a patch is released,
you're welcome to publish details, blog posts, or conference presentations.

## Security Contact

- **GitHub Security Advisories:** https://github.com/brucedombrowski/Security/security/advisories/new

## Related Documents

- [CLAUDE.md](./CLAUDE.md) - AI agent instructions and architecture
- [docs/COMPLIANCE.md](./docs/COMPLIANCE.md) - Compliance framework
- [docs/FALSE-POSITIVES-MACOS.md](./docs/FALSE-POSITIVES-MACOS.md) - macOS security notes

---

Last Updated: January 30, 2026
