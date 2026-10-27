# Security policy

CheckAm is a safety tool, so we take reports about it seriously.

## Supported versions
Only the current `main` branch and the live service at https://checkam.me are supported.

## Report a vulnerability
Do **not** open a public issue. Use one of these:
- GitHub: the **Report a vulnerability** button under this repository's Security tab (private advisory).
- Email: groundtruth.cm@gmail.com with the subject "CheckAm security".

Tell us what you found, how to reproduce it and what an attacker could do with it. We reply within 72 hours, keep you updated until it is fixed and credit you in the fix unless you ask us not to.

## In scope
- Making CheckAm call a scam genuine, or hiding instructions from Scout Intent.
- Forging a signed answer or a published alert, or breaking the alert hash chain.
- Reaching analyst routes without signing in, or getting around the abuse limits.
- Getting a citizen's phone number, a stored message or a secret out of the service.

## Out of scope
- Denial of service by volume, social engineering of the team and reports from automated scanners with no working proof.
- The sponsor services themselves (Zetaris, Meterless, NVIDIA): report those to them.

## Testing rules
Use your own test messages, never a real person's number or data, and stop as soon as you can show the problem.
