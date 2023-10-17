# LooneyPwner

Exploit tool for CVE-2023-4911, targeting the 'Looney Tunables' glibc vulnerability in various Linux distributions.

LooneyPwner is a proof-of-concept (PoC) exploit tool targeting the critical buffer overflow vulnerability, nicknamed "Looney Tunables," found in the GNU C Library (glibc). This flaw, officially tracked as CVE-2023-4911, is present in various Linux distributions, posing significant risks, including unauthorized data access and system alterations.

# Vulnerability Background

The vulnerability in the GNU C Library (glibc) was disclosed last week, with notable security researchers and analysts releasing PoC exploits, indicating the potential for widespread attacks. The flaw, discovered by Qualys researchers, can grant attackers root privileges on various Linux distributions including Fedora, Ubuntu, and Debian.

Unauthorized root access provides attackers unrestricted authority, enabling them to:

    Modify, delete, or steal sensitive data.
    Install malicious software or backdoors.
    Facilitate ongoing attacks that may remain undetected for extended periods.
    Cause data breaches, accessing customer data, intellectual property, and financial records.
    Disrupt critical system operations, potentially causing service outages and harming an organization's reputation.

# Tool Capabilities


LooneyPwner exploits the "Looney Tunables" flaw, targeting affected glibc versions. The tool:

    Detects the installed glibc version.
    Checks for vulnerability status.
    Offers an option for exploitation if vulnerable.

# Usage

```bash
chmod +x looneypwner.sh
./looneypwner.sh

# Disclaimer

This tool is intended for educational purposes and security research only. The user assumes all responsibility for any damages or misuse resulting from its use.

# Credits

This exploit code is based on the work of [leesh3288](https://github.com/leesh3288/CVE-2023-4911). A big thanks to him for the foundational work on the exploit.
