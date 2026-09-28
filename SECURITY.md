# Security

icsmatch reads advisory JSON and inventory CSV files and writes reports. It makes
outbound requests only to fetch the CISA KEV catalog and FIRST EPSS scores, and
only when not run with `--offline`.

## Reporting a vulnerability

If you find a security issue in icsmatch itself, for example a path where crafted
CSAF input causes unsafe behaviour, please report it privately rather than in a
public issue.

Open a GitHub security advisory on this repository, or email the maintainer at
the address on the GitHub profile. Expect an acknowledgement within a week.

## Scope

In scope: the icsmatch code, its parsers, and its handling of untrusted advisory
or inventory input.

Out of scope: vulnerabilities in the advisories it reads. Those belong to the
publishing vendor or CISA.
