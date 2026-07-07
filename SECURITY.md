# Security Policy

## Supported repositories

This repository contains public-safe examples, scripts, documentation or automation assets maintained under the Jarnon404 GitHub profile.

Only the latest public version is actively maintained unless otherwise stated in the repository documentation.

## Reporting a vulnerability or sensitive data issue

If you discover a security issue, exposed secret, accidentally committed customer-specific data or other sensitive information in this repository, please do not open a public issue containing the sensitive details.

Instead, contact the repository owner through the GitHub profile or another appropriate private channel.

## Public-safe content rules

This repository must not contain:

- Passwords, tokens, API keys or private keys
- Tenant IDs, customer IDs or environment-specific identifiers
- Customer names or internal organization names
- Internal hostnames, server names or domain names
- Private IP addresses from real environments
- Generated audit reports from customer, employer or production systems
- Screenshots or exports containing identifiable environment data

## Operational safety

Scripts and examples are provided as-is and must be reviewed before use.

Before running anything in a real environment:

- Read the script before executing it
- Test in a lab, sandbox or pilot environment first
- Use least privilege where possible
- Prefer read-only permissions for audit scripts
- Do not commit generated reports or environment-specific output

## Scope

This policy applies to the public contents of this repository.
