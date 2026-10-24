
def scan_config(config):
    """Check AWS-style configuration for selected security risks."""

    findings = []

    # Rule 1: SSH open to the internet
    for group in config.get("security_groups", []):
        for rule in group.get("ingress", []):
            if (
                rule.get("protocol") == "tcp"
                and rule.get("port") == 22
                and rule.get("cidr") == "0.0.0.0/0"
            ):
                findings.append({
                    "rule_id": "CG-001",
                    "severity": "HIGH",
                    "title": "SSH open to the internet",
                    "resource": group.get("name", "unknown"),
                    "recommendation": (
                        "Restrict SSH access to trusted IP addresses."
                    )
                })

    # Rule 2: S3 public access protection disabled
    for bucket in config.get("s3_buckets", []):
        if bucket.get("block_public_access") is False:
            findings.append({
                "rule_id": "CG-002",
                "severity": "HIGH",
                "title": "S3 public access protection disabled",
                "resource": bucket.get("name", "unknown"),
                "recommendation": (
                    "Review bucket policies and enable appropriate "
                    "S3 Block Public Access settings."
                )
            })

    # Rule 3: Overly permissive IAM permissions
    for policy in config.get("iam_policies", []):
        for statement in policy.get("statements", []):
            actions = statement.get("action", [])
            resources = statement.get("resource", [])

            if isinstance(actions, str):
                actions = [actions]

            if isinstance(resources, str):
                resources = [resources]

            if (
                statement.get("effect") == "Allow"
                and "*" in actions
                and "*" in resources
            ):
                findings.append({
                    "rule_id": "CG-003",
                    "severity": "HIGH",
                    "title": "Broad IAM permissions",
                    "resource": policy.get("name", "unknown"),
                    "recommendation": (
                        "Apply least privilege by allowing only "
                        "required actions on required resources."
                    )
                })

    return findings
