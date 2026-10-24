
from scanner import scan_config


def test_detects_public_ssh():
    config = {
        "security_groups": [
            {
                "name": "test-server",
                "ingress": [
                    {
                        "protocol": "tcp",
                        "port": 22,
                        "cidr": "0.0.0.0/0"
                    }
                ]
            }
        ]
    }

    findings = scan_config(config)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CG-001"
    assert findings[0]["severity"] == "HIGH"

def test_allows_restricted_ssh():
    config = {
        "security_groups": [
            {
                "name": "secure-server",
                "ingress": [
                    {
                        "protocol": "tcp",
                        "port": 22,
                        "cidr": "203.0.113.10/32"
                    }
                ]
            }
        ]
    }

    findings = scan_config(config)

    assert findings == []

def test_detects_s3_public_access_protection_disabled():
    config = {
        "s3_buckets": [
            {
                "name": "test-bucket",
                "block_public_access": False
            }
        ]
    }

    findings = scan_config(config)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CG-002"


def test_detects_broad_iam_permissions():
    config = {
        "iam_policies": [
            {
                "name": "test-policy",
                "statements": [
                    {
                        "effect": "Allow",
                        "action": "*",
                        "resource": "*"
                    }
                ]
            }
        ]
    }

    findings = scan_config(config)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CG-003"
def test_empty_config_returns_no_findings():
    config = {}

    findings = scan_config(config)

    assert findings == []