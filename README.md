# AWS Healthcare HIPAA-Compliant PHI Isolation Network (Terraform)

An enterprise-grade, Infrastructure-as-Code implementation designed to provision an isolated network perimeter enforcing the technical safeguards specified by the **HIPAA Security Rule (45 CFR § 164.312)**.

## 📋 HIPAA Security Rule Technical Safeguards Mapping

| HIPAA Regulation Section | Architecture Control Paradigm | Resource Mapping |
| :--- | :--- | :--- |
| **§164.312(a)(2)(iv)** / **(e)(2)(ii)** | Enforced AES-256 Customer Managed Keys (CMK) with active annual cryptographic rotation for data at rest and log states. | `aws_kms_key` |
| **§164.312(b)** (Audit Controls) | Granular network ingress/egress record captures with a mandatory 7-year (2557 days) immutable retention lifecycle policy. | `aws_flow_log`, `aws_cloudwatch_log_group` |
| **§164.312(c)(1)** / **(e)(1)** | Isolation of database systems containing PHI into dedicated zero-internet subnets, stripping all unmapped ingress vectors. | `aws_vpc`, `aws_subnet`, `aws_default_security_group` |

## 🚀 Hardened Structural Security Specifications
* **Extended Healthcare Retention Engine:** Elevates the CloudWatch retention parameters to a 7-year envelope to safely guarantee compliance with federal healthcare record holding rules.
* **Hermetic Network Isolation:** PHI processing subnets are systematically denied route-table mappings to Internet Gateways or NAT Gateways, rendering them inaccessible from outside the perimeter.
