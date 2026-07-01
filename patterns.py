"""
Security signatures and regex patterns for Cyber Secret Scanner Pro.

This module houses precompiled regular expressions and associated metadata for
various types of credentials, certificates, tokens, and sensitive strings.
Each pattern is dictionary-configured with:
- name: The human-readable name of the secret type.
- regex: Precompiled regular expression.
- severity: Risk severity assigned to the finding (CRITICAL, HIGH, MEDIUM, LOW).
- description: Details regarding the vulnerability or threat context.
"""
import re
from typing import Dict, Any, List

SECRET_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "AWS Access Key",
        "regex": re.compile(r"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ASCA|ASIA)[A-Z0-9]{16}\b"),
        "severity": "HIGH",
        "description": "Amazon Web Services Access Key ID identifies your AWS account and API client."
    },
    {
        "name": "AWS Secret Key",
        "regex": re.compile(r"(?i)(?:aws_secret|aws_secret_key|aws_secret_access_key)\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"),
        "severity": "CRITICAL",
        "description": "Amazon Web Services Secret Access Key used for API request signing and full programmatic access."
    },
    {
        "name": "Google API Key",
        "regex": re.compile(r"\bAIza[Sy][A-Za-z0-9_-]{35}\b"),
        "severity": "HIGH",
        "description": "Google Cloud Platform API key used for accessing Google Developer services."
    },
    {
        "name": "Google OAuth Client ID",
        "regex": re.compile(r"\b[0-9]+-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com\b"),
        "severity": "MEDIUM",
        "description": "Google OAuth 2.0 client credential identifier used in application sign-in flows."
    },
    {
        "name": "GitHub Personal Access Token",
        "regex": re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}\b"),
        "severity": "HIGH",
        "description": "Classic GitHub Personal Access Token granting repository and account permissions."
    },
    {
        "name": "GitHub Fine Grained Token",
        "regex": re.compile(r"\bgithub_pat_[a-zA-Z0-9]{82}\b"),
        "severity": "HIGH",
        "description": "Fine-grained GitHub token with specific repository resource access permissions."
    },
    {
        "name": "Slack Token",
        "regex": re.compile(r"\bxox[bapr]-[0-9]{10,12}-[a-zA-Z0-9]{12,24}\b"),
        "severity": "CRITICAL",
        "description": "Slack API token (Bot, User, or Workspace access) providing access to communication channels."
    },
    {
        "name": "Discord Token",
        "regex": re.compile(r"\b(mfa\.[a-zA-Z0-9_-]{20,})|([a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27})\b"),
        "severity": "HIGH",
        "description": "Discord User or Bot token providing full programmatic control over accounts and guilds."
    },
    {
        "name": "Stripe Secret Key",
        "regex": re.compile(r"\bsk_(test|live)_[0-9a-zA-Z]{24,34}\b"),
        "severity": "CRITICAL",
        "description": "Stripe Secret Key used for processing financial transactions and account management."
    },
    {
        "name": "Twilio Key",
        "regex": re.compile(r"\bAC[0-9a-fA-F]{32}\b"),
        "severity": "HIGH",
        "description": "Twilio Account SID credential used to authenticate telecommunication services."
    },
    {
        "name": "JWT Token",
        "regex": re.compile(r"\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+=/]*\b"),
        "severity": "MEDIUM",
        "description": "JSON Web Token containing encoded payload. May expose sensitive internal state or user claims."
    },
    {
        "name": "Bearer Token",
        "regex": re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*\b"),
        "severity": "HIGH",
        "description": "Bearer Authentication token used to access protected HTTP resources."
    },
    {
        "name": "Basic Authorization Header",
        "regex": re.compile(r"(?i)basic\s+[A-Za-z0-9+/=]{10,}\b"),
        "severity": "HIGH",
        "description": "HTTP Basic Authentication credential header containing base64-encoded username and password."
    },
    {
        "name": "Private Key",
        "regex": re.compile(r"-----BEGIN\s+([A-Z0-9\s_]+)?PRIVATE\s+KEY-----"),
        "severity": "CRITICAL",
        "description": "Generic Private Key block used for asymmetric cryptography and authentication."
    },
    {
        "name": "RSA Key",
        "regex": re.compile(r"-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----"),
        "severity": "CRITICAL",
        "description": "RSA Private cryptographic key block used for encryption or digital signatures."
    },
    {
        "name": "OpenSSH Key",
        "regex": re.compile(r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----"),
        "severity": "CRITICAL",
        "description": "OpenSSH Private Key block used for SSH client certificate authentication."
    },
    {
        "name": "PEM Key",
        "regex": re.compile(r"-----BEGIN\s+[A-Z0-9\s_]+\b"),
        "severity": "HIGH",
        "description": "Privacy Enhanced Mail (PEM) header, signaling start of certificates or keys."
    },
    {
        "name": "MongoDB Connection String",
        "regex": re.compile(r"mongodb(?:\+srv)?://[a-zA-Z0-9\-._~%!$&'()*+,;=:]+:[a-zA-Z0-9\-._~%!$&'()*+,;=:]+@[a-zA-Z0-9\-._~%!$&'()*+,;=:]+"),
        "severity": "CRITICAL",
        "description": "MongoDB URI connection string with inline username and password credentials."
    },
    {
        "name": "MySQL Connection String",
        "regex": re.compile(r"mysql://[a-zA-Z0-9\-._~%!$&'()*+,;=:]+:[a-zA-Z0-9\-._~%!$&'()*+,;=:]+@[a-zA-Z0-9\-._~%!$&'()*+,;=:]+"),
        "severity": "CRITICAL",
        "description": "MySQL database connection URI containing access credentials."
    },
    {
        "name": "PostgreSQL Connection String",
        "regex": re.compile(r"postgres(?:ql)?://[a-zA-Z0-9\-._~%!$&'()*+,;=:]+:[a-zA-Z0-9\-._~%!$&'()*+,;=:]+@[a-zA-Z0-9\-._~%!$&'()*+,;=:]+"),
        "severity": "CRITICAL",
        "description": "PostgreSQL database connection URI containing active access credentials."
    },
    {
        "name": "Redis URL",
        "regex": re.compile(r"redis(?:s)?://:[a-zA-Z0-9\-._~%!$&'()*+,;=:]+@[a-zA-Z0-9\-._~%!$&'()*+,;=:]+"),
        "severity": "HIGH",
        "description": "Redis connection URL with exposed authentication password."
    },
    {
        "name": "Firebase URL",
        "regex": re.compile(r"https://[a-zA-Z0-9\-]+\.firebaseio\.com"),
        "severity": "LOW",
        "description": "Firebase Realtime Database URL endpoints, useful for mapping data infrastructure."
    },
    {
        "name": "Hardcoded Password",
        "regex": re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{6,50})['\"]"),
        "severity": "HIGH",
        "description": "Exposed hardcoded password or credential string in source file."
    },
    {
        "name": "Hardcoded API Key",
        "regex": re.compile(r"(?i)(?:api_key|apikey|api-key)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,64})['\"]"),
        "severity": "HIGH",
        "description": "Potential API Key variable assignment with hardcoded value."
    },
    {
        "name": "Generic Secret Key",
        "regex": re.compile(r"(?i)(?:secret|secret_key|secretkey)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,64})['\"]"),
        "severity": "HIGH",
        "description": "Variable assignment indicating generic cryptographic or authentication secret."
    },
    {
        "name": "Environment Variables",
        "regex": re.compile(r"(?i)export\s+(?:AWS_SECRET|DATABASE_URL|SECRET_KEY|API_KEY|PASSWORD|TOKEN)\s*=\s*['\"]?([^'\"\n]{8,})['\"]?"),
        "severity": "HIGH",
        "description": "Environment variable exports containing raw sensitive access parameters."
    },
    {
        "name": "Database Password",
        "regex": re.compile(r"(?i)(?:db_password|db_pass|dbpass|dbpassword)\s*[:=]\s*['\"]([^'\"]{4,50})['\"]"),
        "severity": "HIGH",
        "description": "Explicit database login password variable set directly in codebase."
    },
    {
        "name": "Encryption Key",
        "regex": re.compile(r"(?i)(?:encryption_key|encrypt_key|cipher_key)\s*[:=]\s*['\"]([a-zA-Z0-9+/=]{16,64})['\"]"),
        "severity": "HIGH",
        "description": "Symmetric cryptographic key or initialization vector exposed in code."
    },
    {
        "name": "Webhook URL",
        "regex": re.compile(r"https://hooks\.(?:slack|discord|teams)\.com/services/[A-Za-z0-9_/]+"),
        "severity": "MEDIUM",
        "description": "Slack, Discord, or MS Teams incoming Webhook URL. Allows posting message payloads."
    },
    {
        "name": "Cryptographic Secret",
        "regex": re.compile(r"(?i)(?:salt|key_derivation|passphrase|private_salt)\s*[:=]\s*['\"]([^'\"]{6,100})['\"]"),
        "severity": "MEDIUM",
        "description": "Exposed salt, passphrase, or helper seed for key derivation algorithms."
    },
    {
        "name": "Azure Key",
        "regex": re.compile(r"(?i)(?:azure_storage_key|azure_key|azure_secret)\s*[:=]\s*['\"]([a-zA-Z0-9+/=]{88})['\"]"),
        "severity": "CRITICAL",
        "description": "Microsoft Azure storage account key or service principal client secret."
    },
    {
        "name": "DigitalOcean Token",
        "regex": re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),
        "severity": "CRITICAL",
        "description": "DigitalOcean Personal Access Token for full API account resource creation and control."
    },
    {
        "name": "Heroku API Key",
        "regex": re.compile(r"(?i)(?:heroku_api_key|heroku_key)\s*[:=]\s*['\"]([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['\"]"),
        "severity": "CRITICAL",
        "description": "Heroku platform API authentication token."
    },
    {
        "name": "GitLab Token",
        "regex": re.compile(r"\bglpat-[a-zA-Z0-9\-=_]{20,}\b"),
        "severity": "HIGH",
        "description": "GitLab Personal Access Token providing API and repository write permission."
    },
    {
        "name": "Bitbucket Token",
        "regex": re.compile(r"(?i)(?:bitbucket_token|bitbucket_client_secret)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]"),
        "severity": "HIGH",
        "description": "Bitbucket OAuth client secret or access token."
    },
    {
        "name": "OpenAI API Key",
        "regex": re.compile(r"\bsk-(proj-[a-zA-Z0-9]{20,}|[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})\b"),
        "severity": "CRITICAL",
        "description": "OpenAI API Key giving authorization to run language models and billing endpoints."
    },
    {
        "name": "Anthropic API Key",
        "regex": re.compile(r"\bsk-ant-sid01-[a-zA-Z0-9_-]{93,}\b"),
        "severity": "CRITICAL",
        "description": "Anthropic Claude API token key."
    },
    {
        "name": "HuggingFace Token",
        "regex": re.compile(r"\bhf_[a-zA-Z0-9]{34}\b"),
        "severity": "HIGH",
        "description": "Hugging Face developer access token for weights download and model hub hosting."
    },
    {
        "name": "SSH Private Key",
        "regex": re.compile(r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----"),
        "severity": "CRITICAL",
        "description": "OpenSSH-specific format Private Key. Authorizes access to remote server shells."
    },
    {
        "name": "SSH Public Key",
        "regex": re.compile(r"\bssh-(rsa|dss|ed25519)\s+[A-Za-z0-9+/=]{50,}\b"),
        "severity": "LOW",
        "description": "SSH public key. Typically not secret but useful for mapping trusted systems."
    },
    {
        "name": "RSA Private Key",
        "regex": re.compile(r"-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----"),
        "severity": "CRITICAL",
        "description": "PEM formatted RSA Private Key block."
    },
    {
        "name": "EC Private Key",
        "regex": re.compile(r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----"),
        "severity": "CRITICAL",
        "description": "Elliptic Curve (EC) cryptographic format private key block."
    },
    {
        "name": "OAuth Token",
        "regex": re.compile(r"(?i)(?:oauth_token|oauth-token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,100})['\"]"),
        "severity": "HIGH",
        "description": "Generic OAuth client secret or access token identifier."
    },
    {
        "name": "Session Token",
        "regex": re.compile(r"(?i)(?:session_token|session-token|sessionid)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,100})['\"]"),
        "severity": "MEDIUM",
        "description": "Authentication session token variable assignment."
    },
    {
        "name": "Cookie Secret",
        "regex": re.compile(r"(?i)(?:cookie_secret|cookie-secret|cookie_key)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,100})['\"]"),
        "severity": "MEDIUM",
        "description": "Signing secret key for securing HTTP cookie tokens against client tempering."
    }
]
