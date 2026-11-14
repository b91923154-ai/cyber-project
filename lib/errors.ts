/**
 * errors.ts — Human-friendly error translation for user and system exceptions.
 * Provides clear explanations, friendly titles, and helpful next steps for both
 * client-facing and server-side errors.
 */

export interface FriendlyError {
  title: string;
  message: string;
  hint: string;
  code: string;
  isUserError: boolean;
}

export function formatFriendlyError(
  code: string = "UNKNOWN",
  rawMessage: string = ""
): FriendlyError {
  const normCode = (code || "").toUpperCase();
  const lowerMsg = (rawMessage || "").toLowerCase();

  // 1. Denylisted targets (Gov, mil, high-profile like google.com, apple.com)
  if (normCode === "DENYLISTED" || lowerMsg.includes("denylist")) {
    return {
      title: "Protected Target Domain",
      message:
        "This domain is protected under CyberShield's Safe by Design policy (e.g. government, critical infrastructure, or major cloud provider). Security probing against it is restricted to prevent unauthorized scanning abuse.",
      hint: "Please test against a website, web app, or staging domain that you own or have permission to audit.",
      code: "DENYLISTED",
      isUserError: true,
    };
  }

  // 2. SSRF / IP literal (127.0.0.1, 169.254.169.254, etc.)
  if (normCode === "IP_LITERAL" || lowerMsg.includes("ip address")) {
    return {
      title: "Direct IP Scanning Restricted",
      message:
        "Scanning raw IP addresses directly is restricted to prevent probing internal, loopback, or private networks.",
      hint: "Please enter a public domain name (e.g. example.com) rather than an IP address.",
      code: "IP_LITERAL",
      isUserError: true,
    };
  }

  // 3. Internal / single-label hostnames (localhost, .local, intranet)
  if (normCode === "INTERNAL_HOST" || lowerMsg.includes("internal host")) {
    return {
      title: "Internal Hostname Restricted",
      message:
        "Single-label and internal hostnames (such as localhost, .local, or intranet) are blocked by CyberShield's Pre-Connection SSRF Guard.",
      hint: "Please use a publicly accessible domain name for your security assessment.",
      code: "INTERNAL_HOST",
      isUserError: true,
    };
  }

  // 4. Blocked private IP address resolution (SSRF)
  if (normCode === "BLOCKED_ADDRESS" || lowerMsg.includes("non-public address")) {
    return {
      title: "Private Address Blocked (SSRF Shield)",
      message:
        "The target domain resolved to a private, loopback, or cloud-metadata IP address. Our SSRF firewall blocked the connection before any network packets were sent.",
      hint: "Make sure your domain's DNS A/AAAA records point to a publicly routable IP address.",
      code: "BLOCKED_ADDRESS",
      isUserError: true,
    };
  }

  // 5. DNS Resolution Failure
  if (normCode === "DNS_FAIL" || lowerMsg.includes("dns") || lowerMsg.includes("could not be resolved")) {
    return {
      title: "Domain Resolution Failed",
      message:
        "We couldn't find active DNS records for this domain. The domain might be misspelled, unregistered, or its nameservers might currently be unavailable.",
      hint: "Check the spelling of the domain and confirm it opens normally in your web browser.",
      code: "DNS_FAIL",
      isUserError: true,
    };
  }

  // 6. Bad URL format or credentials
  if (normCode === "BAD_INPUT" || lowerMsg.includes("invalid characters") || lowerMsg.includes("credentials")) {
    return {
      title: "Invalid Target URL",
      message:
        "The entered address could not be parsed as a standard domain or URL.",
      hint: "Try typing a simple web address like 'example.com' or 'https://example.com' without credentials or spaces.",
      code: "BAD_INPUT",
      isUserError: true,
    };
  }

  // 7. Non-standard ports
  if (normCode === "BAD_PORT" || lowerMsg.includes("port")) {
    return {
      title: "Port Restricted",
      message:
        "Scanning is limited to standard web ports (80 for HTTP and 443 for HTTPS) to adhere to safe, non-intrusive scanning standards.",
      hint: "Remove any custom port numbers (e.g., :8080 or :3000) from your target URL.",
      code: "BAD_PORT",
      isUserError: true,
    };
  }

  // 8. Unsupported protocol
  if (normCode === "BAD_SCHEME" || lowerMsg.includes("scheme") || lowerMsg.includes("protocol")) {
    return {
      title: "Unsupported Protocol",
      message: "CyberShield scans web applications over standard HTTP and HTTPS protocols only.",
      hint: "Please use 'https://' or enter the domain name directly.",
      code: "BAD_SCHEME",
      isUserError: true,
    };
  }

  // 9. Ownership Verification Required
  if (normCode === "NOT_VERIFIED" || lowerMsg.includes("ownership") || lowerMsg.includes("verification required")) {
    return {
      title: "Domain Ownership Verification Required",
      message:
        "Deep scanning executes active security probes. To follow legal safe harbor guidelines and prevent unauthorized scans, technical domain ownership must be verified first.",
      hint: "Publish the DNS TXT record, upload the .well-known file, or insert the HTML meta tag, then click 'Verify Now'.",
      code: "NOT_VERIFIED",
      isUserError: true,
    };
  }

  // 9b. Legal Attestation Required
  if (normCode === "ATTESTATION_REQUIRED" || lowerMsg.includes("attestation") || lowerMsg.includes("written authorization")) {
    return {
      title: "Legal Attestation Required",
      message:
        "Deep Scan active tests require explicit legal attestation that you own or possess written authorization to perform security testing on this domain.",
      hint: "Check the 'Legal Attestation & Scope Agreement' box in the verification panel.",
      code: "ATTESTATION_REQUIRED",
      isUserError: true,
    };
  }

  // 10. Rate limiting (429)
  if (normCode === "RATE_LIMITED" || lowerMsg.includes("rate limit") || lowerMsg.includes("too many times")) {
    return {
      title: "Scan Cooldown Active",
      message:
        "This client or target host has initiated multiple scans recently. A temporary cooldown is in place to protect web infrastructure.",
      hint: "Please wait 30–60 seconds before launching your next scan.",
      code: "RATE_LIMITED",
      isUserError: true,
    };
  }

  // 11. Verification secret missing (Server setup)
  if (normCode === "VERIFY_SECRET_MISSING" || lowerMsg.includes("cs_verify_secret")) {
    return {
      title: "Server Configuration Update in Progress",
      message:
        "The verification engine is currently running with default configuration and requires its verification key to be initialized.",
      hint: "Basic passive scans remain available. For deep scanning, ensure CS_VERIFY_SECRET is set in .env.local.",
      code: "CONFIG_ERROR",
      isUserError: false,
    };
  }

  // 12. HTTPS Connection Failed / Reachability error
  if (lowerMsg.includes("failed to query https") || lowerMsg.includes("econnrefused") || lowerMsg.includes("timed out")) {
    return {
      title: "Target Website Unreachable",
      message:
        "We could not establish a connection to the target web server. The site might be temporarily offline, rejecting incoming automated traffic, or blocking HTTPS connections.",
      hint: "Ensure the target site is live and reachable via HTTPS in your web browser.",
      code: "UNREACHABLE",
      isUserError: false,
    };
  }

  // 13. Fallback: Friendly general exception
  return {
    title: "Scan Process Interrupted",
    message: rawMessage || "An unexpected error occurred while communicating with the target or analyzing telemetry.",
    hint: "Please verify the domain name, check your network connection, and try again in a moment.",
    code: normCode || "UNEXPECTED_ERROR",
    isUserError: false,
  };
}
