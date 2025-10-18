"""Generate test images for CyberShield sample prompts testing."""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


def create_security_logs_screenshot():
    """Generate a screenshot-style image with security logs and IP addresses."""
    # Create a dark terminal-style background
    img = Image.new("RGB", (1200, 800), color=(30, 30, 30))
    draw = ImageDraw.Draw(img)

    # Try to use a monospace font, fallback to default
    try:
        font = ImageFont.truetype("/System/Library/Fonts/Monaco.ttf", 14)
        title_font = ImageFont.truetype("/System/Library/Fonts/Monaco.ttf", 18)
    except OSError:
        font = ImageFont.load_default()
        title_font = ImageFont.load_default()

    # Title
    draw.text(
        (20, 20),
        "Security Log Monitor - Active Threats Detected",
        fill=(255, 100, 100),
        font=title_font,
    )

    # Security logs with various IOCs
    logs = [
        "[2024-08-15 14:23:45] WARNING: Failed login attempt from 203.0.113.42",
        "[2024-08-15 14:23:48] ERROR: Multiple failed attempts from IP: 198.51.100.5",
        "[2024-08-15 14:24:12] ALERT: Suspicious hash detected: d41d8cd98f00b204e9800998ecf8427e",
        "[2024-08-15 14:24:15] CRITICAL: Connection to malware-c2.example.com blocked",
        "[2024-08-15 14:25:01] WARNING: Port scan detected from 185.220.101.42:443",
        "[2024-08-15 14:25:30] ERROR: DNS query for bitcoin-miner.ru detected",
        "[2024-08-15 14:26:10] ALERT: Process hash: 5d41402abc4b2a76b9719d911017c592",
        "[2024-08-15 14:26:45] CRITICAL: Lateral movement: 10.0.0.15 -> 10.0.0.25",
        "[2024-08-15 14:27:20] WARNING: Cobalt Strike beacon signature detected",
        "[2024-08-15 14:27:55] ERROR: C2 server: command-control.darkweb.onion",
        "[2024-08-15 14:28:30] ALERT: Bitcoin wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "[2024-08-15 14:29:05] CRITICAL: SHA256: a665a45920422f9d417e4867efdc4fb8",
        "[2024-08-15 14:29:40] WARNING: Firewall rule violated by 192.168.1.100",
        "[2024-08-15 14:30:15] ERROR: Suspicious domain: phishing-site.ru",
        "[2024-08-15 14:30:50] ALERT: Email from suspicious.sender@temp-mail.org",
        "[2024-08-15 14:31:25] CRITICAL: SSH brute force detected from 8.8.8.8",
        "",
        "Total threats detected: 16 | Active blocks: 8 | Under investigation: 8",
    ]

    y_offset = 70
    for log in logs:
        # Color code based on severity
        if "CRITICAL" in log:
            color = (255, 50, 50)
        elif "ERROR" in log:
            color = (255, 150, 50)
        elif "WARNING" in log:
            color = (255, 200, 50)
        elif "ALERT" in log:
            color = (255, 100, 150)
        elif "Total threats" in log:
            color = (100, 200, 255)
        else:
            color = (200, 200, 200)

        draw.text((20, y_offset), log, fill=color, font=font)
        y_offset += 35

    return img


def create_email_pii_screenshot():
    """Generate an email screenshot with PII data."""
    img = Image.new("RGB", (1000, 700), color=(245, 245, 245))
    draw = ImageDraw.Draw(img)

    try:
        font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 14)
        title_font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 18)
        bold_font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 16)
    except OSError:
        font = ImageFont.load_default()
        title_font = ImageFont.load_default()
        bold_font = ImageFont.load_default()

    # Email header background
    draw.rectangle([(0, 0), (1000, 60)], fill=(70, 130, 180))
    draw.text((20, 20), "SecureMail Pro - Inbox", fill=(255, 255, 255), font=title_font)

    # Email container
    draw.rectangle(
        [(20, 80), (980, 680)], fill=(255, 255, 255), outline=(200, 200, 200)
    )

    # Email metadata
    draw.text((40, 100), "From:", fill=(100, 100, 100), font=bold_font)
    draw.text((120, 100), "john.doe@company.com", fill=(50, 50, 50), font=font)

    draw.text((40, 130), "To:", fill=(100, 100, 100), font=bold_font)
    draw.text((120, 130), "hr-department@company.com", fill=(50, 50, 50), font=font)

    draw.text((40, 160), "Subject:", fill=(100, 100, 100), font=bold_font)
    draw.text(
        (120, 160),
        "Employee Information Update Request",
        fill=(50, 50, 50),
        font=font,
    )

    draw.line([(40, 190), (960, 190)], fill=(200, 200, 200), width=2)

    # Email body with PII
    email_body = [
        "",
        "Dear HR Team,",
        "",
        "I need to update my personal information in the system:",
        "",
        "Full Name: John Michael Doe",
        "Social Security Number: 123-45-6789",
        "Date of Birth: 1985-03-15",
        "Phone Number: +1-555-0123",
        "Personal Email: john.doe.personal@gmail.com",
        "Credit Card (for expenses): 4532-1234-5678-9012",
        "Driver's License: CA-D1234567",
        "",
        "Emergency Contact:",
        "Name: Jane Smith",
        "Phone: +1-555-0199",
        "Email: jane.smith@company.org",
        "",
        "Please process this information securely.",
        "",
        "Best regards,",
        "John Doe",
    ]

    y_offset = 210
    for line in email_body:
        # Highlight PII fields
        if any(
            keyword in line
            for keyword in [
                "SSN",
                "Social Security",
                "Credit Card",
                "Driver's License",
                "Date of Birth",
            ]
        ):
            color = (200, 0, 0)
        else:
            color = (50, 50, 50)

        draw.text((40, y_offset), line, fill=color, font=font)
        y_offset += 22

    return img


def create_security_dashboard():
    """Generate a security alert dashboard mockup."""
    img = Image.new("RGB", (1400, 900), color=(240, 240, 245))
    draw = ImageDraw.Draw(img)

    try:
        font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 14)
        title_font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 24)
        header_font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 18)
    except OSError:
        font = ImageFont.load_default()
        title_font = ImageFont.load_default()
        header_font = ImageFont.load_default()

    # Top header
    draw.rectangle([(0, 0), (1400, 80)], fill=(40, 40, 60))
    draw.text(
        (40, 25),
        "CyberShield Security Dashboard",
        fill=(255, 255, 255),
        font=title_font,
    )
    draw.text((1150, 30), "Status: ACTIVE", fill=(100, 255, 100), font=header_font)

    # Critical Alerts Panel
    draw.rectangle(
        [(20, 100), (680, 420)], fill=(255, 250, 250), outline=(255, 0, 0), width=3
    )
    draw.rectangle([(20, 100), (680, 140)], fill=(255, 100, 100))
    draw.text((30, 110), "CRITICAL ALERTS (3)", fill=(255, 255, 255), font=header_font)

    alerts = [
        "⚠ APT Activity Detected",
        "   Source: 203.0.113.42",
        "   Target: Internal Server 10.0.0.25",
        "   Signature: Cobalt Strike Beacon",
        "",
        "⚠ Malware C2 Communication",
        "   Domain: command-control.darkweb.onion",
        "   Hash: a665a45920422f9d417e4867efdc4fb8",
        "   Action: Connection Blocked",
        "",
        "⚠ Data Exfiltration Attempt",
        "   Volume: 2.5 GB transferred",
        "   Destination: 185.220.101.42:443",
        "   Status: Prevented",
    ]

    y = 160
    for alert in alerts:
        draw.text((40, y), alert, fill=(100, 0, 0), font=font)
        y += 20

    # Network Activity Panel
    draw.rectangle(
        [(720, 100), (1380, 420)], fill=(250, 255, 250), outline=(0, 150, 0), width=2
    )
    draw.rectangle([(720, 100), (1380, 140)], fill=(100, 180, 100))
    draw.text((730, 110), "NETWORK ACTIVITY", fill=(255, 255, 255), font=header_font)

    network_data = [
        "Active Connections: 1,247",
        "Blocked IPs: 42",
        "Firewall Rules: 156 active",
        "",
        "Top Blocked Sources:",
        "  198.51.100.5 (15 attempts)",
        "  203.0.113.42 (12 attempts)",
        "  185.220.101.42 (8 attempts)",
        "",
        "Suspicious Domains:",
        "  malware-c2.example.com",
        "  bitcoin-miner.ru",
        "  phishing-site.ru",
    ]

    y = 160
    for line in network_data:
        draw.text((740, y), line, fill=(0, 80, 0), font=font)
        y += 20

    # IOC Summary Panel
    draw.rectangle(
        [(20, 440), (680, 880)], fill=(250, 250, 255), outline=(100, 100, 200), width=2
    )
    draw.rectangle([(20, 440), (680, 480)], fill=(100, 100, 200))
    draw.text(
        (30, 450), "INDICATORS OF COMPROMISE", fill=(255, 255, 255), font=header_font
    )

    ioc_data = [
        "IP Addresses (8):",
        "  203.0.113.42, 198.51.100.5, 185.220.101.42",
        "  192.168.1.100, 10.0.0.15, 10.0.0.25, 8.8.8.8",
        "",
        "File Hashes (4):",
        "  d41d8cd98f00b204e9800998ecf8427e",
        "  5d41402abc4b2a76b9719d911017c592",
        "  a665a45920422f9d417e4867efdc4fb8",
        "  7c4a8d09ca3762af61e59520943dc26494f8941b",
        "",
        "Domains (4):",
        "  malware-c2.example.com",
        "  bitcoin-miner.ru",
        "  command-control.darkweb.onion",
        "  phishing-site.ru",
        "",
        "Bitcoin Addresses (2):",
        "  1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "  3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
    ]

    y = 500
    for line in ioc_data:
        draw.text((40, y), line, fill=(50, 50, 150), font=font)
        y += 20

    # System Status Panel
    draw.rectangle(
        [(720, 440), (1380, 880)], fill=(255, 255, 250), outline=(200, 150, 0), width=2
    )
    draw.rectangle([(720, 440), (1380, 480)], fill=(200, 150, 0))
    draw.text((730, 450), "SYSTEM STATUS", fill=(255, 255, 255), font=header_font)

    status_data = [
        "Threat Detection: ENABLED",
        "Real-time Monitoring: ACTIVE",
        "Auto-blocking: ENABLED",
        "",
        "Agent Status:",
        "  ✓ PII Agent: Running",
        "  ✓ Threat Agent: Running",
        "  ✓ Log Parser: Running",
        "  ✓ Vision Agent: Running",
        "  ✓ Supervisor: Running",
        "",
        "Security Tools:",
        "  ✓ VirusTotal: Connected",
        "  ✓ Shodan: Connected",
        "  ✓ AbuseIPDB: Connected",
        "  ✓ Milvus DB: Operational",
        "  ✓ Redis Cache: Operational",
        "",
        "Last Updated: 2024-08-15 14:31:25",
        "Uptime: 45 days, 12 hours, 23 minutes",
    ]

    y = 500
    for line in status_data:
        if "✓" in line:
            color = (0, 150, 0)
        else:
            color = (100, 80, 0)
        draw.text((740, y), line, fill=color, font=font)
        y += 20

    return img


def main():
    """Generate all test images."""
    output_dir = Path(__file__).parent / "test_images"
    output_dir.mkdir(exist_ok=True)

    print("Generating test images for CyberShield sample prompts...")

    # Generate security logs screenshot
    print("  Creating security_logs_screenshot.png...")
    security_logs = create_security_logs_screenshot()
    security_logs.save(output_dir / "security_logs_screenshot.png")
    print("    ✓ Security logs screenshot created")

    # Generate email with PII
    print("  Creating email_with_pii.png...")
    email_pii = create_email_pii_screenshot()
    email_pii.save(output_dir / "email_with_pii.png")
    print("    ✓ Email with PII screenshot created")

    # Generate security dashboard
    print("  Creating security_dashboard.png...")
    dashboard = create_security_dashboard()
    dashboard.save(output_dir / "security_dashboard.png")
    print("    ✓ Security dashboard created")

    print(f"\n✅ All test images generated successfully in {output_dir}")
    print("\nGenerated images:")
    print("  - security_logs_screenshot.png (1200x800)")
    print("  - email_with_pii.png (1000x700)")
    print("  - security_dashboard.png (1400x900)")


if __name__ == "__main__":
    main()
