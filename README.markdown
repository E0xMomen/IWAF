# Web Application Firewall (WAF) with Flask

## Overview

This project implements a robust **Web Application Firewall (WAF)** built using **Flask**, a lightweight Python web framework. The WAF provides advanced security features to protect web applications from common threats such as SQL injection, cross-site scripting (XSS), command injection, and Distributed Denial of Service (DDoS) attacks. It includes IP-based rate limiting, malicious payload detection, VirusTotal integration for IP reputation checks, and real-time Telegram alerts for security incidents. The system also features a user-friendly dashboard for administrators to manage blacklists, trusted IPs, and user accounts.

## Features

- **Authentication & Authorization**:
  - User management with roles (admin and user).
  - Secure login system using Flask-Login and Bcrypt for password hashing.
  - Role-based access control for admin-only routes.

- **Security Mechanisms**:
  - **IP Blacklisting & Whitelisting**: Automatically or manually block malicious IPs and maintain a trusted IP list.
  - **Rate Limiting**: Configurable request rate limits per IP to mitigate DDoS attacks.
  - **Payload Inspection**: Detects malicious payloads using regex patterns and an optional machine learning model.
  - **VirusTotal Integration**: Checks IP reputation using the VirusTotal API with caching for performance.
  - **Firewall Integration**: Blocks IPs at the OS firewall level (supports Linux, Windows, and macOS).
  - **Slow Request Detection**: Identifies and blocks IPs sending suspiciously slow requests.
  - **Concurrent Request Limits**: Restricts excessive simultaneous connections per IP.
  - **Request Size Validation**: Limits payload and header sizes to prevent abuse.

- **Monitoring & Logging**:
  - Comprehensive logging of security events, including attack attempts and blocked IPs.
  - Real-time Telegram alerts for critical security incidents.
  - Exportable CSV logs for attack and attacker data.

- **Admin Dashboard**:
  - View and manage blacklisted and trusted IPs.
  - Check IP reputation via VirusTotal.
  - Manage user accounts (add, edit, delete).
  - Monitor system statistics (active IPs, request rates, etc.).
  - Configure WAF settings dynamically.

## Requirements

- Python 3.8+
- Flask
- Flask-Login
- Flask-Bcrypt
- Requests
- SQLite3
- Pickle (for ML model loading, optional)
- A VirusTotal API key (for IP reputation checks)
- A Telegram Bot Token and Chat ID (for alerts)

Install dependencies using:
```bash
pip install flask flask-login flask-bcrypt requests
```

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/your-waf-project.git
   cd your-waf-project
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set Up Configuration**:
   - Replace the default `app.secret_key` with a secure, fixed key in production.
   - Obtain a VirusTotal API key and update `VT_API_KEY` in the code.
   - Configure Telegram alerts by setting `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`.

4. **Initialize the Database**:
   The application automatically creates a SQLite database (`users.db`) with a default admin user (username: `admin`, password: `admin123`). Change the default password immediately after setup.

5. **Run the Application**:
   ```bash
   python app.py
   ```
   The WAF will run on `http://0.0.0.0:80` by default.

## Usage

1. **Access the Dashboard**:
   - Navigate to `http://<your-server-ip>/login`.
   - Log in with the admin credentials.
   - Access the dashboard to monitor and manage security settings.

2. **Manage Security**:
   - Use the **Blacklist** page to view and manage blocked IPs.
   - Use the **Trusted IPs** page to add or remove trusted IPs.
   - Check IP reputation on the **Check IP** page.
   - Configure WAF settings (rate limits, payload sizes, etc.) via the **Settings** page.
   - Manage users (add, edit, delete) via the **Manage Users** page (admin-only).

3. **Monitor Logs**:
   - View real-time security logs, attack logs, and attacker logs.
   - Export logs as CSV files for analysis.

4. **Receive Alerts**:
   - Configure Telegram to receive instant alerts for blocked IPs and detected attacks.

## Security Notes

- **Secure the Admin Account**: Change the default admin password immediately.
- **Production Secret Key**: Replace `os.urandom(24)` with a fixed, secure secret key.
- **Firewall Permissions**: Ensure the application has sufficient permissions to modify OS firewall rules.
- **ML Model**: The optional ML model (`waf_model.sav`) must be trained and provided separately for advanced payload detection.
- **API Keys**: Keep VirusTotal and Telegram API keys confidential and avoid hardcoding in production.

## Project Structure

```plaintext
your-waf-project/
├── app.py                # Main Flask application
├── templates/            # HTML templates for the frontend
│   ├── login.html
│   ├── dashboard.html
│   ├── blacklist.html
│   ├── trusted.html
│   ├── check_ip.html
│   ├── settings.html
│   ├── manage_users.html
├── users.db              # SQLite database for user management
├── security.log          # Security event logs
├── attack_log.csv        # Attack attempt logs
├── attacker_log.csv      # Blocked IP logs
├── blacklist.txt         # Blacklisted IPs
├── trusted_ips.txt       # Trusted IPs
├── waf_model.sav         # Optional ML model for payload detection
├── requirements.txt      # Python dependencies
└── README.md             # This file
```

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Make your changes and commit (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a Pull Request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Flask](https://flask.palletsprojects.com/).
- Uses [VirusTotal API](https://www.virustotal.com/) for IP reputation checks.
- Integrates with [Telegram Bot API](https://core.telegram.org/bots) for alerts.
- Inspired by modern WAF solutions and best practices in web security.

---

**Note**: This project is intended for educational and development purposes. For production use, ensure proper security audits, configuration, and testing.