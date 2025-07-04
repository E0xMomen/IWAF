# Web Application Firewall (WAF) Security Server

## Overview

This project is a robust Web Application Firewall (WAF) implemented using Flask, designed to protect web applications from common security threats such as SQL injection, cross-site scripting (XSS), and command injection. It includes advanced security features like IP blacklisting, rate limiting, VirusTotal integration for IP reputation checks, and real-time Telegram alerts for detected attacks. The system also provides a user-friendly interface for administrators to manage users, trusted IPs, blacklists, and logs, with role-based access control.

## Features

- **Security Protections**:
  - Detection and prevention of SQL injection, XSS, and command injection attacks using regex patterns and an optional machine learning model.
  - IP reputation checking via VirusTotal API.
  - Rate limiting and concurrent request monitoring to prevent abuse.
  - Request timeout and payload size restrictions.
- **User Authentication**:
  - Secure user management with Flask-Login and Bcrypt for password hashing.
  - Role-based access control (admin and user roles).
- **Logging and Monitoring**:
  - Detailed logging of security events, blocked IPs, and attack attempts.
  - Exportable CSV logs for attacks and blocked IPs.
  - Real-time alerts via Telegram for security incidents.
- **IP Management**:
  - Blacklist and trusted IP management with automatic firewall integration (iptables, Windows Firewall, or macOS pf).
  - Manual and automated IP blocking/unblocking.
- **Administrative Interface**:
  - Web-based dashboard for monitoring and managing security settings, logs, and user accounts.
  - Secure endpoints restricted to trusted IPs and admin users.
- **Performance Optimization**:
  - Thread-safe operations using locks for concurrent access.
  - Stream limiting to detect and block slow requests.

## Requirements

- Python 3.8+
- Flask
- Flask-Login
- Flask-Bcrypt
- SQLite3
- Requests
- Pickle (for ML model loading, optional)
- A VirusTotal API key
- A Telegram Bot Token and Chat ID for alerts
- System-level firewall support (iptables for Linux, netsh for Windows, or pf for macOS)

## Installation

1. **Clone the Repository**:

   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Install Dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment**:

   - Replace the default `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` in the `Config` class with your own Telegram bot credentials.
   - Replace the `VT_API_KEY` with your VirusTotal API key.
   - Ensure the `waf_model.sav` file (if using ML-based detection) is placed in the project root.
   - Set a secure `app.secret_key` for production environments.

4. **Initialize the Database**: The application automatically creates a SQLite database (`users.db`) with a default admin user (username: `admin`, password: `admin123`) on first run if no admin exists.

5. **Run the Application**:

   ```bash
   python app.py
   ```

   The server will run on `http://0.0.0.0:80` by default.

## Usage

- **Access the Dashboard**:
  - Navigate to `http://<server-ip>/` and log in with valid credentials.
  - Only trusted IPs (default: `127.0.0.1`, `::1`) can access the dashboard.
- **Manage Users**:
  - Admins can add, edit, or delete users via the `/manage-users` route.
- **Monitor Security**:
  - View blacklisted IPs, trusted IPs, and attack logs via dedicated pages (`/blacklist-page`, `/trusted-page`, `/attack-log`).
  - Check IP reputation using the `/check-ip-page` route.
- **Export Logs**:
  - Download attack and attacker logs as CSV files via `/export-attack-log` and `/export-attacker-log`.
- **Configure Settings**:
  - Update security parameters like rate limits and timeout thresholds via the `/settings` page.

## Security Considerations

- **Secret Key**: Replace `app.secret_key = os.urandom(24)` with a fixed, secure key in production.
- **Firewall Permissions**: Ensure the application has sufficient permissions to modify firewall rules (sudo for Linux/macOS or admin rights for Windows).
- **Trusted IPs**: Add trusted IPs carefully to avoid unauthorized access.
- **Telegram Alerts**: Securely store Telegram bot credentials and restrict access to the chat ID.
- **ML Model**: If using the optional ML model (`waf_model.sav`), ensure it is trained and validated for your use case.

## File Structure

- `app.py`: Main application script containing the Flask server and WAF logic.
- `users.db`: SQLite database for user management.
- `blacklist.txt`: File storing blacklisted IPs.
- `trusted_ips.txt`: File storing trusted IPs.
- `security.log`: General security event log.
- `attack_log.csv`: Detailed log of detected attacks.
- `attacker_log.csv`: Log of blocked IPs with reasons.
- `templates/`: Directory containing HTML templates for the web interface.
- `waf_model.sav`: Optional machine learning model for attack detection.

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact

For issues or inquiries, please open an issue on the repository or contact the project maintainer at \[momenameer2003@gmail.com\].