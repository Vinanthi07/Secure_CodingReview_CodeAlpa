# Secure_CodingReview
Flask Security Demo — Vulnerable vs Secure
A minimal Flask app pair for cybersecurity interns to explore and fix 5 common web vulnerabilities.
Files
FilePurposevulnerable_app.pyIntentionally insecure app (DO NOT deploy)secure_app.pyHardened version with all fixes appliedrequirements.txtPython dependenciessecurity_review_report.mdFull vulnerability analysis & Bandit results
Quick Start
bashpip install -r requirements.txt

# Run the vulnerable app (local only!)
python vulnerable_app.py

# Run the secure app
FLASK_SECRET_KEY="your-random-key" ADMIN_PASSWORD="StrongPass!99" python secure_app.py
Both apps run at http://127.0.0.1:5000.
Default login for vulnerable_app.py: admin / admin123
The 5 Vulnerabilities
#TypeWhere to look1SQL Injection/login and /search routes2XSSSearch results template (| safe)3Hardcoded CredentialsModule-level constants4Weak Password ValidationLogin POST handler5Command Injection/ping route (shell=True)
Try These Exploits (on vulnerable_app.py only)
# SQL Injection login bypass
Username: ' OR '1'='1' --
Password: anything

# XSS in search
http://127.0.0.1:5000/search?q=<script>alert('XSS')</script>

# Command injection in ping
Host: 127.0.0.1; whoami
Learning Objectives

Understand how each attack works at the code level
Compare vulnerable vs secure code side-by-side
Run bandit -r vulnerable_app.py and interpret the output
Read security_review_report.md for remediation guidance


Warning: vulnerable_app.py is for local educational use only. Never expose it on a network.
