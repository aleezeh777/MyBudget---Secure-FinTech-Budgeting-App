# MyBudget---Secure-FinTech-Budgeting-App

A simple, secure personal budgeting application built in Python (Flask).

This project was developed as a mini-application for a university cybersecurity course. The primary objective was to build a functional FinTech-related app while implementing key security-aware features from the ground up.

Key Features

🛡️ Security Features

Secure Password Hashing: User passwords are never stored in plain text. They are hashed using bcrypt (Test #7).

Input Validation: All user-submitted forms are validated using Flask-WTF to prevent invalid data and test for common vulnerabilities (Test #2, #10, #12, #15, #20).

Authenticated Session Management: User sessions are securely managed with Flask-Login. Critical pages are protected, and users are redirected if not authorized (Test #4, #5, #6).

Data Encryption: Sensitive expense notes are encrypted at rest using the cryptography (Fernet) library. They are only decrypted when a user views their own dashboard (Test #18).

Secure File Uploads: Validates file extensions (.png, .jpg, .pdf) and sanitizes filenames to prevent malicious uploads (Test #8).

Custom Secure Error Handling: The app serves generic 404 and 500 error pages in production mode to prevent leaking stack traces or sensitive information (Test #9, #17).

Detailed Audit Logging: All significant user actions (adding expenses, updating profile) are recorded in an AuditLog table for traceability.

XSS Protection: All user-supplied data rendered in templates is auto-escaped by the Jinja2 engine, preventing Cross-Site Scripting (XSS) attacks (Test #3).

CSRF Protection: Flask-WTF provides built-in Cross-Site Request Forgery (CSRF) protection on all forms.

💰 Core Application Features

User registration and login system.

Dashboard to add new expenses (amount, category, notes).

View all personal expenses in a sortable table.

Secure profile update page for changing username and email.

Optional receipt file upload for each expense.

🛠️ Technology Stack

Backend: Flask

Database: SQLite (managed with Flask-SQLAlchemy)

Security & Auth: Flask-Login, Flask-Bcrypt, cryptography

Forms & Validation: Flask-WTF (WTForms)

Frontend: Standard HTML, CSS, and Jinja2 templating.

🚀 How to Run

Clone the repository:

git clone [https://github.com/YourUsername/secure-fintech-budget-app.git](https://github.com/YourUsername/secure-fintech-budget-app.git)
cd secure-fintech-budget-app


Create and activate a virtual environment:

# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate


Install the required packages:

pip install -r requirements.txt


Run the application:

python app.py


On the first run, this will automatically create:

site.db (the SQLite database file)

secret.key (the encryption key)

uploads/ (the folder for receipts, created on first upload)

Open the app in your browser at http://127.0.0.1:5000

🧪 Security Testing

A key component of this project was performing manual cybersecurity testing. The application was subjected to a documented 20-point manual test plan to verify its security posture.

Test categories included:

Input Validation (SQL Injection, XSS, Length, Type)

Authentication (Weak Passwords, Duplicate Users, Password Matching)

Session Management (Unauthorized Access, Logout, Expiry)

Data Confidentiality (Password Hashing, Data Encryption)

Secure File Handling (Invalid File Type Rejection)

Error Handling (Information Leakage, Crash Handling)

Access Control (Data Modification Attempts)

The application successfully passed all relevant tests, demonstrating a robust design against common web vulnerabilities.
