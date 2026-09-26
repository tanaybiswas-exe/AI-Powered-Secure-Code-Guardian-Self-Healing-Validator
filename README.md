# 🛡️ AI Secure Code Guardian & Explainer

An advanced, full-stack code auditing, security scanning, and self-healing web platform designed to detect vulnerabilities, automatically fix broken code, and securely log audit histories on a cloud database.

🌐 **Live Demo:** [https://ai-powered-secure-code-guardian-self.onrender.com](https://ai-powered-secure-code-guardian-self.onrender.com)  
*(Note: Hosted on Render's free tier. The first request may take 30–50 seconds for a "cold start" if the server is inactive.)*

---

## ✨ Key Features

- **Multi-Language Security Auditing:** Instantly scans and detects syntax errors, vulnerabilities (such as dangerous `eval` usage and SQL injection risks), and custom rule violations.
- **Smart Self-Healing Engine:** Automatically patches vulnerable code structures and generates clear, bullet-pointed explanations of fixes applied.
- **Live Sandbox Execution:** Safely executes Python code in an isolated environment to provide real-time runtime outputs.
- **Cloud Database Persistence:** Integrated with **Neon PostgreSQL** serverless database to maintain a permanent, reliable audit history log.
- **Modern & Responsive UI:** Built using FastAPI, Bootstrap 5, and Markdown parsing for a clean user experience.

---

## 🛠️ Tech Stack

- **Backend:** Python, FastAPI, Uvicorn, Pydantic, Python AST, Subprocess
- **Database:** Neon PostgreSQL (`psycopg2`)
- **Frontend:** HTML5, CSS3, Bootstrap 5, JavaScript, Marked.js
- **Deployment:** Render (Web Service)

---

## 🚀 Local Installation & Setup

If you want to run this project locally on your machine, follow these steps:

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/tanaybiswas-exe/AI-Powered-Secure-Code-Guardian-Self-Healing-Validator.git](https://github.com/tanaybiswas-exe/AI-Powered-Secure-Code-Guardian-Self-Healing-Validator.git)
   cd AI-Powered-Secure-Code-Guardian-Self-Healing-Validator
