# PromptGuard AI

### Privacy & Security Gateway for Generative AI Prompts

PromptGuard is a Flask-based security gateway that analyzes prompts before they are sent to a Generative AI model. It detects potentially sensitive information and common prompt-injection patterns, calculates privacy and security risks, and determines whether a prompt should be **ALLOWED, SANITIZED, or BLOCKED**.

The project demonstrates how a security layer can be placed between users and LLM providers to reduce unnecessary exposure of sensitive information and identify common prompt-based attacks.

## Key Features

- **Sensitive Data Detection:** Regex-based detection of email addresses, phone numbers, credit-card-like numbers, bank-account-like numbers, passwords, API keys, JWT-like tokens, Aadhaar-like numbers, and IP addresses.
- **Data Masking:** Replaces detected sensitive values with placeholders before approved prompts proceed through the processing pipeline.
- **Prompt Injection Detection:** Detects common instruction overrides, system-prompt extraction attempts, safety bypasses, developer-instruction manipulation, role manipulation, jailbreak patterns, and certain instructions involving untrusted content.
- **Risk Analysis:** Calculates privacy, security, and overall risk scores on a 0–100 scale.
- **Security Decision Engine:** Applies configurable rules to ALLOW, SANITIZE, or BLOCK prompts.
- **LLM Integration:** Includes provider integrations for local Ollama inference and optional Groq API-based generation.
- **Token and Context Analysis:** Estimates prompt token usage and context requirements.
- **Web Dashboard:** Provides a Flask-based interface for prompt analysis and security results.
- **Scan History:** Uses SQLite for local scan-history storage.
- **Automated Tests:** Uses pytest to test detection, masking, security decisions, and API behavior.

## Architecture

```text
                 User Prompt
                      |
                      v
             Sensitive Data Detector
                      |
                      v
              Injection Detector
                      |
                      v
                 Risk Analyzer
                      |
                      v
                Decision Engine
                      |
           +----------+----------+
           |          |          |
           v          v          v
         ALLOW     SANITIZE     BLOCK
           |          |
           |     Mask sensitive
           |        values
           |          |
           +----------+
                |
                v
          LLM Provider Router
                |
          +-----+-----+
          |           |
          v           v
       Ollama       Groq*
          |
          v
      AI Response

* Groq requires its own API credentials and configuration.
```

## How the Security Decisions Work

PromptGuard uses predefined detection patterns, risk scores, and decision rules.

| Condition | Decision |
|---|---|
| No detected privacy or injection risk | ALLOW |
| A password, API key, credential, or JWT is detected | BLOCK |
| Security risk score is 30 or higher | BLOCK |
| Other detected privacy risks require protection | SANITIZE |

The decision engine prioritizes blocking detected credentials and high security-risk scores. Other privacy risks are handled through sanitization.

The risk analyzer assigns weights to detected categories and caps the privacy and security scores at 100. The overall score is the maximum of those two scores.

These are rule-based decisions, not guarantees that every malicious prompt will be detected.

## Sensitive Data Detection

The detector uses Python regular expressions to identify supported data patterns.

Examples include:

- Email addresses
- Indian mobile-number patterns
- Credit-card-like digit sequences
- Password assignments
- Selected API-key formats
- JWT-like tokens
- IPv4 addresses
- Aadhaar-like number patterns
- Contextual bank-account-number patterns

Regex matching has limitations. A matching pattern does not prove that a value is genuine, and an unfamiliar or disguised secret may not be detected.

## Prompt Injection Detection

The injection detector recognizes common patterns in categories such as:

- Instruction Override
- System Prompt Extraction
- Safety Bypass
- Developer Instruction Manipulation
- Role Manipulation
- Jailbreak
- Prompt Injection via Untrusted Content

The detector uses predefined regex patterns rather than a semantic AI classifier. It can miss novel attacks and may occasionally flag harmless text. Detection results should therefore be treated as security indicators, not a complete guarantee of safety.

## Risk Analysis

PromptGuard calculates:

- **Privacy score:** Based on detected sensitive-data categories and their configured weights.
- **Security score:** Based on detected prompt-injection categories and their configured weights.
- **Overall score:** The higher of the privacy and security scores.

Scores are capped at 100. Severity labels are assigned using configured rules.

The scoring system is a prototype policy model. Its weights have not been established as calibrated probabilities of an attack.

## Technology Stack

- Python
- Flask
- Regular Expressions
- HTML, CSS and Jinja2
- SQLite
- Ollama and Llama 3.2
- Optional Groq integration
- pytest
- Git and GitHub

## Project Structure

```text
promptguard/
├── backend/
│   ├── app.py
│   ├── database.py
│   ├── decision_engine.py
│   ├── detector.py
│   ├── injection_detector.py
│   ├── llm_router.py
│   ├── masker.py
│   ├── prompt_optimizer.py
│   ├── risk_analyzer.py
│   ├── suggestions.py
│   ├── token_analyzer.py
│   └── providers/
├── frontend/
│   ├── templates/
│   └── static/
├── evaluation/
├── tests/
├── docs/
│   └── screenshots/
├── .env.example
├── .gitignore
├── Dockerfile
├── requirements.txt
└── README.md
```

## Installation

### 1. Clone the repository

```powershell
git clone https://github.com/sanju-2005/promptguard.git
cd promptguard
```

### 2. Create and activate a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Configure environment variables

Use `.env.example` as a reference for your local `.env` configuration.

Keep API keys and other secrets private. Never commit your `.env` file or expose credentials in screenshots.

### 5. Configure Ollama

Install Ollama separately and make sure the desired model is available.

```powershell
ollama pull llama3.2
ollama list
```

### 6. Start PromptGuard

```powershell
python -m backend.app
```

Open the local dashboard at:

http://127.0.0.1:5000

Actual generation depends on the configured provider, its availability, and the required credentials.

## REST API

The project includes the following documented endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/analyze` | Analyze a prompt for sensitive data and security risks |
| POST | `/api/generate` | Process a generation request through the configured provider |
| GET | `/health` | Check application health |

Request formats, authentication requirements, and response fields depend on the actual implementation in `backend/app.py`. Consult the route definitions before integrating these endpoints into another application.

## Screenshots

### 1. Safe Prompt — ALLOW

![PromptGuard Allow](docs/screenshots/allow-ollama.png)

### 2. Sensitive Data — SANITIZE

![PromptGuard Sanitize](docs/screenshots/sanitize.png)

### 3. Prompt Injection — BLOCK

![PromptGuard Block](docs/screenshots/block-injection.png)

These screenshots illustrate the three intended security outcomes. Actual results depend on the submitted prompt and the configured detection and decision rules.

## Testing

Run the test suite from the project root:

```powershell
python -m pytest -q
```

The latest recorded result during development was **40 passed**. Rerun the tests after making changes to confirm the current result.

The tests cover areas including:

- Sensitive-data detection
- Data masking
- Prompt-injection detection
- Risk analysis
- Security decisions
- API behavior
- Input validation

## Evaluation

The project includes an evaluation script in `evaluation/evaluation.py` with a small, hand-written set of cases and metrics for detection and decision agreement.

These cases are useful for checking expected behavior during development. They are not a representative security benchmark, and high scores on this small dataset do not establish real-world detection accuracy.

More extensive evaluation would require larger datasets, diverse attack variations, false-positive analysis, and independent security testing.

## Security Limitations

PromptGuard is a learning and prototype project, not a replacement for production security controls.

Current limitations include:

- Regex patterns cannot identify every possible secret or prompt injection.
- Pattern-based detection may produce false positives and false negatives.
- Risk weights are predefined rules, not calibrated probabilities.
- Detection does not guarantee that a prompt is safe.
- Provider configuration, authentication, authorization, logging, and deployment security require separate verification.

Production use would require more extensive testing, robust authentication and authorization, secure secret management, monitoring, policy hardening, and provider-specific security controls.

## Future Improvements

- Broader sensitive-data detection and validation
- More comprehensive prompt-injection testing
- Semantic detection for less obvious attacks
- Configurable security policies
- Larger and more representative evaluation datasets
- Additional authentication and deployment controls
- More extensive integration and security tests

## What I Learned

Through PromptGuard, I worked on:

- Python and Flask backend development
- REST API integration
- Regex-based sensitive-data detection
- Data masking
- Prompt-injection detection
- Risk scoring and security decision logic
- LLM provider routing
- Local LLM inference
- SQLite and automated testing
- Git and GitHub workflows

The key architectural lesson was how separate detection, analysis, decision, and routing components can work together as a security pipeline.

## Author

**Sanjana**  
B.Tech CSE — AI Specialization

- GitHub: https://github.com/sanju-2005
- Project repository: https://github.com/sanju-2005/promptguard
