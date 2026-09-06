mptGuard AI 🛡️

### Privacy & Security Gateway for Generative AI Prompts

PromptGuard AI is a security gateway that checks a user's prompt before
it is sent to a Generative AI system.

The main idea is simple:

> Don't directly send every user prompt to an AI model. Check it first.

PromptGuard checks the prompt for sensitive information and common prompt
injection attempts, calculates the risk, and decides whether the prompt
should be allowed, sanitized, or blocked.

---

## Why I Built This

While working with Generative AI applications, user prompts can sometimes
contain sensitive information such as passwords, API keys, phone numbers,
or other personal data.

Prompts can also contain malicious instructions such as:

- Ignore previous instructions
- Reveal the system prompt
- Bypass safety restrictions
- Act as an unrestricted AI

I wanted to build a project that acts as a security layer before the
prompt reaches an AI system.

---

## What PromptGuard Does

The application follows this flow:

```text
User Prompt
     ↓
Sensitive Data Detection
     ↓
Prompt Injection Detection
     ↓
Risk Analysis
     ↓
Security Decision
     ↓
ALLOW / SANITIZE / BLOCK
     ↓
Safe Prompt
Example

Input:

My email is test@example.com

PromptGuard detects the email and creates:

My email is [EMAIL_MASKED]

The system then gives a security decision based on the calculated risk.

Features
Sensitive Data Detection

Currently detects:

Email addresses
Phone numbers
Credit card numbers
Bank account numbers
Passwords
API keys
JWT tokens
Aadhaar numbers
IP addresses
Prompt Injection Detection

Detects common injection patterns such as:

Instruction Override
System Prompt Extraction
Safety Bypass
Developer Instruction Manipulation
Role Manipulation
Jailbreak attempts
Risk Analysis

The application calculates:

Privacy Risk
Security Risk
Overall Risk

Scores are calculated from 0 - 100.

Security Decision

Based on the risk and detected information, PromptGuard can return:

🟢 ALLOW
🟡 SANITIZE
🔴 BLOCK

For example:

No significant risk
        ↓
      ALLOW
Personal information detected
        ↓
     SANITIZE
        ↓
Sensitive data is masked
Password / API key / critical attack
        ↓
      BLOCK
Web Dashboard

The project also has a simple web interface where a user can enter a
prompt and see the complete security analysis.

The dashboard shows:

Privacy score
Security score
Overall score
Detected sensitive information
Prompt injection status
Security decision
Masked prompt
Recommendations

Screenshots will be added to the docs folder.

Project Structure
promptguard/
│
├── backend/
│   ├── __init__.py
│   ├── app.py
│   ├── detector.py
│   ├── masker.py
│   ├── risk_analyzer.py
│   ├── injection_detector.py
│   ├── suggestions.py
│   ├── decision_engine.py
│   └── database.py
│
├── frontend/
│   ├── templates/
│   │   ├── index.html
│   │   └── history.html
│   │
│   └── static/
│       └── style.css
│
├── tests/
│   └── test_promptguard.py
│
├── docs/
│
├── data/
│
├── .gitignore
├── .env.example
├── requirements.txt
└── README.md
What Each Main File Does
File	Purpose
app.py	Flask application and API routes
detector.py	Detects sensitive information
masker.py	Masks detected sensitive data
risk_analyzer.py	Calculates privacy and security risk
injection_detector.py	Detects prompt injection patterns
decision_engine.py	Decides ALLOW, SANITIZE or BLOCK
suggestions.py	Generates security recommendations
database.py	Stores scan history in SQLite
test_promptguard.py	Automated tests
Technology Used
Python - Main programming language
Flask - Backend and REST API
SQLite - Stores scan history
HTML/CSS - Frontend
Jinja2 - HTML templates
Regular Expressions - Pattern-based detection
pytest - Testing
Git & GitHub - Version control
How to Run
1. Clone the repository
git clone https://github.com/sanju-2005/promptguard.git
cd promptguard
2. Create a virtual environment
python -m venv .venv
3. Activate it

For Windows PowerShell:

.venv\Scripts\Activate.ps1
4. Install dependencies
pip install -r requirements.txt
5. Start the application
python -m backend.app

Then open:

http://127.0.0.1:5000
REST API

PromptGuard also provides an API for analyzing prompts.

Endpoint
POST /api/analyze
Example Request
{
    "prompt": "My email is test@example.com"
}
Example Result
{
    "decision": {
        "action": "SANITIZE"
    }
}

The complete response also contains:

Original prompt
Masked prompt
Detected data
Injection analysis
Risk scores
Security decision
Suggestions
Health Check

The application has a simple health endpoint:

GET /health

Example response:

{
    "status": "healthy",
    "service": "PromptGuard AI"
}
Scan History

PromptGuard stores previous scans in a local SQLite database.

The history page can be opened at:

http://127.0.0.1:5000/history

It shows information such as:

Scan ID
Time of scan
Privacy score
Security score
Overall risk
Prompt injection status
Original prompt
Masked prompt

The database file is excluded from Git using .gitignore.

Testing

The project uses pytest.

Run:

python -m pytest -v

The tests cover different parts of the application including:

Sensitive data detection
Data masking
Prompt injection detection
Risk calculation
Security decisions
API endpoints
Health endpoint
Input validation
Scan history
Security Decision Logic

The current decision logic is based on predefined security rules.

Critical sensitive information
            ↓
          BLOCK
Critical prompt injection
            ↓
          BLOCK
No detected risk
            ↓
          ALLOW
Moderate risk
            ↓
        SANITIZE
High risk
            ↓
          BLOCK

Critical information includes things such as passwords, API keys and
Aadhaar numbers.

Current Limitations

This is currently a project/prototype implementation.

Some limitations are:

Detection is mainly regex based.
New or disguised attack patterns may not always be detected.
Prompt injection detection currently focuses on known patterns.
SQLite is being used for local development.
Authentication is not implemented yet.
The application is not yet connected to an external LLM provider.
Production-level security controls are not implemented.
Future Improvements

Some improvements I would like to add later:

ML-based sensitive data detection
Semantic prompt injection detection
LLM-based security classification
PostgreSQL
Authentication and authorization
API rate limiting
Docker deployment
Better security monitoring
Configurable security policies
Integration with different LLM providers
What I Learned From This Project

Through this project I worked with:

Python backend development
Flask
REST APIs
Regular expressions
Data masking
Prompt injection concepts
Risk scoring
Security decision logic
SQLite
HTML/CSS
Automated testing with pytest
Git and GitHub
Basic application architecture

The main thing I learned is how different small components can be
combined to create a complete security pipeline instead of writing
everything in one file.

Project Status
Component	Status
Sensitive Data Detection	✅ Done
Data Masking	✅ Done
Prompt Injection Detection	✅ Done
Risk Analysis	✅ Done
Security Decision Engine	✅ Done
Security Suggestions	✅ Done
SQLite History	✅ Done
REST API	✅ Done
Health Check	✅ Done
Input Validation	✅ Done
Automated Tests	🚧 Final Verification
Screenshots	🚧 To Add
LLM Integration	🔮 Future
Author

Sanjana

B.Tech AI Student

GitHub: https://github.com/sanju-2005/promptguard


### Do this now

1. Open `README.md`
2. **Ctrl + A**
3. Delete everything
4. Copy the README above **starting from `# PromptGuard AI 🛡️`**
5. Paste it
6. **Ctrl + S**

**Do not copy the ```markdown at the beginning or the ``` at the very end** — those are only there to display the README correctly here.

After saving, tell me **`done`**. Then we'll immediately do the **final test verification + Git backup**, without unnecessarily adding more features.

# PromptGuard AI 🛡️

### Privacy & Security Gateway for Generative AI Prompts

PromptGuard AI is a security gateway that checks a user's prompt before

it is sent to a Generative AI system.

The main idea is simple:

> Don't directly send every user prompt to an AI model. Check it first.

PromptGuard checks the prompt for sensitive information and common prompt

injection attempts, calculates the risk, and decides whether the prompt

should be allowed, sanitized, or blocked.

---

## Why I Built This

While working with Generative AI applications, user prompts can sometimes

contain sensitive information such as passwords, API keys, phone numbers,

or other personal data.

Prompts can also contain malicious instructions such as:

- Ignore previous instructions

- Reveal the system prompt

- Bypass safety restrictions

- Act as an unrestricted AI

I wanted to build a project that acts as a security layer before the

prompt reaches an AI system.

---

## What PromptGuard Does

The application follows this flow:

```text

User Prompt

     ↓

Sensitive Data Detection

     ↓

Prompt Injection Detection

     ↓

Risk Analysis

     ↓

Security Decision

     ↓

ALLOW / SANITIZE / BLOCK

     ↓

Safe Prompt

Example

Input:

My email is test@example.com

PromptGuard detects the email and creates:

My email is [EMAIL_MASKED]

The system then gives a security decision based on the calculated risk.

Features

Sensitive Data Detection

Currently detects:

Email addresses

Phone numbers

Credit card numbers

Bank account numbers

Passwords

API keys

JWT tokens

Aadhaar numbers

IP addresses

Prompt Injection Detection

Detects common injection patterns such as:

Instruction Override

System Prompt Extraction

Safety Bypass

Developer Instruction Manipulation

Role Manipulation

Jailbreak attempts

Risk Analysis

The application calculates:

Privacy Risk

Security Risk

Overall Risk

Scores are calculated from 0 - 100.

Security Decision

Based on the risk and detected information, PromptGuard can return:

🟢 ALLOW

🟡 SANITIZE

🔴 BLOCK

For example:

No significant risk

        ↓

      ALLOW

Personal information detected

        ↓

     SANITIZE

        ↓

Sensitive data is masked

Password / API key / critical attack

        ↓

      BLOCK

Web Dashboard

The project also has a simple web interface where a user can enter a

prompt and see the complete security analysis.

The dashboard shows:

Privacy score

Security score

Overall score

Detected sensitive information

Prompt injection status

Security decision

Masked prompt

Recommendations

Screenshots will be added to the docs folder.

Project Structure

promptguard/

│

├── backend/

│   ├── __init__.py

│   ├── app.py

│   ├── detector.py

│   ├── masker.py

│   ├── risk_analyzer.py

│   ├── injection_detector.py

│   ├── suggestions.py

│   ├── decision_engine.py

│   └── database.py

│

├── frontend/

│   ├── templates/

│   │   ├── index.html

│   │   └── history.html

│   │

│   └── static/

│       └── style.css

│

├── tests/

│   └── test_promptguard.py

│

├── docs/

│

├── data/

│

├── .gitignore

├── .env.example

├── requirements.txt

└── README.md

What Each Main File Does

File    Purpose

app.py  Flask application and API routes

detector.py Detects sensitive information

masker.py   Masks detected sensitive data

risk_analyzer.py    Calculates privacy and security risk

injection_detector.py   Detects prompt injection patterns

decision_engine.py  Decides ALLOW, SANITIZE or BLOCK

suggestions.py  Generates security recommendations

database.py Stores scan history in SQLite

test_promptguard.py Automated tests

Technology Used

Python - Main programming language

Flask - Backend and REST API

SQLite - Stores scan history

HTML/CSS - Frontend

Jinja2 - HTML templates

Regular Expressions - Pattern-based detection

pytest - Testing

Git & GitHub - Version control

How to Run

1. Clone the repository

git clone https://github.com/sanju-2005/promptguard.git

cd promptguard

2. Create a virtual environment

python -m venv .venv

3. Activate it

For Windows PowerShell:

.venv\Scripts\Activate.ps1

4. Install dependencies

pip install -r requirements.txt

5. Start the application

python -m backend.app

Then open:

http://127.0.0.1:5000

REST API

PromptGuard also provides an API for analyzing prompts.

Endpoint

POST /api/analyze

Example Request

{

    "prompt": "My email is test@example.com"

}

Example Result

{

    "decision": {

        "action": "SANITIZE"

    }

}

The complete response also contains:

Original prompt

Masked prompt

Detected data

Injection analysis

Risk scores

Security decision

Suggestions

Health Check

The application has a simple health endpoint:

GET /health

Example response:

{

    "status": "healthy",

    "service": "PromptGuard AI"

}

Scan History

PromptGuard stores previous scans in a local SQLite database.

The history page can be opened at:

http://127.0.0.1:5000/history

It shows information such as:

Scan ID

Time of scan

Privacy score

Security score

Overall risk

Prompt injection status

Original prompt

Masked prompt

The database file is excluded from Git using .gitignore.

Testing

The project uses pytest.

Run:

python -m pytest -v

The tests cover different parts of the application including:

Sensitive data detection

Data masking

Prompt injection detection

Risk calculation

Security decisions

API endpoints

Health endpoint

Input validation

Scan history

Security Decision Logic

The current decision logic is based on predefined security rules.

Critical sensitive information

            ↓

          BLOCK

Critical prompt injection

            ↓

          BLOCK

No detected risk

            ↓

          ALLOW

Moderate risk

            ↓

        SANITIZE

High risk

            ↓

          BLOCK

Critical information includes things such as passwords, API keys and

Aadhaar numbers.

Current Limitations

This is currently a project/prototype implementation.

Some limitations are:

Detection is mainly regex based.

New or disguised attack patterns may not always be detected.

Prompt injection detection currently focuses on known patterns.

SQLite is being used for local development.

Authentication is not implemented yet.

The application is not yet connected to an external LLM provider.

Production-level security controls are not implemented.

Future Improvements

Some improvements I would like to add later:

ML-based sensitive data detection

Semantic prompt injection detection

LLM-based security classification

PostgreSQL

Authentication and authorization

API rate limiting

Docker deployment

Better security monitoring

Configurable security policies

Integration with different LLM providers

What I Learned From This Project

Through this project I worked with:

Python backend development

Flask

REST APIs

Regular expressions

Data masking

Prompt injection concepts

Risk scoring

Security decision logic

SQLite

HTML/CSS

Automated testing with pytest

Git and GitHub

Basic application architecture

The main thing I learned is how different small components can be

combined to create a complete security pipeline instead of writing

everything in one file.

Project Status

Component   Status

Sensitive Data Detection    ✅ Done

Data Masking    ✅ Done

Prompt Injection Detection  ✅ Done

Risk Analysis   ✅ Done

Security Decision Engine    ✅ Done

Security Suggestions    ✅ Done

SQLite History  ✅ Done

REST API    ✅ Done

Health Check    ✅ Done

Input Validation    ✅ Done

Automated Tests 🚧 Final Verification

Screenshots 🚧 To Add

LLM Integration 🔮 Future is this okay

Yes, the content is okay, but the version you pasted is NOT ready to paste into README.md yet.

The reason is formatting. Chat has converted your Markdown symbols into escaped text. For example:

**# PromptGuard AI 🛡️** ❌
# PromptGuard AI 🛡️ ✅
\> ❌
> ✅
\``text` ❌
```text ✅
\- item ❌
- item ✅

Also, your pasted version is missing several ## headings and code-block closures, so GitHub won't render it nicely.

The actual content is good

I would keep the content because it:

sounds like a student project
explains why you built it
explains the architecture
documents your files
documents the API
mentions testing
honestly states limitations
doesn't claim that you built an LLM integration when you haven't
is impressive without sounding like an enterprise product
One thing to change

At the very bottom, you currently have:

LLM Integration 🔮 Future

That's fine.

But don't add 50 tests passed yet. We need to actually run:

python -m pytest -v

and see the final result first.

So the answer is:

Content: ✅ YES

Current formatting: ❌ NO

Ready for GitHub after proper Markdown formatting: ✅ YES

If you want, 
I can give you the entire README again as one clean copy-paste block with absolutely no formatting artifacts, so you can replace your README.md directly.

# PromptGuard AI 🛡️

### Privacy & Security Gateway for Generative AI Prompts

PromptGuard AI is a security gateway that checks a user's prompt before

it is sent to a Generative AI system.

The main idea is simple:

> Don't directly send every user prompt to an AI model. Check it first.

PromptGuard checks the prompt for sensitive information and common prompt

injection attempts, calculates the risk, and decides whether the prompt

should be allowed, sanitized, or blocked.

---

## Why I Built This

While working with Generative AI applications, user prompts can sometimes

contain sensitive information such as passwords, API keys, phone numbers,

or other personal data.

Prompts can also contain malicious instructions such as:

- Ignore previous instructions

- Reveal the system prompt

- Bypass safety restrictions

- Act as an unrestricted AI

I wanted to build a project that acts as a security layer before the

prompt reaches an AI system.

---

## What PromptGuard Does

The application follows this flow:

```text

User Prompt

     ↓

Sensitive Data Detection

     ↓

Prompt Injection Detection

     ↓

Risk Analysis

     ↓

Security Decision

     ↓

ALLOW / SANITIZE / BLOCK

     ↓

Safe Prompt

Example

Input:

My email is test@example.com

PromptGuard detects the email and creates:

My email is [EMAIL_MASKED]

The system then gives a security decision based on the calculated risk.

Features

Sensitive Data Detection

Currently detects:

Email addresses

Phone numbers

Credit card numbers

Bank account numbers

Passwords

API keys

JWT tokens

Aadhaar numbers

IP addresses

Prompt Injection Detection

Detects common injection patterns such as:

Instruction Override

System Prompt Extraction

Safety Bypass

Developer Instruction Manipulation

Role Manipulation

Jailbreak attempts

Risk Analysis

The application calculates:

Privacy Risk

Security Risk

Overall Risk

Scores are calculated from 0 - 100.

Security Decision

Based on the risk and detected information, PromptGuard can return:

🟢 ALLOW

🟡 SANITIZE

🔴 BLOCK

For example:

No significant risk

        ↓

      ALLOW

Personal information detected

        ↓

     SANITIZE

        ↓

Sensitive data is masked

Password / API key / critical attack

        ↓

      BLOCK

Web Dashboard

The project also has a simple web interface where a user can enter a

prompt and see the complete security analysis.

The dashboard shows:

Privacy score

Security score

Overall score

Detected sensitive information

Prompt injection status

Security decision

Masked prompt

Recommendations

Screenshots will be added to the docs folder.

Project Structure

promptguard/

│

├── backend/

│   ├── __init__.py

│   ├── app.py

│   ├── detector.py

│   ├── masker.py

│   ├── risk_analyzer.py

│   ├── injection_detector.py

│   ├── suggestions.py

│   ├── decision_engine.py

│   └── database.py

│

├── frontend/

│   ├── templates/

│   │   ├── index.html

│   │   └── history.html

│   │

│   └── static/

│       └── style.css

│

├── tests/

│   └── test_promptguard.py

│

├── docs/

│

├── data/

│

├── .gitignore

├── .env.example

├── requirements.txt

└── README.md

What Each Main File Does

File    Purpose

app.py  Flask application and API routes

detector.py Detects sensitive information

masker.py   Masks detected sensitive data

risk_analyzer.py    Calculates privacy and security risk

injection_detector.py   Detects prompt injection patterns

decision_engine.py  Decides ALLOW, SANITIZE or BLOCK

suggestions.py  Generates security recommendations

database.py Stores scan history in SQLite

test_promptguard.py Automated tests

Technology Used

Python - Main programming language

Flask - Backend and REST API

SQLite - Stores scan history

HTML/CSS - Frontend

Jinja2 - HTML templates

Regular Expressions - Pattern-based detection

pytest - Testing

Git & GitHub - Version control

How to Run

1. Clone the repository

git clone https://github.com/sanju-2005/promptguard.git

cd promptguard

2. Create a virtual environment

python -m venv .venv

3. Activate it

For Windows PowerShell:

.venv\Scripts\Activate.ps1

4. Install dependencies

pip install -r requirements.txt

5. Start the application

python -m backend.app

Then open:

http://127.0.0.1:5000

REST API

PromptGuard also provides an API for analyzing prompts.

Endpoint

POST /api/analyze

Example Request

{

    "prompt": "My email is test@example.com"

}

Example Result

{

    "decision": {

        "action": "SANITIZE"

    }

}

The complete response also contains:

Original prompt

Masked prompt

Detected data

Injection analysis

Risk scores

Security decision

Suggestions

Health Check

The application has a simple health endpoint:

GET /health

Example response:

{

    "status": "healthy",

    "service": "PromptGuard AI"

}

Scan History

PromptGuard stores previous scans in a local SQLite database.

The history page can be opened at:

http://127.0.0.1:5000/history

It shows information such as:

Scan ID

Time of scan

Privacy score

Security score

Overall risk

Prompt injection status

Original prompt

Masked prompt

The database file is excluded from Git using .gitignore.

Testing

The project uses pytest.

Run:

python -m pytest -v

The tests cover different parts of the application including:

Sensitive data detection

Data masking

Prompt injection detection

Risk calculation

Security decisions

API endpoints

Health endpoint

Input validation

Scan history

Security Decision Logic

The current decision logic is based on predefined security rules.

Critical sensitive information

            ↓

          BLOCK

Critical prompt injection

            ↓

          BLOCK

No detected risk

            ↓

          ALLOW

Moderate risk

            ↓

        SANITIZE

High risk

            ↓

          BLOCK

Critical information includes things such as passwords, API keys and

Aadhaar numbers.

Current Limitations

This is currently a project/prototype implementation.

Some limitations are:

Detection is mainly regex based.

New or disguised attack patterns may not always be detected.

Prompt injection detection currently focuses on known patterns.

SQLite is being used for local development.

Authentication is not implemented yet.

The application is not yet connected to an external LLM provider.

Production-level security controls are not implemented.

Future Improvements

Some improvements I would like to add later:

ML-based sensitive data detection

Semantic prompt injection detection

LLM-based security classification

PostgreSQL

Authentication and authorization

API rate limiting

Docker deployment

Better security monitoring

Configurable security policies

Integration with different LLM providers

What I Learned From This Project

Through this project I worked with:

Python backend development

Flask

REST APIs

Regular expressions

Data masking

Prompt injection concepts

Risk scoring

Security decision logic

SQLite

HTML/CSS

Automated testing with pytest

Git and GitHub

Basic application architecture

The main thing I learned is how different small components can be

combined to create a complete security pipeline instead of writing

everything in one file.

Project Status

Component   Status

Sensitive Data Detection    ✅ Done

Data Masking    ✅ Done

Prompt Injection Detection  ✅ Done

Risk Analysis   ✅ Done

Security Decision Engine    ✅ Done

Security Suggestions    ✅ Done

SQLite History  ✅ Done

REST API    ✅ Done

Health Check    ✅ Done

Input Validation    ✅ Done

Automated Tests 🚧 Final Verification

Screenshots 🚧 To Add

LLM Integration 🔮 Future u give extact one i cant change again and again i will just paste

YES. 😭 No more changing. Use the version below as your final README.

I have:

Fixed all Markdown formatting.
Added all missing headings.
Fixed code blocks.
Fixed the project tree.
Made the API examples valid.
Kept the wording student-like.
Removed unnecessary AI-sounding sections.
Kept it impressive and honest.
Removed the unfinished “screenshots” claims from the main feature list and kept them under future/current status.
Did not claim a test count, because we haven't verified the final count yet.
IMPORTANT

Copy only everything inside the following box, starting from # PromptGuard AI and ending at **Sanjana**.

# PromptGuard AI 🛡️

### Privacy & Security Gateway for Generative AI Prompts

PromptGuard AI is a security gateway that checks a user's prompt before
it is sent to a Generative AI system.

The main idea is simple:

> Don't directly send every user prompt to an AI model. Check it first.

PromptGuard checks the prompt for sensitive information and common prompt
injection attempts, calculates the risk, and decides whether the prompt
should be allowed, sanitized, or blocked.

---

## Why I Built This

While working with Generative AI applications, user prompts can sometimes
contain sensitive information such as passwords, API keys, phone numbers,
or other personal data.

Prompts can also contain malicious instructions such as:

- Ignore previous instructions
- Reveal the system prompt
- Bypass safety restrictions
- Act as an unrestricted AI

I wanted to build a project that acts as a security layer before the
prompt reaches an AI system.

---

## What PromptGuard Does

The application follows this flow:

```text
User Prompt
     ↓
Sensitive Data Detection
     ↓
Prompt Injection Detection
     ↓
Risk Analysis
     ↓
Security Decision
     ↓
ALLOW / SANITIZE / BLOCK
     ↓
Safe Prompt
Example

Input:

My email is test@example.com

PromptGuard detects the email and creates:

My email is [EMAIL_MASKED]

The system then gives a security decision based on the calculated risk.

Features
Sensitive Data Detection

Currently detects:

Email addresses
Phone numbers
Credit card numbers
Bank account numbers
Passwords
API keys
JWT tokens
Aadhaar numbers
IP addresses
Prompt Injection Detection

Detects common injection patterns such as:

Instruction Override
System Prompt Extraction
Safety Bypass
Developer Instruction Manipulation
Role Manipulation
Jailbreak attempts
Risk Analysis

The application calculates:

Privacy Risk
Security Risk
Overall Risk

Scores are calculated from 0 - 100.

Security Decision

Based on the risk and detected information, PromptGuard can return:

🟢 ALLOW
🟡 SANITIZE
🔴 BLOCK

For example:

No significant risk
        ↓
      ALLOW
Personal information detected
        ↓
     SANITIZE
        ↓
Sensitive data is masked
Password / API key / critical attack
        ↓
      BLOCK
Web Dashboard

The project also has a simple web interface where a user can enter a
prompt and see the complete security analysis.

The dashboard shows:

Privacy score
Security score
Overall score
Detected sensitive information
Prompt injection status
Security decision
Masked prompt
Recommendations
Project Structure
promptguard/
│
├── backend/
│   ├── __init__.py
│   ├── app.py
│   ├── detector.py
│   ├── masker.py
│   ├── risk_analyzer.py
│   ├── injection_detector.py
│   ├── suggestions.py
│   ├── decision_engine.py
│   └── database.py
│
├── frontend/
│   ├── templates/
│   │   ├── index.html
│   │   └── history.html
│   │
│   └── static/
│       └── style.css
│
├── tests/
│   └── test_promptguard.py
│
├── docs/
├── data/
│
├── .gitignore
├── .env.example
├── requirements.txt
└── README.md
What Each Main File Does
File	Purpose
app.py	Flask application and API routes
detector.py	Detects sensitive information
masker.py	Masks detected sensitive data
risk_analyzer.py	Calculates privacy and security risk
injection_detector.py	Detects prompt injection patterns
decision_engine.py	Decides ALLOW, SANITIZE or BLOCK
suggestions.py	Generates security recommendations
database.py	Stores scan history in SQLite
test_promptguard.py	Automated tests
Technology Used
Python - Main programming language
Flask - Backend and REST API
SQLite - Stores scan history
HTML/CSS - Frontend
Jinja2 - HTML templates
Regular Expressions - Pattern-based detection
pytest - Testing
Git & GitHub - Version control
How to Run
1. Clone the repository
git clone https://github.com/sanju-2005/promptguard.git
cd promptguard
2. Create a virtual environment
python -m venv .venv
3. Activate it

For Windows PowerShell:

.venv\Scripts\Activate.ps1
4. Install dependencies
pip install -r requirements.txt
5. Start the application
python -m backend.app

Then open:

http://127.0.0.1:5000
REST API

PromptGuard also provides an API for analyzing prompts.

Endpoint
POST /api/analyze
Example Request
{
    "prompt": "My email is test@example.com"
}
Example Result
{
    "decision": {
        "action": "SANITIZE"
    }
}

The complete response also contains:

Original prompt
Masked prompt
Detected data
Injection analysis
Risk scores
Security decision
Suggestions
Health Check

The application has a simple health endpoint:

GET /health

Example response:

{
    "status": "healthy",
    "service": "PromptGuard AI"
}
Scan History

PromptGuard stores previous scans in a local SQLite database.

The history page can be opened at:

http://127.0.0.1:5000/history

It shows information such as:

Scan ID
Time of scan
Privacy score
Security score
Overall risk
Prompt injection status
Original prompt
Masked prompt

The database file is excluded from Git using .gitignore.

Testing

The project uses pytest.

Run:

python -m pytest -v

The tests cover different parts of the application including:

Sensitive data detection
Data masking
Prompt injection detection
Risk calculation
Security decisions
API endpoints
Health endpoint
Input validation
Scan history
Security Decision Logic

The current decision logic is based on predefined security rules.

Critical sensitive information
            ↓
          BLOCK
Critical prompt injection
            ↓
          BLOCK
No detected risk
            ↓
          ALLOW
Moderate risk
            ↓
        SANITIZE
High risk
            ↓
          BLOCK

Critical information includes things such as passwords, API keys and
Aadhaar numbers.

Current Limitations

This is currently a project/prototype implementation.

Some limitations are:

Detection is mainly regex based.
New or disguised attack patterns may not always be detected.
Prompt injection detection currently focuses on known patterns.
SQLite is being used for local development.
Authentication is not implemented yet.
The application is not yet connected to an external LLM provider.
Production-level security controls are not implemented.
Future Improvements

Some improvements I would like to add later:

ML-based sensitive data detection
Semantic prompt injection detection
LLM-based security classification
PostgreSQL
Authentication and authorization
API rate limiting
Docker deployment
Better security monitoring
Configurable security policies
Integration with different LLM providers
What I Learned From This Project

Through this project I worked with:

Python backend development
Flask
REST APIs
Regular expressions
Data masking
Prompt injection concepts
Risk scoring
Security decision logic
SQLite
HTML/CSS
Automated testing with pytest
Git and GitHub
Basic application architecture

The main thing I learned is how different small components can be
combined to create a complete security pipeline instead of writing
everything in one file.

Project Status
Component	Status
Sensitive Data Detection	✅ Done
Data Masking	✅ Done
Prompt Injection Detection	✅ Done
Risk Analysis	✅ Done
Security Decision Engine	✅ Done
Security Suggestions	✅ Done
SQLite History	✅ Done
REST API	✅ Done
Health Check	✅ Done
Input Validation	✅ Done
Automated Tests	🚧 Final Verification
Screenshots	🚧 To Add
LLM Integration	🔮 Future
## Author

**Sanjana**

B.Tech AI Student

GitHub: https://github.com/sanju-2005/promptguard