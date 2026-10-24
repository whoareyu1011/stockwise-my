# EntreMaster

> An enterprise-grade, multi-tenant inventory management and automated reorder tracking platform designed to optimize retail supply chains and eliminate material waste for Malaysian SMEs.

---

## Team Information

| Field                 | Details                                         |
| --------------------- | ----------------------------------------------- |
| **Team Name**         | Prompt Masters          |
| **Team Domain**       | Domain 2 |
| **SDG Track (1–17)**  | SDG 8 - Decent Work and Economic |
| **Team Leader**       | Lian Yi Yen                        |
| **University**        | University of Malaya              |
| **Number of Members** | 5                                  |

## Links

| Resource          | Link                                           |
| ----------------- | ---------------------------------------------- |
| GitHub Repository | https://github.com/your-username/stockwise-my  |
| Live Demo         | https://stockwise-my.replit.app                |
| Slide Deck        | https://example.com/slides                     |
| Demo Video        | https://example.com/demo-video                 |

---

## Overview

### Problem

Small and medium-sized enterprises (SMEs) in Malaysia face severe operational inefficiencies and capital lockup due to manual, unoptimized inventory tracking. Overstocking leads to massive resource waste and spoiled inventory, while under-stocking causes costly stockouts. Furthermore, existing software lacks robust tenant isolation and enterprise security, exposing sensitive business data to unauthorized access.

### Solution

EntreMaster provides a secure, multi-tenant inventory management platform backed by PostgreSQL Row-Level Security (RLS) and automated stock tracking. By streamlining real-time stock levels, calculating precise reorder thresholds, and providing role-based security boundaries, StockWise MY helps businesses drastically reduce inventory waste and operational overhead.

### Key Features

- **Multi-Tenant Row-Level Security (RLS):** Strict database-level isolation ensuring absolute privacy and security between different business tenants.
- **Automated Inventory & Alert System:** Real-time stock level monitoring, turnover calculation, and low-stock threshold triggers.
- **Secure Authentication & RBAC:** Granular role-based access control (Manager vs. Staff) powered by JWT tokens verified against active tenant sessions.
- **Automated Security Verification:** Integrated test suite validating RLS policies and preventing unauthorized cross-tenant data access.

### Tech Stack

| Layer         | Technology                            |
| ------------- | ------------------------------------- |
| Frontend      | HTML5, JavaScript (ES6+), CSS3        |
| Backend       | Node.js (v18+), Express.js            |
| Database      | PostgreSQL 17 (Supabase Managed Service) |
| Security/Auth | JSON Web Tokens (`jsonwebtoken`), RLS |
| Hosting / Dev | Replit & Supabase Platform            |

---

## Project Structure


```

.
├── db/                        # Database schemas, migrations, and RLS policies
│   ├── phase2/                # Security policies and SQL commands
│   └── tests/                 # Database integration tests & fixtures
├── docs/                      # Diagrams, architecture docs, screenshots
├── public/                    # Static frontend assets (HTML, JS, CSS)
├── server.js                  # Main Express server entry point
├── authorize.cjs              # Authorization & RBAC middleware
├── verify-token.cjs           # JWT verification middleware
├── pools.cjs                  # Database connection pool manager
├── run-phase2-isolated.py     # Offline automated security audit test runner
├── submission/                # Required hackathon submission documents
│   ├── SDC2026_TeamName_Preliminary.pdf      # Preliminary submission
│   ├── SDC2026_TeamName_TechDeclaration.pdf  # Technical declaration
│   └── SDC2026_TeamName_Replit_POU.pdf       # Replit proof of use
├── .env.example               # Example environment variables
├── .gitignore
├── .replit                    # Replit run configuration
├── package.json               # Node.js dependencies & scripts
├── LICENSE
└── README.md

```

### Architecture


```

User (Browser) ──► Replit Deployments (Node.js/Express Backend) ──► Supabase / PostgreSQL (SSL + RLS)

```

---

## How to Run

### Option 1 — Run on Replit

1. Open the [Replit Project](https://replit.com/@your-username/stockwise-my), or import this repository via **Create Repl → Import from GitHub**.
2. Open the **Secrets** tab (🔒) in Replit and set the environment variables listed in `.env.example`:
   - `DATABASE_URL` (Your PostgreSQL / Supabase SSL connection string)
   - `JWT_SECRET` (Secret token key)
   - `PORT` (Optional, default is 3000)
3. Click **Run**. Replit uses the `.replit` configuration to execute `npm install` and start `server.js`.

---

### Option 2 — Run Locally

#### Prerequisites
- Node.js (v18.x or higher) & npm
- Python (v3.10+) *(Optional, for offline security test script)*
- PostgreSQL / Supabase Database instance

#### Steps

```bash
# 1. Clone the repository
git clone [https://github.com/your-username/stockwise-my.git](https://github.com/your-username/stockwise-my.git)
cd stockwise-my

# 2. Install Node.js dependencies
npm install

# 3. Configure environment variables
cp .env.example .env
# Edit .env and fill in your DATABASE_URL and JWT_SECRET

# 4. (Optional) Initialize Database Schemas & RLS Policies
# Run the SQL scripts in db/phase2/02_policies_commands.sql inside your PostgreSQL instance

# 5. Start the Node.js Express server
npm start
# or
node server.js

```

---

### Run Tests

To run the backend security audit and RLS policy integration tests:

```bash
# Run Node.js security integration unit tests
npm test

# Run the isolated Python RLS policy verification suite (Requires local PG / test DB)
python3 run-phase2-isolated.py

```

---

## How We Use Replit

* **Development:** Collaborated in real-time using Replit Multiplayer for rapid full-stack iteration and backend route debugging.
* **Hosting:** The production web service is deployed directly via Replit Deployments.
* **Secrets Management:** Securely stored sensitive database connection strings (`DATABASE_URL`) and signing keys (`JWT_SECRET`) using Replit Secrets.

📄 Proof of use: [`submission/SDC2026_Prompt Masters_Replit_POU.pdf`](https://www.google.com/search?q=submission/SDC2026_TeamName_Replit_POU.pdf)

---

## Challenges & Learnings

* **Challenge:** Implementing rigorous multi-tenant Row-Level Security (RLS) without introducing latency or connection pooling issues.
*Learning:* Designed custom pool manager modules (`pools.cjs`) with `node-postgres` to safely propagate tenant sessions while ensuring SSL transport security (`supabase-ca.crt`).
* **Challenge:** Preventing cross-tenant data leaks during high-concurrency API calls.
*Learning:* Built an automated test suite (`run-phase2-isolated.py` & `security.test.cjs`) to validate JWT boundaries and RLS enforcement before code deployment.

## Future Improvements

* [ ] Implement real-time WebSocket push notifications for critical low-stock alerts.
* [ ] Add AI-powered demand forecasting modules to further automate reorder point calculations.
* [ ] Expand multi-currency support for regional suppliers across Southeast Asia.

## Team

| Name | Role | GitHub |
| --- | --- | --- |
| Lian Yi Yen | Team Lead / Backend | [@username](https://github.com/username) |
| Chan Yu Earn | Frontend / UI | [@whoareyu1011](https://github.com/whoareyu1011) |
| Wong Hsin Ling | Database Admin | [@whoareyu1011](https://github.com/whoareyu1011) |

---

## Submission Checklist

* [x] Team name, domain (Domain 1 / Domain 2) and SDG track filled in
* [x] Slide deck link added
* [x] Demo video link added
* [x] Replit used, with proof of use in `submission/`
* [x] Preliminary submission completed (`SDC2026_TeamName_Preliminary.pdf`)
* [x] Technology declaration completed (`SDC2026_TeamName_TechDeclaration.pdf`)
* [x] Submission files renamed with your team name (replace `TeamName`)
* [x] "How to Run" steps verified against actual `server.js` codebase
* [x] No API keys or secrets committed to the repository

## License

This project is licensed under the [Apache License 2.0](https://www.google.com/search?q=LICENSE).

```

```
