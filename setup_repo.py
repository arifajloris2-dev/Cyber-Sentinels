
from pathlib import Path

folders = [
    "member1_osint/collectors",
    "member1_osint/analyzers",
    "member1_osint/models",
    "member1_osint/output",
    "member1_osint/data",

    "member2_detection/rules",
    "member2_detection/correlation",
    "member2_detection/models",

    "member3_ai_response/llm",
    "member3_ai_response/prompts",
    "member3_ai_response/response",

    "member4_vmware/log_generators",
    "member4_vmware/scenarios",
    "member4_vmware/config",

    "member5_dashboard/frontend",
    "member5_dashboard/backend",
    "member5_dashboard/components",

    "shared/schemas",
    "shared/api",
    "shared/utils",

    "data/sample",
    "data/processed",

    "docs",
    "tests/integration",
    "tests/unit"
]

files = {
    "README.md": """# Military SOC Intelligence Platform

A collaborative defensive cybersecurity project.

## Team
1. Member 1 - OSINT & Threat Intelligence
2. Member 2 - SOC Detection & Correlation
3. Member 3 - Local AI & Incident Response
4. Member 4 - VMware Simulation & Testing
5. Member 5 - Dashboard & Integration

## Architecture
Threat Intelligence + Simulated Logs
-> SOC Detection
-> AI Incident Response
-> Dashboard

## Development
Each member works in their assigned folder.
Shared schemas and API contracts must be agreed upon
before integration.
""",

    "requirements.txt": """fastapi
uvicorn
pydantic
python-dotenv
requests
pytest
""",

    ".gitignore": """__pycache__/
*.pyc
.env
.venv/
venv/
node_modules/
dist/
build/
*.log
.pytest_cache/
.idea/
.vscode/
""",

    "shared/schemas/README.md":
        "# Shared Schemas\n\nCommon data structures agreed upon by all members.\n",

    "shared/api/README.md":
        "# Shared APIs\n\nAPI contracts between project modules.\n",

    "data/sample/README.md":
        "# Sample Data\n\nUse simulated or public cached datasets. Do not commit secrets.\n",

    "docs/TEAM_WORKFLOW.md": """# Team Workflow

- Member 1: Threat intelligence
- Member 2: Detection and correlation
- Member 3: AI incident response
- Member 4: VMware simulation
- Member 5: Dashboard and integration

All members:
1. Work in your assigned folder.
2. Use shared data formats.
3. Create a separate Git branch for your work.
4. Test before opening a pull request.
5. Integrate through GitHub pull requests.
"""
}

for folder in folders:
    path = Path(folder)
    path.mkdir(parents=True, exist_ok=True)
    (path / "__init__.py").touch()

for filename, content in files.items():
    path = Path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(content, encoding="utf-8")

print("SOC project structure created successfully!")
print("All five member folders are ready.")
