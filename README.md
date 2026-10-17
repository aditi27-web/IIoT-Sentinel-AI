# IIoT Sentinel AI — DBMS + Machine Learning Project

## Project overview
An educational web application inspired by Buja, Apostolova and Luma (2024), *A Model Proposal of Cybersecurity for the IIoT: Enhancing IIoT Cybersecurity through Machine Learning and Deep Learning Techniques*. It records industrial-IoT assets and vulnerability assessments, predicts a severity category with ML, and ranks illustrative remediation actions with a cost-benefit score.

**Important research honesty:** this runnable version trains on synthetic, rule-generated examples. It is not a reproduction of the paper's original dataset or metrics, is not a real network scanner, and should not be used as an operational security product. The paper reported strong results for Gradient Boosting, Decision Tree and Random Forest on its experimental dataset; those reported metrics are not results of this project.

## Features
- Responsive web frontend (HTML/CSS/Jinja)
- Flask/Python backend
- SQLite relational database; schema can be adapted to MySQL
- Device inventory and vulnerability register
- ML classification: Gradient Boosting, Random Forest, Decision Tree, Logistic Regression, MLP Neural Network
- Recommendation engine and CBA score = estimated benefit / estimated cost
- CSV import and JSON summary endpoint
- Seed data for demonstration

## Run on Windows
1. Install Python 3.10 or later.
2. Extract this ZIP.
3. Open Command Prompt in the extracted `iiot_sentinel_ai` folder.
4. Create a virtual environment:
   ```bat
   py -m venv .venv
   .venv\Scripts\activate
   ```
5. Install dependencies:
   ```bat
   pip install -r requirements.txt
   ```
6. Start:
   ```bat
   python app.py
   ```
7. Open `http://127.0.0.1:5000`.

The first run creates `data/iiot_sentinel.db` and trains the demo ML models. Do not commit the generated DB or `ml/models.pkl` to a public repository if you later add sensitive data.

## Main pages
- `/` — overview dashboard
- `/vulnerabilities` — stored assessments
- `/analyze` — submit a record for prediction
- `/devices` — device inventory
- `/import` — upload CSV
- `/api/summary` — severity counts as JSON

## DBMS design
- `devices`: registered industrial assets
- `vulnerabilities`: assessment inputs, predicted severity, recommendation and CBA values
- `predictions`: prediction history by model
- `mitigation_actions`: schema for tracking action status and cost-benefit

Relationships: one device can have many vulnerability records; one vulnerability can have many predictions and mitigation actions. Foreign keys preserve referential integrity. SQL constraints and parameterized queries are used by the application.

## ML pipeline
Features: `cvss`, `port`, `is_public`, `patch_available`, `known_exploit`, `asset_criticality`.
Target: `Low`, `Medium`, `High`, `Critical`.
Models: Gradient Boosting, Random Forest, Decision Tree, Logistic Regression and MLP.

Training labels are created from an illustrative formula in `ml/model.py`; therefore performance against these labels only measures agreement with that synthetic rule. For meaningful research, replace this with a properly licensed and documented dataset, prevent target leakage, use stratified train/test split and report precision, recall, F1 and confusion matrix.

The paper also discusses CNN. CNN is not included in this starter app because tabular vulnerability records are not naturally image/grid data; a CNN can be added if a defensible input representation and sufficient dataset are available.

## CBA calculation
`CBA score = estimated benefit / estimated cost`.
A larger score means more estimated benefit per unit cost. Cost and benefit values in this project are illustrative demo values, not real quotes or guaranteed savings.

## Suggested viva explanation
1. Problem: IIoT devices increase the attack surface and vulnerabilities need prioritization.
2. DBMS: relational tables store assets, vulnerability records, predictions and mitigation actions.
3. Backend: Flask receives input, validates it, calls the model, computes CBA and writes records using SQL.
4. ML: models classify severity based on vulnerability and asset features.
5. CBA: recommendations are ranked by benefit/cost ratio.
6. Limitation: synthetic labels and no operational data; human verification required.
7. Future scope: authorized scanner integration, trusted CVE/NVD data ingestion, authentication/roles, audit logging, model evaluation, and deployment hardening.

## Research reference
Buja, A., Apostolova, M., & Luma, A. (2024). *A Model Proposal of Cybersecurity for the IIoT: Enhancing IIoT Cybersecurity through Machine Learning and Deep Learning Techniques*. Advances in Artificial Intelligence and Machine Learning, 4(3), 2408–2415.
