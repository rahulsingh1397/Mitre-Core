# MITRE-CORE: Advanced Threat Detection & Correlation Engine

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-Live%20Dashboard-brightgreen)

## Overview

MITRE-CORE is an advanced cybersecurity analytics platform designed to detect and correlate security alerts into meaningful attack chains using the MITRE ATT&CK framework. The system ingests raw security events (CSV uploads, synthetic campaigns, or live SIEM telemetry), applies machine learning techniques to identify patterns, and visualizes potential Advanced Persistent Threat (APT) campaigns through an interactive Flask + Plotly dashboard.

## Features

- **Union-Find Correlation Engine**: Weighted scoring, temporal proximity, and adaptive thresholds group alerts into high-confidence clusters
- **MITRE ATT&CK Mapping**: Automatic tactic identification plus stage classification (Initial / Partial / Potential Hit)
- **Live SIEM Connectors**: Splunk, Elastic, Microsoft Sentinel, IBM QRadar, Syslog, and Webhook adapters stream telemetry into the engine
- **Developer Mode**: Toggle synthetic campaign generation and testing tools directly from the dashboard
- **Interactive Dashboard**: Plotly network graph, cluster explorer, tactic distribution, and live alert feed
- **Research-Grade Evaluation**: Comprehensive benchmarking suite with ARI/NMI metrics, baseline methods, and statistical validation

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/MITRE-CORE.git
   cd MITRE-CORE
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### 1) Launch the web dashboard

```bash
export FLASK_ENV=development  # optional
python app.py
```

Open <http://localhost:5000> in your browser and choose one of two workflows:

1. **Analysis Tab (default)**
   - Upload a CSV with alert data (see Data Requirements below)
   - Optionally toggle **Developer Mode** (top-right PRO switch) to generate synthetic campaigns via `Testing.py`
   - Inspect stats, Plotly graph, tactic distribution, and detailed cluster cards

2. **Live SIEM Tab**
   - Add connectors (Splunk, Elastic, Sentinel, QRadar, Syslog, Webhook)
   - Start the ingestion engine (configurable poll/correlation intervals)
   - Watch live alerts, buffer stats, and correlation results update in real time

### 2) Command-line evaluation (optional)

```bash
python tests/validate_improvements.py
python tests/phase1_verification.py
```

### 3) Output artifacts

- Cleaned/correlated CSVs: `Data/Cleaned/`
- JSON summaries: `output.json`
- Plotly HTML exports (if generated programmatically): `Plots/`

## Data Requirements

Input data should be in CSV format with the following key fields:

| Field | Description |
|--------|-------------|
| `AlertId` | Unique identifier for each alert |
| `SourceAddress` | Source IP address |
| `DestinationAddress` | Destination IP address |
| `DeviceAddress` | Device IP address |
| `SourceUserName` | Source username |
| `SourceHostName` | Source hostname |
| `DestinationHostName` | Destination hostname |
| `AttackType` | Type of attack |
| `AttackSeverity` | Severity level |

## Project Structure

```
MITRE-CORE/
├── app.py                    # Flask + Plotly dashboard / REST API
├── correlation_indexer.py    # Enhanced Union-Find correlation engine
├── preprocessing.py          # Data ingestion, feature engineering
├── postprocessing.py         # Cluster cleaning, chain extraction
├── output.py                 # JSON report builder + stage classification
├── Testing.py                # Synthetic campaign generator (Dev Mode)
├── plots.py                  # Standalone Plotly export utility
├── siem/
│   ├── connectors.py         # Splunk/Elastic/Sentinel/QRadar/Syslog/Webhook adapters
│   └── ingestion_engine.py   # Live ingestion, buffering, alerting
├── evaluation/               # Metrics + benchmarking suite
├── baselines/                # Reference clustering methods
├── templates/index.html      # Tailwind UI for dashboard
├── static/                   # Static assets (generated uploads ignored)
├── docs/                     # Reports, roadmaps, research notes
├── tests/                    # Validation + verification scripts
├── Data/, Plots/, evaluation_results/ (gitignored output dirs)
└── requirements.txt
```

## Performance

| Dataset Size | Processing Time | Accuracy (ARI/NMI) |
|--------------|-----------------|--------------------|
| 5 attacks (64 rows) | 11 seconds | 1.00 / 1.00 |
| 40 attacks (301 rows) | 1 min 51 sec | 1.00 / 1.00 |

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For questions or feedback, please open an issue or reach out via the contact info in `docs/PROJECT_SUMMARY.md`.

---

*This project is not affiliated with or endorsed by The MITRE Corporation.*

https://center-for-threat-informed-defense.github.io/attack-flow/example_flows/#list-of-examples

https://github.com/vz-risk/veris

https://github.com/sduff/mitre_attack_csv/tree/main
