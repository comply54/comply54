# comply54 Sector Quickstart Notebooks

These notebooks provide runnable quickstarts for the sector-specific compliance packs included with `comply54`.

Each notebook demonstrates how to install `comply54`, initialize a sector pack, evaluate realistic compliance scenarios, inspect `ComplianceResult` decisions, and understand how the same compliance layer can be integrated into a LangGraph agent workflow.

## Quickstarts

| Sector | Compliance class | Jurisdiction(s) | Notebook |
|---|---|---|---|
| Nigeria Fintech | `NigeriaFintechCompliance` | Nigeria | [Open notebook](01_nigeria_fintech.ipynb) |
| Nigeria Healthcare | `NigeriaHealthcareCompliance` | Nigeria | [Open notebook](02_nigeria_health.ipynb) |
| Nigeria Insurance | `NigeriaInsuranceCompliance` | Nigeria | [Open notebook](03_nigeria_insurance.ipynb) |
| Kenya Fintech | `KenyaFintechCompliance` | Kenya | [Open notebook](04_kenya_fintech.ipynb) |
| Pan-African Fintech | `PanAfricanFintechCompliance` | Nigeria, Kenya, South Africa, Ghana, Rwanda, Egypt, Ethiopia, Mauritius, Tanzania, Uganda | [Open notebook](05_pan_african.ipynb) |

## Run in Google Colab

Each notebook includes an **Open in Colab** badge near the top.

Opening a notebook in Colab gives you a hosted Jupyter environment, so you can run the quickstart without setting up a local Python environment.

Run the cells from top to bottom. The notebook installs its required package with:

```python
%pip install comply54
```

## Run locally

Clone the repository and move into the project directory:

```bash
git clone https://github.com/comply54/comply54.git
cd comply54
```

Start Jupyter:

```bash
jupyter notebook
```

Then open the `notebooks/` directory and select the quickstart you want to run.

Run the notebook cells from top to bottom.

## LangGraph integration

The executable quickstart examples require only `comply54`.

Each notebook also includes a non-executed LangGraph integration example showing how `Comply54Guard` can be placed between an AI agent and its tools so compliance checks happen before tool execution.

To run those optional integration examples in your own application, install the LangGraph extra:

```bash
pip install "comply54[langgraph]"
```

The LangGraph snippets are integration sketches and assume application-specific components such as agent state, model calls, and tool definitions.