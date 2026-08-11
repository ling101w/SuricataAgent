# Web boundary

`suricata_agent.web.app` is the import target for the FastAPI surface. The
implementation remains in the root `web_app.py` for now because its static-file
and artifact defaults are rooted at the repository (`web/` and `artifacts/`).
The root module is still supported for existing deployments.
