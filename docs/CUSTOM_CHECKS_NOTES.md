# custom_checks integration notes

## Driver hook target
/Users/michele.daddetta/Documents/Databricks/TotalEnergies/security-analysis-tool/notebooks/security_analysis_driver.py

The driver defines `processWorkspace(wsrow)` at line 107, which is called to orchestrate analysis of each workspace. Key entry points:
- Line 124-136: calls `workspace_bootstrap` then chains to `workspace_analysis`, `workspace_stats`, `workspace_settings`
- Line 156-173: iterates over workspaces and calls `processWorkspace` in serial or parallel mode

## Config target
/Users/michele.daddetta/Documents/Databricks/TotalEnergies/security-analysis-tool/notebooks/Utils/initialize.py

This notebook populates the `json_` configuration dictionary starting at line 48. Key sections:
- Lines 48-58: core config (account_id, sql_warehouse_id, analysis_schema_name, verbosity, maxpages, timebetweencalls, proxies) loaded from secrets
- Lines 73-78: intermediate_schema naming logic
- Lines 82-102: secondary config updates (master_name_scope, workspace_pat_scope, sat_version, etc.)
- Lines 108-145: cloud-specific config for GCP and Azure

The `json_` dict is then passed to child notebooks via `dbutils.notebook.run(..., {"json_": json.dumps(json_)})`.

## Pytest baseline
1 passed, 192 errors, 0 skipped

Test suite located in: `/Users/michele.daddetta/Documents/Databricks/TotalEnergies/security-analysis-tool/src/securityanalysistoolproject/tests/`

The 192 errors are environment-related (KeyError: 'MEISTERSTUFF'), indicating the test suite expects a pre-configured workspace context that is not available in local CLI runs. This is expected behavior and does not indicate broken tests.

## Package structure
notebooks/Includes/custom_checks/ will be created as a Python package for custom check implementations.

Import verification (Step 6) confirmed: `importlib.util.spec_from_file_location()` successfully resolves workspace_analysis.py, confirming the file-based import mechanism works.
