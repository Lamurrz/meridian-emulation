from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Meridian Risk API
    meridian_api_url: str = "http://127.0.0.1:8000"
    meridian_timeout: int = 10

    # CyberGraph-AD API (optional — for detection validation)
    cybergraph_api_url: str = ""
    cybergraph_findings_dir: str = ""  # path to data/findings/ if no API

    # Atomic Red Team
    atomic_repo_url: str = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master"
    atomic_index_url: str = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/index.yaml"
    atomic_cache_dir: str = "data/atomic_cache"
    atomic_cache_ttl_hours: int = 24  # re-fetch after this many hours

    # Execution
    dry_run: bool = True             # safe default — no execution without explicit flag
    execution_platform: str = "windows"  # windows | linux | macos
    execution_timeout_seconds: int = 60
    max_concurrent_tests: int = 1    # serial execution for safety

    # Output
    output_dir: str = "data/results"
    report_format: str = "json"      # json | pdf | both


settings = Settings()
