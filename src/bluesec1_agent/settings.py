from pathlib import Path
from typing import Any

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class Settings(BaseSettings):
    """Scenario-runtime and OpenAI-compatible provider settings."""

    model_config = SettingsConfigDict(
        env_file=_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    scenario_runtime_endpoint: str = Field(
        default="127.0.0.1:50051",
        validation_alias="SCENARIO_RUNTIME_ENDPOINT",
        min_length=1,
    )
    scenario_runtime_token: SecretStr = Field(
        validation_alias="SCENARIO_RUNTIME_TOKEN",
        min_length=1,
    )
    scenario_runtime_verify_tls: bool = Field(
        default=True,
        validation_alias="SCENARIO_RUNTIME_VERIFY_TLS",
    )
    scenario_runtime_arena: str | None = Field(
        default=None,
        validation_alias="SCENARIO_RUNTIME_ARENA",
        min_length=1,
        max_length=64,
    )
    remote_run_label: str = Field(
        default="bluesec1-agent",
        validation_alias="REMOTE_RUN_LABEL",
        min_length=1,
    )
    agent_name: str = Field(
        default="bluesec1-agent",
        validation_alias="AGENT_NAME",
        min_length=1,
        max_length=255,
    )

    public_model_name: str | None = Field(
        default=None,
        validation_alias="PUBLIC_MODEL_NAME",
        min_length=1,
        max_length=255,
    )

    llm_base_url: str = Field(validation_alias="LLM_BASE_URL", min_length=1)
    llm_api_key: SecretStr = Field(validation_alias="LLM_API_KEY", min_length=1)
    llm_default_model: str = Field(validation_alias="LLM_DEFAULT_MODEL", min_length=1)
    llm_timeout_seconds: float = Field(
        default=120.0,
        validation_alias="LLM_TIMEOUT_SECONDS",
        gt=0,
    )
    llm_temperature: float | None = Field(
        default=None,
        validation_alias="LLM_TEMPERATURE",
        ge=0,
        le=2,
    )
    llm_extra_body: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias="LLM_EXTRA_BODY",
    )
    llm_max_completion_tokens: int = Field(
        default=16_384,
        validation_alias="LLM_MAX_COMPLETION_TOKENS",
        gt=0,
    )
    llm_outage_wait_seconds: float = Field(
        default=300.0,
        validation_alias="LLM_OUTAGE_WAIT_SECONDS",
        ge=0,
    )
    llm_recovery_wait_seconds: float = Field(
        # The platform closes a run after 15 minutes without a request.
        default=720.0,
        validation_alias="LLM_RECOVERY_WAIT_SECONDS",
        ge=0,
    )
    llm_max_step_retries: int = Field(
        default=3,
        validation_alias="LLM_MAX_STEP_RETRIES",
        ge=1,
        le=5,
    )
    agent_max_steps: int = Field(
        default=100,
        validation_alias="BLUESEC_AGENT_MAX_STEPS",
        ge=1,
        le=100,
    )
    agent_soft_steps: int | None = Field(
        default=25,
        validation_alias="BLUESEC_AGENT_SOFT_STEPS",
        ge=1,
    )
    agent_tool_result_max_chars: int = Field(
        default=20_000,
        validation_alias="BLUESEC_TOOL_RESULT_MAX_CHARS",
        ge=500,
    )
    agent_context_max_chars: int = Field(
        default=120_000,
        validation_alias="BLUESEC_CONTEXT_MAX_CHARS",
        ge=10_000,
    )
    agent_review_finish: bool = Field(
        default=True,
        validation_alias="BLUESEC_REVIEW_FINISH",
    )
    agent_knowledge: bool = Field(
        default=True,
        validation_alias="BLUESEC_KNOWLEDGE",
    )
    agent_knowledge_calls: int = Field(
        default=8,
        validation_alias="BLUESEC_KNOWLEDGE_CALLS",
        ge=0,
    )
    agent_thinking: str = Field(
        default="key",
        validation_alias="BLUESEC_THINKING",
        pattern="^(off|key|all)$",
    )
    agent_assess_samples: int = Field(
        default=3,
        validation_alias="BLUESEC_ASSESS_SAMPLES",
        ge=1,
        le=7,
    )
    agent_report_samples: int = Field(
        default=3,
        validation_alias="BLUESEC_REPORT_SAMPLES",
        ge=1,
        le=7,
    )
    agent_composite_tools: bool = Field(
        default=True,
        validation_alias="BLUESEC_COMPOSITE_TOOLS",
    )
    agent_process_tree: bool = Field(
        default=False,
        validation_alias="BLUESEC_PROCESS_TREE",
    )
    agent_hypotheses: bool = Field(
        default=True,
        validation_alias="BLUESEC_HYPOTHESES",
    )
    agent_report_form: bool = Field(
        default=True,
        validation_alias="BLUESEC_REPORT_FORM",
    )
    agent_ad_lookups: int = Field(
        default=1,
        validation_alias="BLUESEC_AD_LOOKUPS",
        ge=0,
    )
    agent_detections: bool = Field(
        default=False,
        validation_alias="BLUESEC_DETECTIONS",
    )
    agent_stacking: bool = Field(
        default=True,
        validation_alias="BLUESEC_STACKING",
    )
    agent_pace: str = Field(
        default="lean",
        validation_alias="BLUESEC_PACE",
        pattern="^(lean|brisk|normal)$",
    )
    agent_benign_shape: str = Field(
        default="core_people",
        validation_alias="BLUESEC_BENIGN_SHAPE",
        pattern="^(core_people|core|model)$",
    )
    agent_artifact_filter: bool = Field(
        default=True,
        validation_alias="BLUESEC_ARTIFACT_FILTER",
    )
    agent_host_sweep_pages: int = Field(
        # One page: the trigger's session. In 240 practice tasks the host-timeline page
        # never opened report evidence, while the session page did in half of them.
        default=1,
        validation_alias="BLUESEC_HOST_SWEEP_PAGES",
        ge=0,
        le=5,
    )
    agent_logon_sweep: bool = Field(
        default=False,
        validation_alias="BLUESEC_LOGON_SWEEP",
    )
    agent_sweep_split: bool = Field(
        default=False,
        validation_alias="BLUESEC_SWEEP_SPLIT",
    )
    agent_account_directory: bool = Field(
        default=False,
        validation_alias="BLUESEC_ACCOUNT_DIRECTORY",
    )
    agent_account_context: bool = Field(
        default=True,
        validation_alias="BLUESEC_ACCOUNT_CONTEXT",
    )
    agent_knowledge_ranker: str = Field(
        default="hybrid",
        validation_alias="BLUESEC_KNOWLEDGE_RANKER",
        pattern="^(idf|bm25|hybrid)$",
    )
    agent_checkpoint_after: int | None = Field(
        default=15,
        validation_alias="BLUESEC_CHECKPOINT_AFTER",
        ge=1,
    )
    agent_trajectory_dir: Path | None = Field(
        default=Path("runs"),
        validation_alias="BLUESEC_TRAJECTORY_DIR",
    )
