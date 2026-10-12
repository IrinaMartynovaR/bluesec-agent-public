import asyncio
import json
import time
from types import TracebackType
from typing import Any, Protocol, Self, cast

from loguru import logger
from openai import (
    APIConnectionError,
    APITimeoutError,
    AsyncOpenAI,
    InternalServerError,
    RateLimitError,
)
from openai.types.chat import ChatCompletionMessageParam, ChatCompletionToolParam

from bluesec1_agent.models import AgentAction, ToolCatalog

REPAIR_INSTRUCTION = (
    "Your previous reply was rejected before reaching the runtime: {error} "
    "Reply with exactly one call to an advertised tool, with arguments that match "
    "its JSON schema. Pass nested objects as JSON objects, not as strings."
)


# Provider failures that go away on their own; anything else is a real error.
TRANSIENT_ERRORS = (APIConnectionError, APITimeoutError, RateLimitError, InternalServerError)
MAX_BACKOFF_SECONDS = 60.0


class NextStepRequestError(RuntimeError):
    """Raised when an LLM cannot produce a valid tool call."""


class ActionClient(Protocol):
    """Narrow async contract consumed by the investigation loop."""

    async def next_action(
        self,
        messages: list[dict[str, Any]],
        catalog: ToolCatalog,
        *,
        force_tool: str | None = None,
        thinking: bool = False,
    ) -> AgentAction:
        """Generate and validate one tool call."""
        ...


class OpenAIToolCallingClient:
    """Native tool-calling client for OpenAI-compatible providers."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout_seconds: float,
        max_completion_tokens: int,
        max_retries: int,
        temperature: float | None = None,
        extra_body: dict[str, Any] | None = None,
        outage_wait_seconds: float = 300.0,
        client: AsyncOpenAI | None = None,
    ) -> None:
        """Initialize an OpenAI-compatible tool-calling client.

        Args:
            base_url: OpenAI-compatible API root.
            api_key: Provider credential.
            model: Provider model identifier.
            timeout_seconds: Timeout applied to each provider request.
            max_completion_tokens: Maximum generated tokens per attempt.
            max_retries: Maximum generation attempts per step.
            temperature: Optional sampling temperature; provider default when None.
            extra_body: Optional provider-specific request fields, e.g. vLLM
                `chat_template_kwargs` or `repetition_penalty`.
            outage_wait_seconds: How long one request keeps retrying transient
                provider failures (connection, timeout, 429, 5xx) before giving up.
            client: Optional injected SDK client used by tests.
        """
        self.model = model
        self.max_completion_tokens = max_completion_tokens
        self.max_retries = max_retries
        self.temperature = temperature
        self.extra_body = dict(extra_body or {})
        self.outage_wait_seconds = outage_wait_seconds
        self.total_tokens = 0
        self._owns_client = client is None
        self._client = client or AsyncOpenAI(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout_seconds,
            max_retries=0,
        )

    async def __aenter__(self) -> Self:
        """Enter the async LLM client context."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close an internally owned provider client."""
        await self.aclose()

    async def aclose(self) -> None:
        """Close the provider transport created by this wrapper."""
        if self._owns_client:
            await self._client.close()

    async def next_action(
        self,
        messages: list[dict[str, Any]],
        catalog: ToolCatalog,
        *,
        force_tool: str | None = None,
        thinking: bool = False,
    ) -> AgentAction:
        """Return one locally validated tool call, repairing bad replies when possible.

        Repair turns are kept out of the caller's history so rejected attempts do
        not pollute the investigation context.

        Args:
            messages: Current investigation conversation.
            catalog: Tools advertised for the current task.
            force_tool: Tool the model must call, e.g. the finishing tool.
            thinking: Enable the model's reasoning mode for this call only.

        Returns:
            A validated tool call.

        Raises:
            NextStepRequestError: If every provider reply is unusable.
        """
        request_messages = list(messages)
        tool_choice: Any = (
            {"type": "function", "function": {"name": force_tool}} if force_tool else "required"
        )
        last_error = "Unable to obtain a tool call."
        previous_reply = None

        for attempt in range(1, self.max_retries + 1):
            started_at = time.perf_counter()
            response = await self._create(
                model=self.model,
                messages=cast(list[ChatCompletionMessageParam], request_messages),
                tools=cast(list[ChatCompletionToolParam], catalog.openai_tools()),
                tool_choice=tool_choice,
                max_completion_tokens=self.max_completion_tokens,
                **self._sampling_kwargs(thinking),
            )
            latency_ms = int((time.perf_counter() - started_at) * 1000)
            tokens = response_total_tokens(response)
            self.total_tokens += tokens

            action, error = parse_action(response, catalog)
            if action is not None:
                logger.info(
                    "LLM selected {} in {} ms using {} tokens.", action.tool, latency_ms, tokens
                )
                return action

            last_error = error
            logger.warning(
                "Rejected LLM reply on attempt {}/{}: {}", attempt, self.max_retries, error
            )
            reply = describe_reply(response)
            # The same invalid call twice means repair turns will not change the model's
            # mind; hand the error back to the investigation instead of burning retries.
            # A forced call (the final report) keeps every attempt.
            if force_tool is None and reply == previous_reply:
                logger.warning("The model repeated the same invalid call; giving up on it.")
                break
            previous_reply = reply
            request_messages.extend(
                [
                    {"role": "assistant", "content": reply[:2_000]},
                    {"role": "user", "content": REPAIR_INSTRUCTION.format(error=error)},
                ]
            )

        raise NextStepRequestError(last_error)

    async def _create(self, **kwargs: Any) -> Any:
        """Call the provider, retrying transient failures with backoff.

        Raises:
            The last transient error once `outage_wait_seconds` has passed.
        """
        deadline = time.monotonic() + self.outage_wait_seconds
        delay = 2.0
        while True:
            try:
                return await self._client.chat.completions.create(**kwargs)
            except TRANSIENT_ERRORS as exc:
                if time.monotonic() + delay > deadline:
                    raise
                logger.warning("LLM provider unavailable ({}); retrying in {:.0f} s.", exc, delay)
                await asyncio.sleep(delay)
                delay = min(delay * 2, MAX_BACKOFF_SECONDS)

    async def wait_until_available(self, max_wait_seconds: float) -> bool:
        """Block until the provider answers a minimal request, or the wait runs out.

        Args:
            max_wait_seconds: Longest time to keep probing.

        Returns:
            True once the provider answers.
        """
        deadline = time.monotonic() + max_wait_seconds
        delay = 5.0
        while True:
            try:
                await self._client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": "ping"}],
                    max_completion_tokens=1,
                )
                return True
            except TRANSIENT_ERRORS as exc:
                if time.monotonic() + delay > deadline:
                    return False
                logger.warning(
                    "Waiting for the LLM provider ({}); next probe in {:.0f} s.", exc, delay
                )
                await asyncio.sleep(delay)
                delay = min(delay * 2, MAX_BACKOFF_SECONDS)

    def _sampling_kwargs(self, thinking: bool = False) -> dict[str, Any]:
        """Build optional sampling arguments, omitting unset ones.

        Args:
            thinking: Override `chat_template_kwargs.enable_thinking` to True.

        Returns:
            Keyword arguments for the chat completion request.
        """
        kwargs: dict[str, Any] = {}
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        extra_body = dict(self.extra_body)
        if thinking:
            template_kwargs = dict(extra_body.get("chat_template_kwargs") or {})
            template_kwargs["enable_thinking"] = True
            extra_body["chat_template_kwargs"] = template_kwargs
        if extra_body:
            kwargs["extra_body"] = extra_body
        return kwargs


def parse_action(response: Any, catalog: ToolCatalog) -> tuple[AgentAction | None, str]:
    """Turn a chat completion into a validated action.

    Args:
        response: OpenAI-compatible chat completion response.
        catalog: Tools advertised for the current task.

    Returns:
        The action and an empty string, or None and the rejection reason.
    """
    choices = getattr(response, "choices", None)
    if not choices:
        return None, "The response has no choices."
    message = getattr(choices[0], "message", None)
    if message is None:
        return None, "The response has no message."
    tool_calls = getattr(message, "tool_calls", None) or []
    if not tool_calls:
        return None, "The reply contains no tool call."
    if len(tool_calls) > 1:
        logger.warning("LLM returned {} tool calls; using the first.", len(tool_calls))

    function = tool_calls[0].function
    try:
        arguments = json.loads(function.arguments or "{}")
    except json.JSONDecodeError:
        return None, f"Arguments for {function.name} are not valid JSON."
    arguments, error = catalog.validate(function.name, arguments)
    if error is not None:
        return None, error
    return (
        AgentAction(
            thought=extract_message_text(message).strip(),
            reasoning=extract_reasoning(message),
            tool=function.name,
            arguments=arguments,
        ),
        "",
    )


def extract_reasoning(message: Any) -> str:
    """Return the reasoning a thinking-mode model produced, if the provider exposes it."""
    extra = getattr(message, "model_extra", None) or {}
    reasoning = (
        getattr(message, "reasoning_content", None)
        or extra.get("reasoning_content")
        or extra.get("reasoning")
    )
    return reasoning.strip() if isinstance(reasoning, str) else ""


def describe_reply(response: Any) -> str:
    """Summarize a rejected reply for the repair turn."""
    choices = getattr(response, "choices", None) or []
    message = getattr(choices[0], "message", None) if choices else None
    if message is None:
        return "<empty>"
    parts = [extract_message_text(message)]
    for call in getattr(message, "tool_calls", None) or []:
        parts.append(f"Called {call.function.name} with {call.function.arguments}")
    return "\n".join(part for part in parts if part) or "<empty>"


def extract_message_text(message: Any) -> str:
    """Normalize string and multipart assistant content into plain text.

    Args:
        message: Provider-specific chat completion message.

    Returns:
        Concatenated textual message content.
    """
    content = getattr(message, "content", None)
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""

    text_parts: list[str] = []
    for part in content:
        if isinstance(part, dict) and part.get("type") == "text":
            text_parts.append(str(part.get("text", "")))
        elif getattr(part, "type", None) == "text":
            text_parts.append(str(getattr(part, "text", "")))
    return "".join(text_parts)


def response_total_tokens(response: Any) -> int:
    """Read total token usage when the provider supplies it.

    Args:
        response: OpenAI-compatible chat completion response.

    Returns:
        Non-negative total token count, or zero when unavailable.
    """
    usage = getattr(response, "usage", None)
    total_tokens = getattr(usage, "total_tokens", 0)
    return total_tokens if isinstance(total_tokens, int) and total_tokens >= 0 else 0


def render_json(value: Any) -> str:
    """Serialize participant-visible context for an LLM message.

    Args:
        value: Public JSON-compatible value.

    Returns:
        Stable compact JSON text.
    """
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
