"""AgentExecutor implementing the domain-lookup skill.

domainscope-agent ships one skill, `domain-lookup`, exposed through both A2A
and MCP. A2A invocation flows through this executor; MCP invocation flows
through the matching tool definition in mcp_server.py. Both surfaces look up
a domain over public RDAP and return a human-readable summary.
"""
from __future__ import annotations

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events.event_queue_v2 import EventQueue
from a2a.types.a2a_pb2 import (
    Artifact,
    Part,
    Task,
    TaskArtifactUpdateEvent,
    TaskState,
    TaskStatus,
    TaskStatusUpdateEvent,
)

from domainscope_agent.rdap_client import RdapLookupError, lookup_domain


def _make_task(task_id: str, context_id: str) -> Task:
    return Task(
        id=task_id,
        context_id=context_id,
        status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED),
    )


def _make_status(task_id: str, context_id: str, state: TaskState) -> TaskStatusUpdateEvent:
    return TaskStatusUpdateEvent(
        task_id=task_id,
        context_id=context_id,
        status=TaskStatus(state=state),
    )


def _make_artifact(task_id: str, context_id: str, text: str) -> TaskArtifactUpdateEvent:
    return TaskArtifactUpdateEvent(
        task_id=task_id,
        context_id=context_id,
        artifact=Artifact(
            artifact_id="result",
            name="domain-lookup-result",
            parts=[Part(text=text)],
        ),
    )


def format_lookup_result(result: dict) -> str:
    """Render an rdap_client.lookup_domain() result as human-readable text."""
    domain = result["domain"]
    if not result.get("registered"):
        return f"{domain} is not registered."

    lines = [f"{domain} is registered."]
    status = result.get("status") or []
    if status:
        lines.append(f"Status: {', '.join(status)}")
    nameservers = result.get("nameservers") or []
    if nameservers:
        lines.append(f"Nameservers: {', '.join(nameservers)}")
    if result.get("registered_date"):
        lines.append(f"Registered: {result['registered_date']}")
    if result.get("expiration_date"):
        lines.append(f"Expires: {result['expiration_date']}")
    lines.append(f"DNSSEC: {'signed' if result.get('dnssec_signed') else 'not signed'}")
    return "\n".join(lines)


def run_domain_lookup(user_text: str) -> str:
    """Look up the domain named in user_text and return a formatted reply."""
    domain = user_text.strip()
    if not domain:
        return "Please provide a domain name to look up."
    try:
        result = lookup_domain(domain)
    except RdapLookupError as exc:
        return f"Lookup failed for {domain}: {exc}"
    return format_lookup_result(result)


class DomainLookupExecutor(AgentExecutor):
    """Looks up a domain over public RDAP for every A2A request."""

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        task_id = context.task_id or "unknown"
        context_id = getattr(context, "context_id", None) or "unknown"
        if not isinstance(context_id, str):
            context_id = "unknown"

        # Enqueue the Task object first; the SDK requires this before any
        # TaskStatusUpdateEvent or TaskArtifactUpdateEvent can be processed.
        await event_queue.enqueue_event(_make_task(task_id, context_id))
        await event_queue.enqueue_event(
            _make_status(task_id, context_id, TaskState.TASK_STATE_WORKING)
        )

        user_text = context.get_user_input() or ""
        reply = run_domain_lookup(user_text)

        await event_queue.enqueue_event(_make_artifact(task_id, context_id, reply))
        await event_queue.enqueue_event(
            _make_status(task_id, context_id, TaskState.TASK_STATE_COMPLETED)
        )

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        task_id = context.task_id or "unknown"
        context_id = getattr(context, "context_id", None) or "unknown"
        if not isinstance(context_id, str):
            context_id = "unknown"
        await event_queue.enqueue_event(
            _make_status(task_id, context_id, TaskState.TASK_STATE_CANCELED)
        )
