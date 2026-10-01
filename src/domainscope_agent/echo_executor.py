"""Minimal AgentExecutor implementing the echo skill.

The reference agent ships one skill, `echo`, exposed through both A2A and MCP.
A2A invocation flows through this executor; MCP invocation flows through the
matching tool definition in mcp_server.py. Both surfaces return the input
string with a small prefix so a caller can confirm the round trip.

Production agents replace this executor with their own behavior; the rest of
the reference (registration, Trust Card hosting, MCP tool surface, A2A routes)
does not change.
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
            name="echo-result",
            parts=[Part(text=text)],
        ),
    )


class EchoExecutor(AgentExecutor):
    """Returns `echo: <input>` for every A2A request."""

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
        reply = f"echo: {user_text}" if user_text else "echo: (empty input)"

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
