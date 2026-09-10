import uuid
from datetime import datetime, timedelta, timezone

from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AgentToolCall, ConnectionEvent
from pydantic import BaseModel, Field, ValidationError

class ToolNotAllowedError(Exception):
    pass


class ProcessConnectionsArguments(BaseModel):
    pid: int = Field(ge=1)
    start_time: datetime
    end_time: datetime
    
class TopNetworkProcessesArguments(BaseModel):
    minutes: int = Field(default=60, ge=1, le=1440)
    limit: int = Field(default=10, ge=1, le=100)


class ConnectionBurstsArguments(BaseModel):
    threshold: int = Field(default=100, ge=1, le=10000)
    minutes: int = Field(default=60, ge=1, le=1440)


async def get_process_connections(
    session: AsyncSession,
    arguments: ProcessConnectionsArguments,
) -> dict:
    query = (
        select(ConnectionEvent)
        .where(
            ConnectionEvent.pid == arguments.pid,
            ConnectionEvent.timestamp >= arguments.start_time,
            ConnectionEvent.timestamp <= arguments.end_time,
        )
        .order_by(ConnectionEvent.timestamp)
        .limit(500)
    )

    result = await session.execute(query)
    events = result.scalars().all()

    return {
        "pid": arguments.pid,
        "event_count": len(events),
        "events": [
            {
                "event_id": str(event.id),
                "timestamp": event.timestamp.isoformat(),
                "process_name": event.process_name,
                "uid": event.uid,
                "destination_ip": str(event.destination_ip),
                "destination_port": event.destination_port,
                "ip_version": event.ip_version,
                "duration_ms": event.duration_ms,
            }
            for event in events
        ],
    }

async def get_top_network_processes(
    session: AsyncSession,
    arguments: TopNetworkProcessesArguments,
) -> dict:
    cutoff_time = datetime.now(timezone.utc) - timedelta(
        minutes=arguments.minutes
    )

    connection_count = func.count(
        ConnectionEvent.id
    ).label("connection_count")

    query = (
        select(
            ConnectionEvent.pid,
            ConnectionEvent.process_name,
            connection_count,
            func.array_agg(ConnectionEvent.id).label(
                "event_ids"
            ),
        )
        .where(ConnectionEvent.timestamp >= cutoff_time)
        .group_by(
            ConnectionEvent.pid,
            ConnectionEvent.process_name,
        )
        .order_by(connection_count.desc())
        .limit(arguments.limit)
    )

    result = await session.execute(query)

    processes = [
        {
            "pid": row.pid,
            "process_name": row.process_name,
            "connection_count": row.connection_count,
            "event_ids": [
                str(event_id)
                for event_id in row.event_ids
            ],
        }
        for row in result.all()
    ]

    return {
        "minutes": arguments.minutes,
        "processes": processes,
    }

async def find_connection_bursts(
    session: AsyncSession,
    arguments: ConnectionBurstsArguments,
) -> dict:
    cutoff_time = datetime.now(timezone.utc) - timedelta(
        minutes=arguments.minutes
    )

    minute_window = func.date_trunc(
        "minute",
        ConnectionEvent.timestamp,
    ).label("window_start")

    connection_count = func.count(
        ConnectionEvent.id
    ).label("connection_count")

    query = (
        select(
            ConnectionEvent.pid,
            ConnectionEvent.process_name,
            minute_window,
            connection_count,
            func.array_agg(ConnectionEvent.id).label(
                "event_ids"
            ),
        )
        .where(ConnectionEvent.timestamp >= cutoff_time)
        .group_by(
            ConnectionEvent.pid,
            ConnectionEvent.process_name,
            minute_window,
        )
        .having(
            func.count(ConnectionEvent.id)
            > arguments.threshold
        )
        .order_by(connection_count.desc())
    )

    result = await session.execute(query)

    bursts = [
        {
            "pid": row.pid,
            "process_name": row.process_name,
            "window_start": row.window_start.isoformat(),
            "connection_count": row.connection_count,
            "event_ids": [
                str(event_id)
                for event_id in row.event_ids
            ],
        }
        for row in result.all()
    ]

    return {
        "threshold": arguments.threshold,
        "minutes": arguments.minutes,
        "bursts": bursts,
    }

TOOL_REGISTRY = {
    "get_process_connections": {
        "arguments_model": ProcessConnectionsArguments,
        "function": get_process_connections,
    },
    "get_top_network_processes": {
        "arguments_model": TopNetworkProcessesArguments,
        "function": get_top_network_processes,
    },
    "find_connection_bursts": {
        "arguments_model": ConnectionBurstsArguments,
        "function": find_connection_bursts,
    },
}


async def execute_agent_tool(
    tool_name: str,
    raw_arguments: dict,
    investigation_id: uuid.UUID,
    session: AsyncSession,
) -> dict:
    tool_definition = TOOL_REGISTRY.get(tool_name)

    if tool_definition is None:
        audit_record = AgentToolCall(
            investigation_id=investigation_id,
            tool_name=tool_name,
            arguments=jsonable_encoder(raw_arguments),
            result={
                "error": "tool_not_allowed",
                "message": f"Tool '{tool_name}' is not permitted.",
            },
        )

        session.add(audit_record)
        await session.commit()

        raise ToolNotAllowedError(
            f"Tool '{tool_name}' is not permitted."
        )

    arguments_model = tool_definition["arguments_model"]
    tool_function = tool_definition["function"]

    try:
        validated_arguments = arguments_model.model_validate(
            raw_arguments
        )

    except ValidationError as error:
        audit_record = AgentToolCall(
            investigation_id=investigation_id,
            tool_name=tool_name,
            arguments=jsonable_encoder(raw_arguments),
            result={
                "error": "invalid_arguments",
                "details": jsonable_encoder(error.errors()),
            },
        )

        session.add(audit_record)
        await session.commit()

        raise

    tool_result = await tool_function(
        session=session,
        arguments=validated_arguments,
    )

    serializable_result = jsonable_encoder(tool_result)

    audit_record = AgentToolCall(
        investigation_id=investigation_id,
        tool_name=tool_name,
        arguments=jsonable_encoder(
            validated_arguments.model_dump()
        ),
        result=serializable_result,
    )

    session.add(audit_record)
    await session.commit()

    return serializable_result
    

