from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Query, status
from sqlalchemy import func, select, text, tuple_
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta, timezone

from app.database import engine, get_session
from app.models import Base, ConnectionEvent
from app.schemas import (
    ConnectionBurstResponse,
    ConnectionEventBatch,
    ConnectionEventCreate,
    ConnectionEventResponse,
    HighUniqueDestinationsResponse,
    TopProcessResponse,
    UnusualDestinationResponse,
)
@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    yield

    await engine.dispose()


app = FastAPI(
    title="TracePilot API",
    description="Backend for the TracePilot network incident copilot",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


@app.get("/health/database")
async def database_health_check(
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(text("SELECT 1"))

    return {
        "status": "healthy",
        "database_result": result.scalar_one(),
    }


@app.post(
    "/events",
    response_model=ConnectionEventResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_event(
    event_data: ConnectionEventCreate,
    session: AsyncSession = Depends(get_session),
):
    event = ConnectionEvent(
        timestamp=event_data.timestamp,
        pid=event_data.pid,
        process_name=event_data.process_name,
        uid=event_data.uid,
        destination_ip=str(event_data.destination_ip),
        destination_port=event_data.destination_port,
        ip_version=event_data.ip_version,
        duration_ms=event_data.duration_ms,
        source=event_data.source,
    )

    session.add(event)
    await session.commit()
    await session.refresh(event)

    return event
    
@app.post(
    "/events/batch",
    response_model=list[ConnectionEventResponse],
    status_code=status.HTTP_201_CREATED,
)
async def create_event_batch(
    batch: ConnectionEventBatch,
    session: AsyncSession = Depends(get_session),
):
    events = [
        ConnectionEvent(
            timestamp=event_data.timestamp,
            pid=event_data.pid,
            process_name=event_data.process_name,
            uid=event_data.uid,
            destination_ip=str(event_data.destination_ip),
            destination_port=event_data.destination_port,
            ip_version=event_data.ip_version,
            duration_ms=event_data.duration_ms,
            source=event_data.source,
        )
        for event_data in batch.events
    ]

    session.add_all(events)
    await session.commit()

    return events
    
@app.get(
    "/processes/{pid}/connections",
    response_model=list[ConnectionEventResponse],
)
async def get_process_connections(
    pid: int,
    session: AsyncSession = Depends(get_session),
):
    query = (
        select(ConnectionEvent)
        .where(ConnectionEvent.pid == pid)
        .order_by(ConnectionEvent.timestamp.desc())
    )

    result = await session.execute(query)

    return result.scalars().all()
    
@app.get(
    "/analytics/top-processes",
    response_model=list[TopProcessResponse],
)
async def get_top_processes(
    minutes: int = Query(default=60, ge=1, le=1440),
    limit: int = Query(default=10, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
):
    cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=minutes)

    query = (
        select(
            ConnectionEvent.pid,
            ConnectionEvent.process_name,
            func.count(ConnectionEvent.id).label("connection_count"),
        )
        .where(ConnectionEvent.timestamp >= cutoff_time)
        .group_by(
            ConnectionEvent.pid,
            ConnectionEvent.process_name,
        )
        .order_by(func.count(ConnectionEvent.id).desc())
        .limit(limit)
    )

    result = await session.execute(query)

    return [
        TopProcessResponse(
            pid=row.pid,
            process_name=row.process_name,
            connection_count=row.connection_count,
        )
        for row in result.all()
    ]
    
@app.get(
    "/analytics/connection-bursts",
    response_model=list[ConnectionBurstResponse],
)
async def find_connection_bursts(
    threshold: int = Query(default=100, ge=1, le=10000),
    minutes: int = Query(default=60, ge=1, le=1440),
    session: AsyncSession = Depends(get_session),
):
    cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=minutes)

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
            func.array_agg(ConnectionEvent.id).label("event_ids"),
        )
        .where(ConnectionEvent.timestamp >= cutoff_time)
        .group_by(
            ConnectionEvent.pid,
            ConnectionEvent.process_name,
            minute_window,
        )
        .having(func.count(ConnectionEvent.id) > threshold)
        .order_by(connection_count.desc())
    )

    result = await session.execute(query)

    return [
        ConnectionBurstResponse(
            pid=row.pid,
            process_name=row.process_name,
            window_start=row.window_start,
            connection_count=row.connection_count,
            event_ids=row.event_ids,
        )
        for row in result.all()
    ]
    
@app.get(
    "/analytics/unusual-destinations",
    response_model=list[UnusualDestinationResponse],
)
async def find_unusual_destinations(
    pid: int = Query(ge=1),
    recent_minutes: int = Query(default=60, ge=1, le=1440),
    baseline_minutes: int = Query(default=1440, ge=1, le=10080),
    session: AsyncSession = Depends(get_session),
):
    now = datetime.now(timezone.utc)
    recent_start = now - timedelta(minutes=recent_minutes)
    baseline_start = recent_start - timedelta(minutes=baseline_minutes)

    baseline_query = (
        select(
            ConnectionEvent.destination_ip,
            ConnectionEvent.destination_port,
        )
        .where(
            ConnectionEvent.pid == pid,
            ConnectionEvent.timestamp >= baseline_start,
            ConnectionEvent.timestamp < recent_start,
        )
        .distinct()
    )

    baseline_result = await session.execute(baseline_query)

    baseline_destinations = {
        (str(row.destination_ip), row.destination_port)
        for row in baseline_result.all()
    }

    recent_query = (
        select(
            ConnectionEvent.destination_ip,
            ConnectionEvent.destination_port,
            func.min(ConnectionEvent.timestamp).label("first_seen"),
            func.array_agg(ConnectionEvent.id).label("event_ids"),
        )
        .where(
            ConnectionEvent.pid == pid,
            ConnectionEvent.timestamp >= recent_start,
            ConnectionEvent.timestamp <= now,
        )
        .group_by(
            ConnectionEvent.destination_ip,
            ConnectionEvent.destination_port,
        )
        .order_by(func.min(ConnectionEvent.timestamp))
    )

    recent_result = await session.execute(recent_query)

    unusual_destinations = []

    for row in recent_result.all():
        destination = (
            str(row.destination_ip),
            row.destination_port,
        )

        if destination not in baseline_destinations:
            unusual_destinations.append(
                UnusualDestinationResponse(
                    pid=pid,
                    destination_ip=row.destination_ip,
                    destination_port=row.destination_port,
                    first_seen=row.first_seen,
                    event_ids=row.event_ids,
                )
            )

    return unusual_destinations
    
@app.get(
    "/analytics/high-unique-destinations",
    response_model=list[HighUniqueDestinationsResponse],
)
async def find_high_unique_destinations(
    threshold: int = Query(default=20, ge=1, le=10000),
    minutes: int = Query(default=60, ge=1, le=1440),
    session: AsyncSession = Depends(get_session),
):
    cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=minutes)

    unique_destination_count = func.count(
        func.distinct(
            tuple_(
                ConnectionEvent.destination_ip,
                ConnectionEvent.destination_port,
            )
        )
    ).label("unique_destination_count")

    connection_count = func.count(
        ConnectionEvent.id
    ).label("connection_count")

    query = (
        select(
            ConnectionEvent.pid,
            ConnectionEvent.process_name,
            unique_destination_count,
            connection_count,
            func.array_agg(ConnectionEvent.id).label("event_ids"),
        )
        .where(ConnectionEvent.timestamp >= cutoff_time)
        .group_by(
            ConnectionEvent.pid,
            ConnectionEvent.process_name,
        )
        .having(unique_destination_count > threshold)
        .order_by(unique_destination_count.desc())
    )

    result = await session.execute(query)

    return [
        HighUniqueDestinationsResponse(
            pid=row.pid,
            process_name=row.process_name,
            unique_destination_count=row.unique_destination_count,
            connection_count=row.connection_count,
            event_ids=row.event_ids,
        )
        for row in result.all()
    ]
