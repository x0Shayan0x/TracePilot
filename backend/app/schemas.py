import uuid
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress


class ConnectionEventCreate(BaseModel):
    timestamp: datetime
    pid: int = Field(ge=1)
    process_name: str = Field(min_length=1, max_length=64)
    uid: int = Field(ge=0)
    destination_ip: IPvAnyAddress
    destination_port: int = Field(ge=1, le=65535)
    ip_version: Literal[4, 6]
    duration_ms: float | None = Field(default=None, ge=0)
    source: str = Field(default="ebpf", max_length=20)


class ConnectionEventResponse(ConnectionEventCreate):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    
class ConnectionEventBatch(BaseModel):
    events: list[ConnectionEventCreate] = Field(
        min_length=1,
        max_length=500,
    )

class TopProcessResponse(BaseModel):
    pid: int
    process_name: str
    connection_count: int
    
class ConnectionBurstResponse(BaseModel):
    pid: int
    process_name: str
    window_start: datetime
    connection_count: int
    event_ids: list[uuid.UUID]
    
class UnusualDestinationResponse(BaseModel):
    pid: int
    destination_ip: IPvAnyAddress
    destination_port: int
    first_seen: datetime
    event_ids: list[uuid.UUID]
    
class HighUniqueDestinationsResponse(BaseModel):
    pid: int
    process_name: str
    unique_destination_count: int
    connection_count: int
    event_ids: list[uuid.UUID]
    
class InvestigationCreate(BaseModel):
    question: str = Field(
        min_length=5,
        max_length=2000,
    )


class InvestigationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    question: str
    status: str
    answer: str | None
    created_at: datetime
    completed_at: datetime | None


class AgentToolCallResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    investigation_id: uuid.UUID
    tool_name: str
    arguments: dict
    result: dict
    created_at: datetime
