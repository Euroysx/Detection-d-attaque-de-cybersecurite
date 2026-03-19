from pydantic import BaseModel, Field

class NetworkFlow(BaseModel):
    destination_port: int = Field(..., ge=0, le=65535)
    flow_duration: int = Field(..., gt=0)
    total_fwd_packets: int = Field(..., ge=0)
    total_bwd_packets: int = Field(..., ge=0)
    flow_bytes_s: float = Field(..., ge=0)