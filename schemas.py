"""
Database Schemas for Slash Messenger

Each Pydantic model represents a MongoDB collection. The collection name is the lowercase of the class name.
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import datetime

class User(BaseModel):
    username: str = Field(..., description="Unique username")
    name: str = Field(..., description="Full name")
    password_hash: str = Field(..., description="Hashed password (bcrypt)")
    phone: str = Field(..., description="Phone number as string")
    avatar_url: Optional[str] = Field(None, description="Public URL of profile picture")
    bio: Optional[str] = Field(None, description="Short bio/status")
    role: Literal["user", "admin"] = Field("user", description="User role")
    is_active: bool = Field(True, description="Whether user can log in and use the app")
    suspended_reason: Optional[str] = Field(None, description="If suspended, the reason")

class Message(BaseModel):
    sender: str = Field(..., description="Username of sender")
    recipient: str = Field(..., description="Username of recipient")
    msg_type: Literal["text", "image", "video", "audio", "voice"] = Field("text")
    text: Optional[str] = Field(None)
    media_url: Optional[str] = Field(None, description="URL to uploaded media if any")
    created_at: Optional[datetime] = None
    read: bool = Field(False)

class Block(BaseModel):
    blocker: str = Field(..., description="Username who blocks")
    blocked: str = Field(..., description="Username being blocked")
    created_at: Optional[datetime] = None

# For admin audit logs
class AdminLog(BaseModel):
    actor: str
    action: str
    target: Optional[str] = None
    metadata: Optional[dict] = None
    created_at: Optional[datetime] = None
