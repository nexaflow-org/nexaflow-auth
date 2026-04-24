from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class UserCredentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)

    @field_validator("password")
    @classmethod
    def strong_password(cls, value: str) -> str:
        trimmed = value.strip()
        if len(trimmed) < 12:
            raise ValueError("Password must be at least 12 characters long.")
        return trimmed


class TokenResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: str
    email: EmailStr
    access_token: str
    token_type: str = "bearer"


class UserProfile(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: str
    email: EmailStr


class TokenValidationRequest(BaseModel):
    token: str = Field(min_length=20, max_length=4096)


class TokenValidationResponse(BaseModel):
    valid: bool
    user_id: str | None = None
    email: EmailStr | None = None
