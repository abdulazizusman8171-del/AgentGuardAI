from pydantic import BaseModel, Field


class RegistrationRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=12, max_length=128)


class EmailVerificationRequest(BaseModel):
    token: str = Field(min_length=20, max_length=200)


class LoginRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class ApprovalKeyRecoveryRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)
