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


class OrganizationCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)

class OrganizationInvitationRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    role: str = Field(min_length=3, max_length=30)
    expires_in_seconds: int = Field(
        default=604800,
        ge=60,
        le=2592000
    )

class OrganizationInvitationAcceptRequest(BaseModel):
    token: str = Field(min_length=20, max_length=200)

