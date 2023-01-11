from pydantic import BaseModel


class CashuError(BaseModel):
    code: int
    error: str


class MintException(CashuError):
    code = 100
    error = "Mint"


class LightningException(MintException):
    code = 200
    error = "Lightning"


class InvoiceNotPaidException(LightningException):
    code = 201
    error = "invoice not paid."
