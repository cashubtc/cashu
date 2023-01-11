from os import getenv
from typing import Dict, Optional

import requests
import base64

from cashu.core.settings import LNBITS_ENDPOINT, LNBITS_KEY

from .base import (
    InvoiceResponse,
    PaymentResponse,
    PaymentStatus,
    StatusResponse,
    Wallet,
)


class LNbitsWallet(Wallet):
    """https://github.com/lnbits/lnbits"""

    def __init__(self):
        self.endpoint = LNBITS_ENDPOINT

        key = LNBITS_KEY
        self.key = {"X-Api-Key": key}
        self.s = requests.Session()
        self.s.auth = ("user", "pass")
        self.s.headers.update({"X-Api-Key": key})

    async def status(self) -> StatusResponse:
        try:
            r = self.s.get(url=f"{self.endpoint}/api/v1/wallet", timeout=15)
        except Exception as exc:
            return StatusResponse(
                f"Failed to connect to {self.endpoint} due to: {exc}", 0
            )

        try:
            data = r.json()
        except:
            return StatusResponse(
                f"Failed to connect to {self.endpoint}, got: '{r.text[:200]}...'", 0
            )
        if "detail" in data:
            return StatusResponse(f"LNbits error: {data['detail']}", 0)
        return StatusResponse(None, data["balance"])

    async def create_invoice(
        self,
        amount: int,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
        unhashed_description: Optional[bytes] = None,
    ) -> InvoiceResponse:
        print("lnbits description_hash:", description_hash)
        
        data: Dict = {"out": False, "amount": amount}
        
        print('description_hash', description_hash)
        
        # description_hash = None
        if description_hash:
            # This the fix - the decription_hash needs to be decoded
            data["description_hash"] = description_hash.decode() 
        if unhashed_description:
            data["unhashed_description"] = unhashed_description.hex()
        
        data["memo"] = memo or ""

        
        try:
            r = self.s.post(url=f"{self.endpoint}/api/v1/payments", json=data)
        except:
            return InvoiceResponse(False, None, None, r.json()["detail"])
        ok, checking_id, payment_request, error_message = (
            True,
            None,
            None,
            None,
        )
        
        data = r.json()
        
        checking_id, payment_request = data["checking_id"], data["payment_request"]
        

        return InvoiceResponse(ok, checking_id, payment_request, error_message)

    async def pay_invoice(self, bolt11: str, fee_limit_msat: int) -> PaymentResponse:
        try:
            r = self.s.post(
                url=f"{self.endpoint}/api/v1/payments",
                json={"out": True, "bolt11": bolt11},
                timeout=None,
            )
        except:
            error_message = r.json()["detail"]
            return PaymentResponse(None, None, None, None, error_message)
        if r.status_code > 299:
            return PaymentResponse(None, None, None, None, f"HTTP status: {r.reason}")
        if "detail" in r.json():
            return PaymentResponse(None, None, None, None, r.json()["detail"])
        ok, checking_id, fee_msat, preimage, error_message = (
            True,
            None,
            None,
            None,
            None,
        )

        data = r.json()
        checking_id = data["payment_hash"]

        # we do this to get the fee and preimage
        payment: PaymentStatus = await self.get_payment_status(checking_id)

        return PaymentResponse(ok, checking_id, payment.fee_msat, payment.preimage)

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        try:

            r = self.s.get(
                url=f"{self.endpoint}/api/v1/payments/{checking_id}",
                headers=self.key,
            )
        except:
            return PaymentStatus(None)
        if r.json().get("detail"):
            return PaymentStatus(None)
        return PaymentStatus(r.json()["paid"])

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        try:
            r = self.s.get(
                url=f"{self.endpoint}/api/v1/payments/{checking_id}", headers=self.key
            )
        except:
            return PaymentStatus(None)
        data = r.json()
        if "paid" not in data and "details" not in data:
            return PaymentStatus(None)

        return PaymentStatus(data["paid"], data["details"]["fee"], data["preimage"])

    # async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
    #     url = f"{self.endpoint}/api/v1/payments/sse"

    #     while True:
    #         try:
    #             async with requests.stream("GET", url) as r:
    #                 async for line in r.aiter_lines():
    #                     if line.startswith("data:"):
    #                         try:
    #                             data = json.loads(line[5:])
    #                         except json.decoder.JSONDecodeError:
    #                             continue

    #                         if type(data) is not dict:
    #                             continue

    #                         yield data["payment_hash"]  # payment_hash

    #         except:
    #             pass

    #         print("lost connection to lnbits /payments/sse, retrying in 5 seconds")
    #         await asyncio.sleep(5)
