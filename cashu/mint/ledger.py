"""
Implementation of https://gist.github.com/phyro/935badc682057f418842c72961cf096c
"""

import math
from typing import Dict, List, Set, Optional

from loguru import logger

import cashu.core.b_dhke as b_dhke
import cashu.core.bolt11 as bolt11
import cashu.core.legacy as legacy
from cashu.core.base import (
    BlindedMessage,
    BlindedSignature,
    Invoice,
    MintKeyset,
    MintKeysets,
    Proof,
)
from cashu.core.db import Database
from cashu.core.helpers import fee_reserve, sum_proofs
from cashu.core.script import verify_script
from cashu.core.secp import PublicKey
from cashu.core.settings import LIGHTNING, MAX_ORDER, VERSION
from cashu.core.split import amount_split
from cashu.mint.crud import LedgerCrud

# from starlette_context import context


class Ledger:
    def __init__(
        self,
        db: Database,
        seed: str,
        derivation_path="",
        crud=LedgerCrud,
        lightning=None,
    ):
        self.proofs_used: Set[str] = set()
        self.master_key = seed
        self.derivation_path = derivation_path

        self.db = db
        self.crud = crud
        self.lightning = lightning

    async def load_used_proofs(self):
        """Load all used proofs from database."""
        proofs_used = await self.crud.get_proofs_used(db=self.db)
        self.proofs_used = set(proofs_used)

    async def load_keyset(self, derivation_path, autosave=True):
        """Load current keyset keyset or generate new one."""
        keyset = MintKeyset(
            seed=self.master_key, derivation_path=derivation_path, version=VERSION
        )
        # check if current keyset is stored in db and store if not
        logger.trace(f"Loading keyset {keyset.id} from db.")
        tmp_keyset_local: List[MintKeyset] = await self.crud.get_keyset(
            id=keyset.id, db=self.db
        )
        if not len(tmp_keyset_local) and autosave:
            logger.trace(f"Storing keyset {keyset.id}.")
            await self.crud.store_keyset(keyset=keyset, db=self.db)

        # store the new keyset in the current keysets
        self.keysets.keysets[keyset.id] = keyset
        return keyset

    async def init_keysets(self, autosave=True):
        """Loads all keysets from db."""
        # load all past keysets from db
        tmp_keysets: List[MintKeyset] = await self.crud.get_keyset(db=self.db)
        self.keysets = MintKeysets(tmp_keysets)
        logger.trace(f"Loading {len(self.keysets.keysets)} keysets form db.")
        # generate all derived keys from stored derivation paths of past keysets
        for _, v in self.keysets.keysets.items():
            logger.trace(f"Generating keys for keyset {v.id}")
            v.generate_keys(self.master_key)
        # load the current keyset
        self.keyset = await self.load_keyset(self.derivation_path, autosave)

    async def _generate_promises(
        self, B_s: List[BlindedMessage], keyset: MintKeyset = None
    ):
        """Generates promises that sum to the given amount."""
        return [
            await self._generate_promise(
                b.amount, PublicKey(bytes.fromhex(b.B_), raw=True), keyset
            )
            for b in B_s
        ]

    async def _generate_promise(
        self, amount: int, B_: PublicKey, keyset: MintKeyset = None
    ):
        """Generates a promise for given amount and returns a pair (amount, C')."""
        keyset = keyset if keyset else self.keyset
        private_key_amount = keyset.private_keys[amount]
        C_ = b_dhke.step2_bob(B_, private_key_amount)
        await self.crud.store_promise(
            amount=amount, B_=B_.serialize().hex(), C_=C_.serialize().hex(), db=self.db
        )
        return BlindedSignature(id=keyset.id, amount=amount, C_=C_.serialize().hex())

    def _check_spendable(self, proof: Proof):
        """Checks whether the proof was already spent."""
        return not proof.secret in self.proofs_used

    def _verify_secret_criteria(self, proof: Proof):
        """Verifies that a secret is present and is not too long (DOS prevention)."""
        if proof.secret is None or proof.secret == "":
            raise Exception("no secret in proof.")
        if len(proof.secret) > 64:
            raise Exception("secret too long.")
        return True

    def _verify_proof_bdhke(self, proof: Proof):
        """Verifies that the proof of promise was issued by this ledger."""
        if not self._check_spendable(proof):
            raise Exception(f"tokens already spent. Secret: {proof.secret}")
        # if no keyset id is given in proof, assume the current one
        if not proof.id:
            private_key_amount = self.keyset.private_keys[proof.amount]
        else:
            # use the appropriate active keyset for this proof.id
            private_key_amount = self.keysets.keysets[proof.id].private_keys[
                proof.amount
            ]

        C = PublicKey(bytes.fromhex(proof.C), raw=True)

        # backwards compatibility with old hash_to_curve < 0.4.0
        try:
            ret = legacy.verify_pre_0_3_3(private_key_amount, C, proof.secret)
            if ret:
                return ret
        except:
            pass

        return b_dhke.verify(private_key_amount, C, proof.secret)

    def _verify_script(self, idx: int, proof: Proof):
        """
        Verify bitcoin script in proof.script commited to by <address> in proof.secret.
        proof.secret format: P2SH:<address>:<secret>
        """
        # if no script is given
        if (
            proof.script is None
            or proof.script.script is None
            or proof.script.signature is None
        ):
            if len(proof.secret.split("P2SH:")) == 2:
                # secret indicates a script but no script is present
                return False
            else:
                # secret indicates no script, so treat script as valid
                return True
        # execute and verify P2SH
        txin_p2sh_address, valid = verify_script(
            proof.script.script, proof.script.signature
        )
        if valid:
            # check if secret commits to script address
            # format: P2SH:<address>:<secret>
            assert len(proof.secret.split(":")) == 3, "secret format wrong."
            assert proof.secret.split(":")[1] == str(
                txin_p2sh_address
            ), f"secret does not contain correct P2SH address: {proof.secret.split(':')[1]} is not {txin_p2sh_address}."
        return valid

    def _verify_outputs(self, total: int, amount: int, outputs: List[BlindedMessage]):
        """Verifies the expected split was correctly computed"""
        frst_amt, scnd_amt = total - amount, amount  # we have two amounts to split to
        frst_outputs = amount_split(frst_amt)
        scnd_outputs = amount_split(scnd_amt)
        expected = frst_outputs + scnd_outputs
        given = [o.amount for o in outputs]
        return given == expected

    def _verify_no_duplicate_proofs(self, proofs: List[Proof]):
        secrets = [p.secret for p in proofs]
        if len(secrets) != len(list(set(secrets))):
            return False
        return True

    def _verify_no_duplicate_outputs(self, outputs: List[BlindedMessage]):
        B_s = [od.B_ for od in outputs]
        if len(B_s) != len(list(set(B_s))):
            return False
        return True

    def _verify_split_amount(self, amount: int):
        """Split amount like output amount can't be negative or too big."""
        try:
            self._verify_amount(amount)
        except:
            # For better error message
            raise Exception("invalid split amount: " + str(amount))

    def _verify_amount(self, amount: int):
        """Any amount used should be a positive integer not larger than 2^MAX_ORDER."""
        valid = isinstance(amount, int) and amount > 0 and amount < 2**MAX_ORDER
        if not valid:
            raise Exception("invalid amount: " + str(amount))
        return amount

    def _verify_equation_balanced(
        self, proofs: List[Proof], outs: List[BlindedSignature]
    ):
        """Verify that Σoutputs - Σinputs = 0."""
        sum_inputs = sum(self._verify_amount(p.amount) for p in proofs)
        sum_outputs = sum(self._verify_amount(p.amount) for p in outs)
        assert sum_outputs - sum_inputs == 0

    async def _request_lightning_invoice(self, amount: int, description_hash: Optional[bytes] = None):
        """Returns an invoice from the Lightning backend."""

        error, balance = await self.lightning.status()
        if error:
            raise Exception(f"Lightning wallet not responding: {error}")
        (
            ok,
            checking_id,
            payment_request,
            error_message,
        ) = await self.lightning.create_invoice(amount, "cashu deposit",description_hash)
        return payment_request, checking_id

    async def _check_lightning_invoice(self, amount: int, payment_hash: str):
        """
        Checks with the Lightning backend whether an invoice with this payment_hash was paid.
        Raises exception if invoice is unpaid.
        """
        invoice: Invoice = await self.crud.get_lightning_invoice(
            hash=payment_hash, db=self.db
        )
        if invoice is None:
            raise Exception("invoice not found.")
        if invoice.issued:
            raise Exception("tokens already issued for this invoice.")

        # set this invoice as issued
        await self.crud.update_lightning_invoice(
            hash=payment_hash, issued=True, db=self.db
        )

        try:
            if amount > invoice.amount:
                raise Exception(
                    f"requested amount too high: {amount}. Invoice amount: {invoice.amount}"
                )

            status = await self.lightning.get_invoice_status(payment_hash)
            if status.paid:
                return status.paid
            else:
                raise Exception("Lightning invoice not paid yet.")
        except Exception as e:
            # unset issued
            await self.crud.update_lightning_invoice(
                hash=payment_hash, issued=False, db=self.db
            )
            raise e

    async def _pay_lightning_invoice(self, invoice: str, fees_msat: int):
        """Returns an invoice from the Lightning backend."""
        error, _ = await self.lightning.status()
        if error:
            raise Exception(f"Lightning wallet not responding: {error}")
        (
            ok,
            checking_id,
            fee_msat,
            preimage,
            error_message,
        ) = await self.lightning.pay_invoice(invoice, fee_limit_msat=fees_msat)
        return ok, preimage

    async def _invalidate_proofs(self, proofs: List[Proof]):
        """
        Adds secrets of proofs to the list of known secrets and stores them in the db.
        Removes proofs from pending table.
        """
        # Mark proofs as used and prepare new promises
        proof_msgs = set([p.secret for p in proofs])
        self.proofs_used |= proof_msgs
        # store in db
        for p in proofs:
            await self.crud.invalidate_proof(proof=p, db=self.db)

    async def _set_proofs_pending(self, proofs: List[Proof]):
        """
        If none of the proofs is in the pending table (_validate_proofs_pending), adds proofs to
        the list of pending proofs or removes them. Used as a mutex for proofs.
        """
        # first we check whether these proofs are pending aready
        await self._validate_proofs_pending(proofs)
        for p in proofs:
            try:
                await self.crud.set_proof_pending(proof=p, db=self.db)
            except:
                raise Exception("proofs already pending.")

    async def _unset_proofs_pending(self, proofs: List[Proof]):
        """Deletes proofs from pending table."""
        # we try: except: this block in order to avoid that any errors here
        # could block the _invalidate_proofs() call that happens afterwards.
        try:
            for p in proofs:
                await self.crud.unset_proof_pending(proof=p, db=self.db)
        except Exception as e:
            print(e)
            pass

    async def _validate_proofs_pending(self, proofs: List[Proof]):
        """Checks if any of the provided proofs is in the pending proofs table. Raises exception for at least one match."""
        proofs_pending = await self.crud.get_proofs_pending(db=self.db)
        for p in proofs:
            for pp in proofs_pending:
                if p.secret == pp.secret:
                    raise Exception("proofs are pending.")

    async def _verify_proofs(self, proofs: List[Proof]):
        """Checks a series of criteria for the verification of proofs."""
        # Verify scripts
        if not all([self._verify_script(i, p) for i, p in enumerate(proofs)]):
            raise Exception("script validation failed.")
        # Verify secret criteria
        if not all([self._verify_secret_criteria(p) for p in proofs]):
            raise Exception("secrets do not match criteria.")
        # verify that only unique proofs were used
        if not self._verify_no_duplicate_proofs(proofs):
            raise Exception("duplicate proofs.")
        # Verify proofs
        if not all([self._verify_proof_bdhke(p) for p in proofs]):
            raise Exception("could not verify proofs.")

    # Public methods
    def get_keyset(self, keyset_id: str = None):
        keyset = self.keysets.keysets[keyset_id] if keyset_id else self.keyset
        return {a: p.serialize().hex() for a, p in keyset.public_keys.items()}

    async def request_mint(self, amount, description_hash: Optional[bytes] = None):
        """Returns Lightning invoice and stores it in the db."""
        # description_hash = None
        payment_request, checking_id = await self._request_lightning_invoice(amount,description_hash)
        invoice = Invoice(
            amount=amount, pr=payment_request, hash=checking_id, issued=False
        )
        if not payment_request or not checking_id:
            raise Exception(f"Could not create Lightning invoice.")
        await self.crud.store_lightning_invoice(invoice=invoice, db=self.db)
        return payment_request, checking_id

    async def mint(
        self,
        B_s: List[BlindedMessage],
        payment_hash=None,
        keyset: MintKeyset = None,
    ):
        """Mints a promise for coins for B_."""
        amounts = [b.amount for b in B_s]
        amount = sum(amounts)
        # check if lightning invoice was paid
        if LIGHTNING:
            if not payment_hash:
                raise Exception("no payment_hash provided.")
            try:
                paid = await self._check_lightning_invoice(amount, payment_hash)
            except Exception as e:
                raise e

        for amount in amounts:
            if amount not in [2**i for i in range(MAX_ORDER)]:
                raise Exception(f"Can only mint amounts up to {2**MAX_ORDER}.")

        promises = await self._generate_promises(B_s, keyset)
        return promises

    async def melt(self, proofs: List[Proof], invoice: str):
        """Invalidates proofs and pays a Lightning invoice."""

        # validate and set proofs as pending
        await self._set_proofs_pending(proofs)

        try:
            await self._verify_proofs(proofs)

            total_provided = sum_proofs(proofs)
            invoice_obj = bolt11.decode(invoice)
            amount = math.ceil(invoice_obj.amount_msat / 1000)
            fees_msat = await self.check_fees(invoice)
            assert total_provided >= amount + fees_msat / 1000, Exception(
                "provided proofs not enough for Lightning payment."
            )

            if LIGHTNING:
                status, preimage = await self._pay_lightning_invoice(invoice, fees_msat)
            else:
                status, preimage = True, "preimage"
            if status == True:
                await self._invalidate_proofs(proofs)
        except Exception as e:
            raise e
        finally:
            # delete proofs from pending list
            await self._unset_proofs_pending(proofs)

        return status, preimage

    async def check_spendable(self, proofs: List[Proof]):
        """Checks if all provided proofs are valid and still spendable (i.e. have not been spent)."""
        return {i: self._check_spendable(p) for i, p in enumerate(proofs)}

    async def check_fees(self, pr: str):
        """Returns the fees (in msat) required to pay this pr."""
        decoded_invoice = bolt11.decode(pr)
        amount = math.ceil(decoded_invoice.amount_msat / 1000)
        # hack: check if it's internal, if it exists, it will return paid = False,
        # if id does not exist (not internal), it returns paid = None
        if LIGHTNING:
            paid = await self.lightning.get_invoice_status(decoded_invoice.payment_hash)
            internal = paid.paid == False
        else:
            internal = True
        fees_msat = fee_reserve(amount * 1000, internal)
        return fees_msat

    async def split(
        self,
        proofs: List[Proof],
        amount: int,
        outputs: List[BlindedMessage],
        keyset: MintKeyset = None,
    ):
        """Consumes proofs and prepares new promises based on the amount split."""

        # set proofs as pending
        await self._set_proofs_pending(proofs)

        total = sum_proofs(proofs)

        try:
            # verify that amount is kosher
            self._verify_split_amount(amount)
            # verify overspending attempt
            if amount > total:
                raise Exception("split amount is higher than the total sum.")

            await self._verify_proofs(proofs)

            # verify that only unique outputs were used
            if not self._verify_no_duplicate_outputs(outputs):
                raise Exception("duplicate promises.")
            # verify that outputs have the correct amount
            if not self._verify_outputs(total, amount, outputs):
                raise Exception("split of promises is not as expected.")
        except Exception as e:
            raise e
        finally:
            # delete proofs from pending list
            await self._unset_proofs_pending(proofs)

        # Mark proofs as used and prepare new promises
        await self._invalidate_proofs(proofs)

        # split outputs according to amount
        outs_fst = amount_split(total - amount)
        B_fst = [od for od in outputs[: len(outs_fst)]]
        B_snd = [od for od in outputs[len(outs_fst) :]]

        # generate promises
        prom_fst, prom_snd = await self._generate_promises(
            B_fst, keyset
        ), await self._generate_promises(B_snd, keyset)

        # verify amounts in produced proofs
        self._verify_equation_balanced(proofs, prom_fst + prom_snd)
        return prom_fst, prom_snd
