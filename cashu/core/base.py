from sqlite3 import Row
from typing import Any, Dict, List, Optional, TypedDict, Union

from pydantic import BaseModel

from cashu.core.crypto import derive_keys, derive_keyset_id, derive_pubkeys
from cashu.core.secp import PrivateKey, PublicKey


class P2SHScript(BaseModel):
    script: str
    signature: str
    address: Union[str, None] = None


class Proof(BaseModel):
    id: Union[
        None, str
    ] = ""  # NOTE: None for backwards compatibility of old clients < 0.3
    amount: int = 0
    secret: str = ""
    C: str = ""
    script: Union[P2SHScript, None] = None
    reserved: Union[None, bool] = False  # whether this proof is reserved for sending
    send_id: Union[None, str] = ""  # unique ID of send attempt
    time_created: Union[None, str] = ""
    time_reserved: Union[None, str] = ""

    def to_dict(self):
        return dict(id=self.id, amount=self.amount, secret=self.secret, C=self.C)

    def to_dict_no_secret(self):
        return dict(id=self.id, amount=self.amount, C=self.C)

    def __getitem__(self, key):
        return self.__getattribute__(key)

    def __setitem__(self, key, val):
        self.__setattr__(key, val)


class Proofs(BaseModel):
    """TODO: Use this model"""

    proofs: List[Proof]


class Invoice(BaseModel):
    amount: int
    pr: str
    hash: Union[None, str] = None
    preimage: Union[str, None] = None
    issued: Union[None, bool] = False
    paid: Union[None, bool] = False
    time_created: Union[None, str, int, float] = ""
    time_paid: Union[None, str, int, float] = ""


class BlindedMessage(BaseModel):
    amount: int
    B_: str


class BlindedSignature(BaseModel):
    id: Union[str, None] = None
    amount: int
    C_: str


class KeysResponse(BaseModel):
    __root__: Dict[str, str]


class KeysetsResponse(BaseModel):
    keysets: list[str]


class BlindedMessages(BaseModel):
    blinded_messages: List[BlindedMessage] = []


class PostMintResponse(BaseModel):
    promises: List[BlindedSignature] = []


class GetMintResponse(BaseModel):
    pr: str
    hash: str


class GetMeltResponse(BaseModel):
    paid: Union[bool, None]
    preimage: Union[str, None]


class SplitRequest(BaseModel):
    proofs: List[Proof]
    amount: int
    output_data: Union[
        BlindedMessages, None
    ] = None  # backwards compatibility with clients < v0.2.2
    outputs: Union[BlindedMessages, None] = None

    def __init__(self, **data):
        super().__init__(**data)
        self.backwards_compatibility_v021()

    def backwards_compatibility_v021(self):
        # before v0.2.2: output_data, after: outputs
        if self.output_data:
            self.outputs = self.output_data
            self.output_data = None


class PostSplitResponse(BaseModel):
    fst: List[BlindedSignature]
    snd: List[BlindedSignature]


class CheckRequest(BaseModel):
    proofs: List[Proof]


class CheckFeesRequest(BaseModel):
    pr: str


class CheckFeesResponse(BaseModel):
    fee: Union[int, None]


class MeltRequest(BaseModel):
    proofs: List[Proof]
    invoice: str


class KeyBase(BaseModel):
    id: str
    amount: int
    pubkey: str


class WalletKeyset:
    id: Union[str, None]
    public_keys: Union[Dict[int, PublicKey], None]
    mint_url: Union[str, None] = None
    valid_from: Union[str, None] = None
    valid_to: Union[str, None] = None
    first_seen: Union[str, None] = None
    active: Union[bool, None] = True

    def __init__(
        self,
        public_keys=None,
        mint_url=None,
        id=None,
        valid_from=None,
        valid_to=None,
        first_seen=None,
        active=None,
    ):
        self.id = id
        self.valid_from = valid_from
        self.valid_to = valid_to
        self.first_seen = first_seen
        self.active = active
        self.mint_url = mint_url
        if public_keys:
            self.public_keys = public_keys
            self.id = derive_keyset_id(self.public_keys)


class MintKeyset:
    id: Union[str, None]
    derivation_path: str
    private_keys: Dict[int, PrivateKey]
    public_keys: Union[Dict[int, PublicKey], None] = None
    valid_from: Union[str, None] = None
    valid_to: Union[str, None] = None
    first_seen: Union[str, None] = None
    active: Union[bool, None] = True
    version: Union[str, None] = None

    def __init__(
        self,
        id=None,
        valid_from=None,
        valid_to=None,
        first_seen=None,
        active=None,
        seed: str = "",
        derivation_path: str = "",
        version: str = "",
    ):
        self.derivation_path = derivation_path
        self.id = id
        self.valid_from = valid_from
        self.valid_to = valid_to
        self.first_seen = first_seen
        self.active = active
        self.version = version
        # generate keys from seed
        if seed:
            self.generate_keys(seed)

    def generate_keys(self, seed):
        """Generates keys of a keyset from a seed."""
        self.private_keys = derive_keys(seed, self.derivation_path)
        self.public_keys = derive_pubkeys(self.private_keys)  # type: ignore
        self.id = derive_keyset_id(self.public_keys)  # type: ignore

    def get_keybase(self):
        assert self.id is not None
        return {
            k: KeyBase(id=self.id, amount=k, pubkey=v.serialize().hex())
            for k, v in self.public_keys.items()  # type: ignore
        }


class MintKeysets:
    keysets: Dict[str, MintKeyset]

    def __init__(self, keysets: List[MintKeyset]):
        self.keysets = {k.id: k for k in keysets}  # type: ignore

    def get_ids(self):
        return [k for k, _ in self.keysets.items()]


class TokenMintJson(BaseModel):
    url: str
    ks: List[str]


class TokenJson(BaseModel):
    tokens: List[Proof]
    mints: Optional[Dict[str, TokenMintJson]] = None

    def to_dict(self):
        return dict(
            tokens=[p.to_dict() for p in self.tokens],
            mints={k: v.dict() for k, v in self.mints.items()},  # type: ignore
        )
