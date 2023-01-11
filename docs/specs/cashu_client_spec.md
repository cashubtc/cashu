# Notation

Sending user: `Alice`
Receivung user: `Carol`
Mint: `Bob`

## Bob (mint)
- `k` private key of mint (one for each amount)
- `K` public key of mint
- `Q` promise (blinded signature)

## Alice (user)
- `x` random string (secret message), corresponds to point `Y` on curve
- `r` private key (blinding factor)
- `T` blinded message
- `Z` proof (unblinded signature)

# Blind Diffie-Hellmann key exchange (BDH)
-   Mint `Bob` publishes `K = kG` 
-   `Alice` picks secret `x` and computes `Y = hash_to_curve(x)` 
-   `Alice` sends to `Bob`: `T = Y + rG` with `r` being a random nonce
-   `Bob` sends back to `Alice` blinded key: `Q = kT` (these two steps are the DH key exchange)
-   `Alice` can calculate the unblinded key as `Q - rK = kY + krG - krG = kY = Z`
-   Alice can take the pair `(x, Z)` as a token and can send it to `Carol`.
-   `Carol` can send `(x, Z)` to `Bob` who then checks that `k*hash_to_curve(x) == Z`, and if so treats it as a valid spend of a token, adding `x`  to the list of spent secrets.

# Cashu client protocol

## 1 - Request public keys from mint

`Alice` receives public keys from mint `Bob` via `GET /keys` and stores them in a key-value store like a dictionary. Keys are received as a JSON of the form `{<amount_1> : <mint_pubkey_1>, <amount_2> : ...}` for each `<amount_i>` of the amounts the mint `Bob` supports. [NOTE: `mint_pubkey` should be consistent with the notation above.]

## 2 - Mint tokens

### Step 1: `Alice` requests mint
- `Alice` requests the minting of tokens of value `amount : int` via `GET /mint?amount=<amount>` 
- `Bob` responds with a JSON `{"pr": <payment_request>, "hash": <payment_hash>}` where `payment_request` is the bolt11 Lightning invoice that `Alice` needs to pay and `payment_hash` is the hash of the invoice necessary for alice to request minting of tokens later. `Alice` stores `payment_hash`. [NOTE: <payment_hash> does not need to be passed by Bob, can be derived from <payment_request>]
- `Alice` pays bolt11 invoice `payment_request` using a Bitcoin Lightning wallet.

### Step 2: Request tokens
- To request tokens of value `amount : int`, `Alice` decomposes `amount` into a sum of values of `2^n`, e.g. `13` is `amounts : List[int] = [1, 4, 8]`. This can be easily done by representing `amount` as binary and using each binary digit that is `1` as part of the sum, e.g. `13` would be `1101` wich is `2^0 + 2^2 + 2^3`. In this example, `Alice` will request `N = len(amounts) = 3` tokens.
- `Alice` generates a random secret string `x_i` of `128` random bits with `i \in [0,..,N-1]`for each of the `N` requested tokens and encodes them in `base64`. [*TODO: remove index i*]
- `Alice` remembers `x` for the construction of the proof in Step 5.

### Step 3: Generate blinded message
Here we see how `Alice` generates `N` blinded messages `T_i`. The following steps are executed for each of the `N` tokens that `Alice` requests. The index `i` is dropped for simplicity. [*TODO: either write everything independent of i or not, don't mix*]
- `Alice` generates a point `Y` on the elliptic curve from the secret `x` using the deterministic function `Y = hash_to_curve(hash(x : string)) : Point`. 
- `h = hash(x : string) : string` can be the `SHA256` hash function.
- `Y = hash_to_curve(h :  string) : Point` verifies that `Y` is an element of the elliptic curve.
- `Alice` generates a random nonce `r : int` that is a private key and computes the public key from it using `r*G`.
- `Alice` generates the blinded message `T = Y + r*G`
- `Alice` remembers `r` for the construction of the proof in Step 5.

### Step 4: Request tokens
- `Alice` constructs JSON `BlindedMessages = {"blinded_messages" : ["amount" : <amount>, "B_" : <blinded_message>] }` [NOTE: rename "blinded_messages", rename "B_", rename "BlindedMessages"] 
- `Alice` requests tokens via `POST /mint?payment_hash=<payment_hash>` with body `BlindedMessages` [NOTE: rename BlindedMessages]
- `Alice` receives from `Bob` a list of blinded signatures `List[BlindedSignature]`, one for each token, e.g. `[{"amount" : <amount>, "C_" : <blinded_signature>}, ...]` [NOTE: rename C_]
- If an error occured, `Alice` receives JSON `{"error" : <error_reason>}}`[*TODO: Specify case of error*]

### Step 5: Construct proofs
Here, `Alice` construct proofs for each token using the tuple `(blinded_signature, r, s)`. Again, all steps are repeated for each token separately but we show it here for only one token.
- `Alice` unblinds `blinded_signature` by subtracting `r*<mint_pubkey>` from it. Note that `<mint_pubkey>` must be according to the `<amount>` of the token. The result is the proof `Z`. [Note: in notation, this is Z = Q - r*K]
- `Alice` constructs spendable token as a tuple `(<amount>, Z, s)` and stores it in her database. 

## 3 - Send tokens
Here we describe how `Alice` sends tokens to `Carol`.

### 3.1 – Split tokens to desired amount
`Alice` wants to send tokens of total value `<total>` to `Carol` but doesn't necessarily have a set of tokens that sum to `<total>`. Say `Alice` has tokens of the amount `<alice_balance>` which is greater than `<total>` in here database. Note that `<alice_balance>` does not need to include all of `Alice`'s tokens but only at least tokens of a total amount of `<total>`. Therefore, `Alice` sends tokens of amount `<alice_balance>` to `Bob` asks `Bob` to issue two new sets of tokens of value `<total>` and `<alice_balance>-<total>` each.
- `Alice` performs a split on the amounts `<total>` and `<alice_balance>-<total>` separately as in 2.2 - Request tokens. [*TODO: fix reference*]
- `Alice` constructs two new sets of blinded messages like in 2.3 - Generate blind messages [*TODO: fix reference*], one for each of the two amounts `<total>` and `<alice_balance>-<total>`.
- `Alice` concatenates both sets of blinded messages into the list `<blinded_messages>` [*TODO: list?*]
- `Alice` constructs a JSON out of multiple tokens from her database that sum to `<alice_balance>` of the form `{"amount" : <total>, "proofs" : [{"amount" : <amount>, "secret" : s, "C" : Z}, ...], "outputs" : ["amount" : <amount>, "B_" : <blinded_message>]}`. The blinded messages in `"outputs"` are the list of concatenated blinded message from the previous step. [*TODO: refer to this as BlindMessages or something and reuse in Section 4 and 2*]

### 3.2 - Request new tokens for sending
- `Alice` constructs a JSON out of multiple tokens of the form `[{"amount" : <amount>, "secret" : s, "C" : Z}, ...]` and serializes is as a Base64 string `TOKEN` which is then sent to `Carol` as a payment of value `sum(<amount_i>)`. [*NOTE: rename C, rewrite sum, find consistency in writing labels, values, TOKEN, in code this is called `Proof`*]
- `Alice` requests new tokens via `POST /mint` with the JSON as the body of the request.
- `Alice` receives a JSON of the form `{"fst" : <signatures_to_keep>}, "snd" : <signatures_to_send>` with both entries being of the type `List[BlindedSignature]`. `Alice` constructs proofs `<keep_proofs>` and `<send_proofs>` from both of these entries like in Step 2.5 [TODO: fix reference]. 
- `Alice` stores the proofs `<keep_proofs>` and `<send_proofs>` in her database and flags `<send_proofs>` as `pending` (for example in a separate column).
- `Alice` may also give the set of `<send_proofs>` a unique ID `send_id` so that she can later connect each set of pending tokens with every send attempt.

### 3.3 - Serialize tokens for sending
Here, `Alice` serializes the proofs from the set `<send_proofs>` for sending to `Carol`.
- `Alice` constructs a JSON of the form `[{"amount" : <amount>, "secret" : s, "C" : Z}, ...]` from `<send_proofs>` and encodes it as a Base64 string using url-safe Base64 encoder. [*NOTE: it probably doesn't need to be url-safe, maybe it shouldn't if this is not widespread or consistent across languages*]
- `Alice` sends the resulting `TOKEN` as the string `W3siYW1vdW50IjogMiwgInNlY3...` to `Carol`.

## 4 - Receive new tokens
Here we describe how `Carol` can redeem new tokens from `Bob` that she previously received from `Alice`. `Carol` receives tokens as a url-safe [*NOTE: remove url-safe?*] base64-encoded string `TOKEN` that, when decoded, is a JSON of the form `[{"amount" : <amount>, "secret" : s, "C" : Z}, ...]`. In the following, we will refer to the tuple `(<amount>, Z, s)` as a single token. [*NOTE: clarify whether a TOKEN is a single token or a list of tokens*] To redeem a token, `Carol` sends it to `Bob` and receives a one of the same value.

`Carol` essentially performs the same procedure to receive tokens as `Alice` did earlier when she prepared her tokens for sending: She sends constructs new blinded messages and sends them together with the tokens she received in order to receive a newly-issued set of tokens which settles the transaction between `Alice` and `Carol`.

Note that the following steps can also be performed by `Alice` herself if she wants to cancel the pending token transfer and claim them for herself.

- `Carol` constructs a list of `<blinded_message>`'s each with the same amount as the list list of tokens that she received. This can be done by the same procedure as during the minting of new tokens in Section 2 [*TODO: update ref*] or during sending in Section 3 [*TODO: update ref*] since the splitting into amounts is deterministic.
- `Carol` performs the same steps as `Alice` when she split the tokens before sending it to her and calls the endpoint `POIT /split` with the JSON `SplitRequests` as the body of the request.

## 5 - Burn sent tokens
Here we describe how `Alice` checks with the mint whether the tokens she sent `Carol` have been redeemed so she can safely delete them from her database. This step is optional but highly recommended so `Alice` can properly account for the tokens and adjust her balance accordingly.
- `Alice` loads all `<send_proofs>` with `pending=True` from her database and might group them by the `send_id`.
- `Alice` constructs a JSON of the form `{"proofs" : [{"amount" : <amount>, "secret" : s, "C" : Z}, ...]}` from these (grouped) tokens. [*TODO: this object is called CheckRequest*]
- `Alice` sends them to the mint `Bob` via the endpoint `POST /check` with the JSON as the body of the request.
- `Alice` receives a JSON of the form `{"1" : <spendable : bool>, "2" : ...}` where `"1"` is the index of the proof she sent to the mint before and `<spendable>` is a boolean that is `True` if the token has not been claimed yet by `Carol` and `False` if it has already been claimed.
- If `<spendable>` is `False`, `Alice` removes the proof [*NOTE: consistent name?*] from her list of spendable proofs.

## 6 - Pay a Lightning invoice
Here we describe how `Alice` can request from `Bob` to make a Lightning payment for her and burn an appropriate amount of tokens in return. `Alice` wants to pay a bolt11 invoice with the amount `<invoice_amount>`. She has to add a fee to the request to account for the possible Lightning fees which results in a request with tokens with the total amount of `<total>`. 

- `Alice` wants to pay the bolt11 invoice `<invoice>`.
- `Alice` asks `Bob` for the Lightning fee via `GET /checkfee` with the body `CheckFeeRequest` being the json `{pr : <invoice>}`
- `Alice` receives the `CheckFeeResponse` in the form of the json `{"fee" : <fee>}` resulting in `<total> = <invoice_amount> + <fee>`.
- `Alice` now performs the same set of instructions as in Step 3.1 and 3.2 and splits her spendable tokens into a set `<keep_proofs>` that she keeps and and a set `<send_proofs>` with a sum of at least `<total>` that she can send for making the Lightning payment.
- `Alice` constructs the JSON `MeltRequest` of the form `{"proofs" : <List[Proof]>, "invoice" : <invoice>}` [*NOTE: Maybe use notation List[Proof] everywhere. Used MeltRequest here, maybe define each payload at the beginning of each section.*]
- `Alice` requests a payment from `Bob` via the endpoint `POST /melt` with the JSON as the body of the request.
- `Alice` receives a JSON of the form `{"paid" :  <status:bool>}` with `<status>` being `True` if the payment was successful and `False` otherwise.
- If `<status> == True`, `Alice` removes `<send_proofs>` from her database of spendable tokens [*NOTE: called it tokens again*]






# Todo:
- Call subsections 1. and 1.2 etc so they can be referenced
- Define objets like `BlindedMessages` and `SplitRequests` once when they appear and reuse them.
- Clarify whether a `TOKEN` is a single Proof or a list of Proofs
