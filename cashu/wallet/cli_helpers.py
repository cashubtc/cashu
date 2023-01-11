import os
import urllib.parse

import click

from cashu.core.base import Proof, TokenJson, TokenMintJson, WalletKeyset
from cashu.core.settings import CASHU_DIR, MINT_URL
from cashu.wallet.crud import get_keyset
from cashu.wallet.wallet import Wallet as Wallet


async def verify_mints(ctx, dtoken):
    trust_token_mints = True
    for mint_id in dtoken.get("mints"):
        for keyset in set(dtoken["mints"][mint_id]["ks"]):
            mint_url = dtoken["mints"][mint_id]["url"]
            # init a temporary wallet object
            keyset_wallet = Wallet(
                mint_url, os.path.join(CASHU_DIR, ctx.obj["WALLET_NAME"])
            )
            # make sure that this mint supports this keyset
            mint_keysets = await keyset_wallet._get_keyset_ids(mint_url)
            assert keyset in mint_keysets["keysets"], "mint does not have this keyset."

            # we validate the keyset id by fetching the keys from the mint
            mint_keyset = await keyset_wallet._get_keyset(mint_url, keyset)
            assert keyset == mint_keyset.id, Exception("keyset not valid.")

            # we check the db whether we know this mint already and ask the user if not
            mint_keysets = await get_keyset(mint_url=mint_url, db=keyset_wallet.db)
            if mint_keysets is None:
                # we encountered a new mint and ask for a user confirmation
                trust_token_mints = False
                print("")
                print("Warning: Tokens are from a mint you don't know yet.")
                print("\n")
                print(f"Mint URL: {mint_url}")
                print(f"Mint keyset: {keyset}")
                print("\n")
                click.confirm(
                    f"Do you trust this mint and want to receive the tokens?",
                    abort=True,
                    default=True,
                )
                trust_token_mints = True

    assert trust_token_mints, Exception("Aborted!")


async def redeem_multimint(ctx, dtoken, script, signature):
    # we get the mint information in the token and load the keys of each mint
    # we then redeem the tokens for each keyset individually
    for mint_id in dtoken.get("mints"):
        for keyset in set(dtoken["mints"][mint_id]["ks"]):
            mint_url = dtoken["mints"][mint_id]["url"]
            # init a temporary wallet object
            keyset_wallet = Wallet(
                mint_url, os.path.join(CASHU_DIR, ctx.obj["WALLET_NAME"])
            )

            # load the keys
            await keyset_wallet.load_mint(keyset_id=keyset)

            # redeem proofs of this keyset
            redeem_proofs = [
                Proof(**p) for p in dtoken["tokens"] if Proof(**p).id == keyset
            ]
            _, _ = await keyset_wallet.redeem(
                redeem_proofs, scnd_script=script, scnd_siganture=signature
            )


async def print_mint_balances(ctx, wallet, show_mints=False):
    # get balances per mint
    mint_balances = await wallet.balance_per_minturl()

    # if we have a balance on a non-default mint, we show its URL
    keysets = [k for k, v in wallet.balance_per_keyset().items()]
    for k in keysets:
        ks = await get_keyset(id=str(k), db=wallet.db)
        if ks and ks.mint_url != ctx.obj["HOST"]:
            show_mints = True

    # or we have a balance on more than one mint
    # show balances per mint
    if len(mint_balances) > 1 or show_mints:
        print(f"You have balances in {len(mint_balances)} mints:")
        print("")
        for i, (k, v) in enumerate(mint_balances.items()):
            print(
                f"Mint {i+1}: Balance: {v['available']} sat (pending: {v['balance']-v['available']} sat) URL: {k}"
            )
        print("")


async def get_mint_wallet(ctx):
    wallet: Wallet = ctx.obj["WALLET"]
    await wallet.load_mint()

    mint_balances = await wallet.balance_per_minturl()

    if len(mint_balances) > 1:
        await print_mint_balances(ctx, wallet, show_mints=True)

        mint_nr_str = (
            input(f"Select mint [1-{len(mint_balances)}, press enter for default 1]: ")
            or "1"
        )
        if not mint_nr_str.isdigit():
            raise Exception("invalid input.")
        mint_nr = int(mint_nr_str)
    else:
        mint_nr = 1

    mint_url = list(mint_balances.keys())[mint_nr - 1]

    # load this mint_url into a wallet
    mint_wallet = Wallet(mint_url, os.path.join(CASHU_DIR, ctx.obj["WALLET_NAME"]))
    mint_keysets: WalletKeyset = await get_keyset(mint_url=mint_url, db=mint_wallet.db)  # type: ignore

    # load the keys
    assert mint_keysets.id
    await mint_wallet.load_mint(keyset_id=mint_keysets.id)

    return mint_wallet


# LNbits token link parsing
# can extract minut URL from LNbits token links like:
# https://lnbits.server/cashu/wallet?mint_id=aMintId&recv_token=W3siaWQiOiJHY2...
def token_from_lnbits_link(link):
    url, token = "", ""
    if len(link.split("&recv_token=")) == 2:
        # extract URL params
        params = urllib.parse.parse_qs(link.split("?")[1])
        # extract URL
        if "mint_id" in params:
            url = (
                link.split("?")[0].split("/wallet")[0]
                + "/api/v1/"
                + params["mint_id"][0]
            )
        # extract token
        token = params["recv_token"][0]
        return token, url
    else:
        return link, ""


async def proofs_to_token(wallet, proofs, url: str):
    """
    Ingests proofs and
    """
    # and add url and keyset id to token
    token: TokenJson = await wallet._make_token(proofs, include_mints=False)
    token.mints = {}

    # get keysets of proofs
    keysets = list(set([p.id for p in proofs]))
    assert keysets is not None, "no keysets"

    # check whether we know the mint urls for these proofs
    for k in keysets:
        ks = await get_keyset(id=k, db=wallet.db)
        url = ks.mint_url if ks and ks.mint_url else ""

    url = url or (
        input(f"Enter mint URL (press enter for default {MINT_URL}): ") or MINT_URL
    )

    token.mints[url] = TokenMintJson(url=url, ks=keysets)  # type: ignore
    token_serialized = await wallet._serialize_token_base64(token)
    return token_serialized
