import json
import os
from decimal import Decimal, InvalidOperation
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


class NearMarketError(Exception):
    """Raised when NEAR market data cannot be retrieved."""


class NearMarketClient:

    API_URL = (
        "https://api.coingecko.com/api/v3/coins/markets"
        "?vs_currency=usd"
        "&ids=near"
        "&price_change_percentage=24h"
    )

    def __init__(self, timeout=15):
        self.timeout = timeout

    def get_market_data(self):

        headers = {
            "Accept": "application/json",
            "User-Agent": "AgentGuardAI/1.0"
        }

        api_key = os.getenv("COINGECKO_API_KEY")

        if api_key:
            headers["x-cg-demo-api-key"] = api_key

        request = Request(
            self.API_URL,
            headers=headers,
            method="GET"
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                result = json.loads(
                    response.read().decode("utf-8")
                )

        except HTTPError as error:
            raise NearMarketError(
                f"Market API HTTP error: {error.code}"
            ) from error

        except (URLError, TimeoutError, OSError) as error:
            raise NearMarketError(
                "Unable to connect to market data provider"
            ) from error

        except json.JSONDecodeError as error:
            raise NearMarketError(
                "Invalid market data response"
            ) from error

        if not isinstance(result, list) or not result:
            raise NearMarketError(
                "NEAR market data is unavailable"
            )

        coin = result[0]

        try:
            price = Decimal(str(coin["current_price"]))
            volume = Decimal(str(coin["total_volume"]))
            change = Decimal(
                str(coin["price_change_percentage_24h"])
            )

            if not all(value.is_finite() for value in (
                price, volume, change
            )):
                raise ValueError("Invalid market numbers")

            if price < 0 or volume < 0:
                raise ValueError("Negative market values")

        except (KeyError, TypeError, ValueError,
                InvalidOperation) as error:
            raise NearMarketError(
                "Invalid NEAR market data"
            ) from error

        return {
            "asset": "NEAR",
            "currency": "USD",
            "price": float(price),
            "volume_24h": float(volume),
            "price_change_24h_percent": float(change),
            "last_updated": coin.get("last_updated"),
            "source": "CoinGecko"
        }

    def get_large_buys(self):

        pool_address = (
            "refv2-17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1:wrap.near:100"
        )

        usdc_address = (
            "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1"
        )

        url = (
            "https://api.geckoterminal.com/api/v2/"
            f"networks/near/pools/{pool_address}/trades"
        )

        request = Request(
            url,
            headers={
                "Accept": "application/json;version=20230203",
                "User-Agent": "AgentGuardAI/1.0"
            },
            method="GET"
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                result = json.loads(response.read().decode("utf-8"))

        except (HTTPError, URLError, TimeoutError, OSError) as error:
            raise NearMarketError(
                "Unable to retrieve NEAR trade data"
            ) from error

        except json.JSONDecodeError as error:
            raise NearMarketError(
                "Invalid trade data response"
            ) from error

        if not isinstance(result, dict):
            raise NearMarketError("Invalid trade data")

        trades = result.get("data")

        if not isinstance(trades, list):
            raise NearMarketError("Invalid trade data")

        buys = []

        for trade in trades:
            if not isinstance(trade, dict):
                continue

            attributes = trade.get("attributes", {})

            if not isinstance(attributes, dict):
                continue

            try:
                if (
                    attributes.get("kind") != "sell"
                    or attributes.get("from_token_address") != usdc_address
                    or attributes.get("to_token_address") != "wrap.near"
                ):
                    continue

                usd_value = Decimal(str(attributes["volume_in_usd"]))
                near_amount = Decimal(str(attributes["to_token_amount"]))

                if (
                    not usd_value.is_finite()
                    or not near_amount.is_finite()
                    or usd_value < 0
                    or near_amount <= 0
                ):
                    continue

                tx_hash = attributes["tx_hash"]

                if not tx_hash:
                    continue

                buys.append({
                    "asset": "NEAR",
                    "direction": "BUY",
                    "near_amount": float(near_amount),
                    "usd_value": float(usd_value),
                    "wallet": attributes.get("tx_from_address"),
                    "timestamp": attributes.get("block_timestamp"),
                    "transaction_hash": tx_hash,
                    "transaction_url": f"https://nearblocks.io/txns/{tx_hash}",
                    "source": "GeckoTerminal",
                    "pool": "Ref Finance USDC/wNEAR"
                })

            except (KeyError, TypeError, ValueError, InvalidOperation):
                continue

        if not buys:
            return []

        return [max(buys, key=lambda buy: buy["usd_value"])]


