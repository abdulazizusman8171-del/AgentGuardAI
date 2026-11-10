import json
import unittest
from unittest.mock import patch, MagicMock
from urllib.error import URLError

from app.near_market import NearMarketClient, NearMarketError


class TestNearMarketClient(unittest.TestCase):

    def setUp(self):
        self.client = NearMarketClient()

    def mock_response(self, data):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = (
            json.dumps(data).encode("utf-8")
        )
        return response

    @patch("app.near_market.urlopen")
    def test_get_market_data_success(self, mock_urlopen):
        mock_urlopen.return_value = self.mock_response([{
            "current_price": 2.50,
            "total_volume": 15000000,
            "price_change_percentage_24h": 4.5,
            "last_updated": "2026-11-10T12:00:00.000Z"
        }])

        result = self.client.get_market_data()

        self.assertEqual(result["asset"], "NEAR")
        self.assertEqual(result["price"], 2.50)
        self.assertEqual(result["volume_24h"], 15000000)
        self.assertEqual(result["price_change_24h_percent"], 4.5)
        self.assertEqual(result["source"], "CoinGecko")

    @patch("app.near_market.urlopen")
    def test_invalid_market_response(self, mock_urlopen):
        mock_urlopen.return_value = self.mock_response([])

        with self.assertRaises(NearMarketError):
            self.client.get_market_data()

    @patch("app.near_market.urlopen")
    def test_market_connection_failure(self, mock_urlopen):
        mock_urlopen.side_effect = URLError("Connection failed")

        with self.assertRaises(NearMarketError):
            self.client.get_market_data()

    def make_trade(self, usd_value=6000, kind="sell",
                   from_token="17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1",
                   to_token="wrap.near"):
        return {
            "type": "trade",
            "attributes": {
                "kind": kind,
                "from_token_address": from_token,
                "to_token_address": to_token,
                "volume_in_usd": str(usd_value),
                "to_token_amount": "2000",
                "tx_hash": "example_transaction_hash",
                "tx_from_address": "example.near",
                "block_timestamp": "2026-11-10T12:00:00Z"
            }
        }

    @patch("app.near_market.urlopen")
    def test_detects_valid_large_near_buy(self, mock_urlopen):
        mock_urlopen.return_value = self.mock_response({
            "data": [self.make_trade()]
        })

        result = self.client.get_large_buys()

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["direction"], "BUY")
        self.assertEqual(result[0]["near_amount"], 2000)
        self.assertEqual(result[0]["usd_value"], 6000)
        self.assertEqual(result[0]["wallet"], "example.near")

    @patch("app.near_market.urlopen")
    def test_accepts_buys_below_old_threshold(self, mock_urlopen):
        mock_urlopen.return_value = self.mock_response({
            "data": [self.make_trade(usd_value=4999)]
        })

        result = self.client.get_large_buys()

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["usd_value"], 4999)

    @patch("app.near_market.urlopen")
    def test_returns_only_largest_buy(self, mock_urlopen):
        mock_urlopen.return_value = self.mock_response({
            "data": [
                self.make_trade(usd_value=4999),
                self.make_trade(usd_value=6000),
                self.make_trade(usd_value=9000)
            ]
        })

        result = self.client.get_large_buys()

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["usd_value"], 9000)

    @patch("app.near_market.urlopen")
    def test_ignores_wrong_trade_direction(self, mock_urlopen):
        mock_urlopen.return_value = self.mock_response({
            "data": [self.make_trade(kind="buy")]
        })

        result = self.client.get_large_buys()

        self.assertEqual(result, [])

    @patch("app.near_market.urlopen")
    def test_rejects_malformed_trade_data(self, mock_urlopen):
        mock_urlopen.return_value = self.mock_response({
            "data": "invalid"
        })

        with self.assertRaises(NearMarketError):
            self.client.get_large_buys()
    @patch("app.near_market.urlopen")
    def test_large_buy_connection_failure(self, mock_urlopen):
        mock_urlopen.side_effect = URLError("Connection failed")

        with self.assertRaises(NearMarketError):
            self.client.get_large_buys()


if __name__ == "__main__":
    unittest.main()


