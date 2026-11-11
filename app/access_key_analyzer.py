from decimal import Decimal, InvalidOperation


YOCTO_PER_NEAR = Decimal("1000000000000000000000000")


def analyze_access_key(key):
    """Produce an explainable risk assessment for one NEAR access key."""

    if not isinstance(key, dict):
        raise ValueError("Invalid access-key data")

    permission = key.get("permission")
    public_key = key.get("public_key")

    if not isinstance(public_key, str) or not public_key:
        raise ValueError("Invalid public key")

    reasons = []
    recommendations = []
    allowance_near = None
    allowance_unlimited = False

    if permission in ("FullAccess", "GasKeyFullAccess"):
        risk_score = 90
        risk_level = "HIGH"

        reasons.append(
            "This key has full-access permissions and can perform "
            "powerful account-level actions."
        )

        recommendations.append(
            "Verify that this public key belongs to an authorized owner."
        )

        recommendations.append(
            "Review whether this level of permission is necessary."
        )

    elif permission in ("FunctionCall", "GasKeyFunctionCall"):
        receiver_id = key.get("receiver_id")
        method_names = key.get("method_names")
        allowance = key.get("allowance")

        if not isinstance(receiver_id, str) or not receiver_id:
            raise ValueError("Invalid receiver account")

        if not isinstance(method_names, list) or not all(
            isinstance(method, str) for method in method_names
        ):
            raise ValueError("Invalid method names")

        if allowance is None:
            allowance_unlimited = True
        else:
            try:
                allowance_value = Decimal(str(allowance))
            except (InvalidOperation, ValueError):
                raise ValueError("Invalid access-key allowance")

            if not allowance_value.is_finite() or allowance_value < 0:
                raise ValueError("Invalid access-key allowance")

            allowance_near = allowance_value / YOCTO_PER_NEAR

        risk_score = 15

        reasons.append(
            f"This key is restricted to receiver {receiver_id}."
        )

        if not method_names:
            risk_score += 25

            reasons.append(
                "An empty method list permits calls to all methods "
                "on the receiver contract."
            )

            recommendations.append(
                "Consider restricting the key to specific contract methods."
            )
        else:
            reasons.append(
                f"This key is restricted to {len(method_names)} method(s)."
            )

        if allowance_unlimited:
            risk_score += 25

            reasons.append(
                "The key has an unlimited gas-fee allowance."
            )

            recommendations.append(
                "Consider setting a finite gas-fee allowance."
            )
        else:
            reasons.append(
                f"The gas-fee allowance is capped at {allowance_near} NEAR."
            )

        if risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        recommendations.append(
            "Verify that the receiver contract is expected and trusted."
        )

    else:
        raise ValueError("Unsupported access-key permission")

    return {
        "public_key": public_key,
        "permission": permission,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons": reasons,
        "recommendations": recommendations,
        "allowance_unlimited": allowance_unlimited,
        "allowance_near": (
            str(allowance_near)
            if allowance_near is not None
            else None
        )
    }
