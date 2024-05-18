# IAM0 Cloud - Core

## ZKP - Schnorr
| Client       | Server   | Description       |
|--------------|----------|-------------------|
| `p`, `g`     | `p`, `g` | Common parameters |
| `x`, `y=g^x` | `y`      | Client public key |
| `k`, `r=g^k` | `r`      | Commitment        |
| `c`          | `c`      | Challenge         |
| `s=k+cx`     | `s`      | Response          |
|              | `r`      | Verification      |
