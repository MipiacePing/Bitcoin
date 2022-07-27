from random import randint
from dataclasses import dataclass


@dataclass
class PrimeGaloisField:
    prime: int

    def __contains__(self, field_value: "FieldElement") -> bool:
        # called whenever you do: <FieldElement> in <PrimeGaloisField>
        return 0 <= field_value.value < self.prime

@dataclass
class FieldElement:
    value: int
    field: PrimeGaloisField

    def __repr__(self):
        return "0x" + f"{self.value:x}".zfill(64)
        
    @property
    def P(self) -> int:
        return self.field.prime
    
    def __add__(self, other: "FieldElement") -> "FieldElement":
        return FieldElement(
            value=(self.value + other.value) % self.P,
            field=self.field
        )
    
    def __sub__(self, other: "FieldElement") -> "FieldElement":
        return FieldElement(
            value=(self.value - other.value) % self.P,
            field=self.field
        )

    def __rmul__(self, scalar: int) -> "FieldValue":
        return FieldElement(
            value=(self.value * scalar) % self.P,
            field=self.field
        )

    def __mul__(self, other: "FieldElement") -> "FieldElement":
        return FieldElement(
            value=(self.value * other.value) % self.P,
            field=self.field
        )
        
    def __pow__(self, exponent: int) -> "FieldElement":
        return FieldElement(
            value=pow(self.value, exponent, self.P),
            field=self.field
        )

    def __truediv__(self, other: "FieldElement") -> "FieldElement":
        other_inv = other ** -1
        return self * other_inv

@dataclass
class EllipticCurve:
    a: int
    b: int

    field: PrimeGaloisField
    
    def __contains__(self, point: "Point") -> bool:
        x, y = point.x, point.y
        return y ** 2 == x ** 3 + self.a * x + self.b

    def __post_init__(self):
        # Encapsulate int parameters in FieldElement
        self.a = FieldElement(self.a, self.field)
        self.b = FieldElement(self.b, self.field)
    
        # Check for membership of curve parameters in the field.
        if self.a not in self.field or self.b not in self.field:
            raise ValueError
# 大质数：2^256 − 2^32 − 2^9 − 2^8 − 2^7 − 2^6 − 2^4 − 1
P: int = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
)
field = PrimeGaloisField(prime=P)

# Elliptic curve parameters A and B of the curve : y² = x³ Ax + B
A: int = 0
B: int = 7

secp256k1 = EllipticCurve(
    a=A,
    b=B,
    field=field
)

inf = float("inf")

@dataclass
class Point:
    x: int
    y: int

    curve: EllipticCurve

    def __post_init__(self):
        # Ignore validation for I
        if self.x is None and self.y is None:   # 两个都为空时，直接返回
            return

        # 两个值不为空时，检查是否在有限域中
        #Encapsulate int coordinates in FieldElement
        self.x = FieldElement(self.x, self.curve.field)
        self.y = FieldElement(self.y, self.curve.field)

        # Verify if the point satisfies the curve equation
        if self not in self.curve:
            raise ValueError
    def __add__(self, other):
        #################################################################
        # Point Addition for P₁ or P₂ = I   (identity)                  #
        #                                                               #
        # Formula:                                                      #
        #     P + I = P                                                 #
        #     I + P = P                                                 #
        #################################################################
        if self == I:
            return other

        if other == I:
            return self

        #################################################################
        # Point Addition for X₁ = X₂   (additive inverse)               #
        #                                                               #
        # Formula:                                                      #
        #     P + (-P) = I                                              #
        #     (-P) + P = I                                              #
        #################################################################
        if self.x == other.x and self.y == (-1 * other.y):
            return I

        #################################################################
        # Point Addition for X₁ ≠ X₂   (line with slope)                #
        #                                                               #
        # Formula:                                                      #
        #     S = (Y₂ - Y₁) / (X₂ - X₁)                                 #
        #     X₃ = S² - X₁ - X₂                                         #
        #     Y₃ = S(X₁ - X₃) - Y₁                                      #
        #################################################################
        if self.x != other.x:
            x1, x2 = self.x, other.x
            y1, y2 = self.y, other.y

            s = (y2 - y1) / (x2 - x1)
            x3 = s ** 2 - x1 - x2
            y3 = s * (x1 - x3) - y1

            return self.__class__(
                x=x3.value,
                y=y3.value,
                curve=secp256k1
            )

        #################################################################
        # Point Addition for P₁ = P₂   (vertical tangent)               #
        #                                                               #
        # Formula:                                                      #
        #     S = ∞                                                     #
        #     (X₃, Y₃) = I                                              #
        #################################################################
        if self == other and self.y == inf:
            return I

        #################################################################
        # Point Addition for P₁ = P₂   (tangent with slope)             #
        #                                                               #
        # Formula:                                                      #
        #     S = (3X₁² + a) / 2Y₁         .. ∂(Y²) = ∂(X² + aX + b)    #
        #     X₃ = S² - 2X₁                                             #
        #     Y₃ = S(X₁ - X₃) - Y₁                                      #
        #################################################################
        if self == other:
            x1, y1, a = self.x, self.y, self.curve.a

            s = (3 * x1 ** 2 + a) / (2 * y1)
            x3 = s ** 2 - 2 * x1
            y3 = s * (x1 - x3) - y1

            return self.__class__(
                x=x3.value,
                y=y3.value,
                curve=secp256k1
            )

    def __rmul__(self, scalar: int) -> "Point":
        # Naive approach:
        #
        # result = I
        # for _ in range(scalar):  # or range(scalar % N)
        #     result = result + self
        # return result
        
        # Optimized approach using binary expansion
        current = self
        result = I
        while scalar:
            if scalar & 1:  # same as scalar % 2
                result = result + current
            current = current + current  # point doubling
            scalar >>= 1  # same as scalar / 2
        return result

I = Point(x=None, y=None, curve=secp256k1)

# Generator point of the abelian group used in Bitcoin
G = Point(
    x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    curve=secp256k1
)

# Order of the group generated by G, such that nG = I
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141



@dataclass
class Signature:
    r: int
    s: int
    
    def verify(self, e: int, pub_key: Point) -> bool:
        s_inv = pow(self.s, -1, N)  # Python 3.8+  可以求逆
        u = (e * s_inv) % N
        v = (self.r * s_inv) % N
        
        return (u*G + v*pub_key).x.value == self.r


@dataclass
class PrivateKey:
    secret: int
    
    def sign(self, e: int) -> Signature:
        d = self.secret
        k = randint(0, N)
        R = k * G
        r = R.x.value
        k_inv = pow(k, -1, N)  # Python 3.8+
        s = ((e + r*d) * k_inv) % N
        
        return Signature(r, s)



pub = Point(
    x=0x887387E452B8EACC4ACFDE10D9AAF7F6D9A0F975AABB10D006E4DA568744D06C,
    y=0x61DE6D95231CD89026E286DF3B6AE4A894A3378E393E93A0F45B666329A0AE34,
    curve=secp256k1
)

# Test case 1: verify authenticity
e = 0xEC208BAA0FC1C19F708A9CA96FDEFF3AC3F230BB4A7BA4AEDE4942AD003C0F60
r = 0xAC8D1C87E51D0D441BE8B3DD5B05C8795B48875DFFE00B7FFCFAC23010D3A395
s = 0x68342CEFF8935EDEDD102DD876FFD6BA72D6A427A3EDB13D26EB0781CB423C4

assert Signature(r, s).verify(e, pub)

# Test case 2: verify authenticity for different signature w/ same P
e = 0x7C076FF316692A3D7EB3C3BB0F8B1488CF72E1AFCD929E29307032997A838A3D
r = 0xEFF69EF2B1BD93A66ED5219ADD4FB51E11A840F404876325A1E8FFE0529A2C
s = 0xC7207FEE197D27C618AEA621406F6BF5EF6FCA38681D82B2F06FDDBDCE6FEAB6
assert Signature(r, s).verify(e, pub)

# Test case 3: sign and verify
d = PrivateKey(randint(0, N))       # generate a private key
pub = d.secret*G
z = randint(0, 2 ** 256)        # generate a random message for testing
signature: Signature = d.sign(z)
assert signature.verify(z, pub)