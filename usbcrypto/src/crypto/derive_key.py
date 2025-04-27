from argon2.low_level import hash_secret_raw, Type


def derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,  # 64MB
        parallelism=2,
        hash_len=32,
        type=Type.ID
    )
