# (c) Copyright Datacraft, 2026
"""Backup codes for MFA recovery."""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class BackupCode:
	"""A backup code."""
	code: str
	hash: str
	used_at: datetime | None = None


def generate_backup_codes(
	count: int = 10,
	length: int = 8,
	separator: str = "-",
) -> list[BackupCode]:
	"""Generate backup codes for MFA recovery.

	Args:
		count: Number of codes to generate
		length: Length of each code segment
		separator: Separator between segments

	Returns:
		List of BackupCode instances
	"""
	codes = []

	for _ in range(count):
		# Generate two segments for readability
		segment1 = secrets.token_hex(length // 2).upper()
		segment2 = secrets.token_hex(length // 2).upper()
		code = f"{segment1}{separator}{segment2}"

		# Hash the code for storage
		code_hash = hash_backup_code(code)

		codes.append(BackupCode(code=code, hash=code_hash))

	return codes


def hash_backup_code(code: str) -> str:
	"""Hash a backup code for secure storage.

	Args:
		code: Plain text backup code

	Returns:
		SHA-256 hash of the code
	"""
	# Normalize: remove separators and lowercase
	normalized = code.replace("-", "").replace(" ", "").lower()
	return hashlib.sha256(normalized.encode()).hexdigest()


def verify_backup_code(code: str, stored_hash: str) -> bool:
	"""Verify a backup code against stored hash.

	Args:
		code: Plain text backup code to verify
		stored_hash: Stored hash to compare against

	Returns:
		True if code matches
	"""
	code_hash = hash_backup_code(code)
	return secrets.compare_digest(code_hash, stored_hash)


class BackupCodeManager:
	"""Manages backup codes for a user."""

	def __init__(self, code_count: int = 10):
		"""Initialize backup code manager.

		Args:
			code_count: Number of backup codes to generate
		"""
		self.code_count = code_count

	def generate_codes(self) -> tuple[list[str], list[str]]:
		"""Generate new backup codes.

		Returns:
			Tuple of (plain_codes, hashed_codes)
		"""
		codes = generate_backup_codes(count=self.code_count)
		plain_codes = [c.code for c in codes]
		hashed_codes = [c.hash for c in codes]
		return plain_codes, hashed_codes

	def verify_and_consume(
		self,
		code: str,
		stored_hashes: list[str],
		used_indices: set[int],
	) -> tuple[bool, int | None]:
		"""Verify a backup code and mark it as used.

		Args:
			code: Plain text backup code
			stored_hashes: List of stored code hashes
			used_indices: Set of already-used code indices

		Returns:
			Tuple of (is_valid, code_index)
		"""
		code_hash = hash_backup_code(code)

		for i, stored_hash in enumerate(stored_hashes):
			if i in used_indices:
				continue

			if secrets.compare_digest(code_hash, stored_hash):
				return True, i

		return False, None

	def count_remaining(
		self,
		total_codes: int,
		used_indices: set[int],
	) -> int:
		"""Count remaining unused backup codes.

		Args:
			total_codes: Total number of codes generated
			used_indices: Set of used code indices

		Returns:
			Number of remaining codes
		"""
		return total_codes - len(used_indices)

	def format_codes_for_display(self, codes: list[str]) -> str:
		"""Format backup codes for user display/download.

		Args:
			codes: List of plain text codes

		Returns:
			Formatted string with numbered codes
		"""
		lines = ["dArchiva Backup Codes", "=" * 30, ""]
		lines.append("Store these codes in a safe place.")
		lines.append("Each code can only be used once.")
		lines.append("")

		for i, code in enumerate(codes, 1):
			lines.append(f"{i:2}. {code}")

		lines.append("")
		lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")

		return "\n".join(lines)


# Default manager instance
default_backup_manager = BackupCodeManager()
