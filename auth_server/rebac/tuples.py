# (c) Copyright Datacraft, 2026
"""Relationship tuples storage and management."""
import uuid
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import String, Index, UniqueConstraint, Boolean, func, select, delete
from sqlalchemy.orm import Mapped, mapped_column, Session
from sqlalchemy.dialects.postgresql import UUID as PGUUID, TIMESTAMP, JSONB

from auth_server.db.base import Base


# Standard relation types following Zanzibar patterns
class Relations:
	"""Standard relation types."""
	# Direct relations
	OWNER = 'owner'
	EDITOR = 'editor'
	VIEWER = 'viewer'
	COMMENTER = 'commenter'
	SHARER = 'sharer'

	# Group/Org relations
	MEMBER = 'member'
	ADMIN = 'admin'
	MANAGER = 'manager'

	# Hierarchical
	PARENT = 'parent'
	CHILD = 'child'

	# Document specific
	CAN_READ = 'can_read'
	CAN_WRITE = 'can_write'
	CAN_DELETE = 'can_delete'
	CAN_SHARE = 'can_share'
	CAN_DOWNLOAD = 'can_download'


class RelationTuple(Base):
	"""
	Zanzibar-style relation tuple.

	Format: object#relation@subject
	Example: document:123#viewer@user:456
	         folder:789#parent@folder:123

	Supports userset subjects like:
	document:123#viewer@group:456#member
	"""

	__tablename__ = "relation_tuples"

	id: Mapped[UUID] = mapped_column(
		PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
	)

	# Object (resource being accessed)
	object_type: Mapped[str] = mapped_column(String(50), nullable=False)
	object_id: Mapped[str] = mapped_column(String(100), nullable=False)

	# Relation
	relation: Mapped[str] = mapped_column(String(50), nullable=False)

	# Subject (who has the relation)
	subject_type: Mapped[str] = mapped_column(String(50), nullable=False)
	subject_id: Mapped[str] = mapped_column(String(100), nullable=False)

	# Optional: relation on subject for userset rewrites
	subject_relation: Mapped[str | None] = mapped_column(String(50), nullable=True)

	# Metadata
	is_active: Mapped[bool] = mapped_column(Boolean, default=True)
	conditions: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
	created_at: Mapped[datetime] = mapped_column(
		TIMESTAMP(timezone=True), server_default=func.now()
	)
	created_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
	expires_at: Mapped[datetime | None] = mapped_column(
		TIMESTAMP(timezone=True), nullable=True
	)

	__table_args__ = (
		UniqueConstraint(
			"object_type", "object_id", "relation",
			"subject_type", "subject_id", "subject_relation",
			name="uq_relation_tuple"
		),
		Index("idx_tuple_object", "object_type", "object_id"),
		Index("idx_tuple_subject", "subject_type", "subject_id"),
		Index("idx_tuple_relation", "relation"),
		Index(
			"idx_tuple_object_relation",
			"object_type", "object_id", "relation"
		),
		Index(
			"idx_tuple_subject_relation",
			"subject_type", "subject_id", "subject_relation"
		),
	)

	def __repr__(self):
		subject = f"{self.subject_type}:{self.subject_id}"
		if self.subject_relation:
			subject += f"#{self.subject_relation}"
		return f"{self.object_type}:{self.object_id}#{self.relation}@{subject}"

	@classmethod
	def parse(cls, tuple_str: str) -> "RelationTuple":
		"""
		Parse tuple from string format.

		Format: object_type:object_id#relation@subject_type:subject_id[#subject_relation]
		"""
		# Split at @
		object_part, subject_part = tuple_str.split('@')

		# Parse object
		obj_and_rel = object_part.split('#')
		obj_parts = obj_and_rel[0].split(':')
		object_type = obj_parts[0]
		object_id = ':'.join(obj_parts[1:])
		relation = obj_and_rel[1]

		# Parse subject
		subject_relation = None
		if '#' in subject_part:
			subj_main, subject_relation = subject_part.split('#')
		else:
			subj_main = subject_part

		subj_parts = subj_main.split(':')
		subject_type = subj_parts[0]
		subject_id = ':'.join(subj_parts[1:])

		return cls(
			object_type=object_type,
			object_id=object_id,
			relation=relation,
			subject_type=subject_type,
			subject_id=subject_id,
			subject_relation=subject_relation,
		)


class TupleKey(BaseModel):
	"""Lightweight representation of a tuple for checks."""
	model_config = ConfigDict(frozen=True)

	object_type: str
	object_id: str
	relation: str
	subject_type: str
	subject_id: str
	subject_relation: str | None = None

	def __hash__(self):
		return hash((
			self.object_type, self.object_id, self.relation,
			self.subject_type, self.subject_id, self.subject_relation
		))


class RelationshipStore:
	"""
	Store and query relationship tuples.

	Provides CRUD operations and basic lookups.
	"""

	def __init__(self, db: Session):
		self.db = db

	async def write(
		self,
		object_type: str,
		object_id: str,
		relation: str,
		subject_type: str,
		subject_id: str,
		subject_relation: str | None = None,
		conditions: dict | None = None,
		created_by: str | None = None,
		expires_at: datetime | None = None,
	) -> RelationTuple:
		"""Write a relationship tuple."""
		tuple_ = RelationTuple(
			object_type=object_type,
			object_id=object_id,
			relation=relation,
			subject_type=subject_type,
			subject_id=subject_id,
			subject_relation=subject_relation,
			conditions=conditions,
			created_by=created_by,
			expires_at=expires_at,
		)
		self.db.add(tuple_)
		self.db.commit()
		self.db.refresh(tuple_)
		return tuple_

	async def write_batch(
		self,
		tuples: list[dict],
		created_by: str | None = None,
	) -> int:
		"""Write multiple tuples in a batch."""
		count = 0
		for t in tuples:
			try:
				tuple_ = RelationTuple(
					object_type=t['object_type'],
					object_id=t['object_id'],
					relation=t['relation'],
					subject_type=t['subject_type'],
					subject_id=t['subject_id'],
					subject_relation=t.get('subject_relation'),
					conditions=t.get('conditions'),
					created_by=created_by,
					expires_at=t.get('expires_at'),
				)
				self.db.add(tuple_)
				count += 1
			except Exception:
				pass  # Skip duplicates
		self.db.commit()
		return count

	async def delete(
		self,
		object_type: str,
		object_id: str,
		relation: str,
		subject_type: str,
		subject_id: str,
		subject_relation: str | None = None,
	) -> bool:
		"""Delete a specific tuple."""
		stmt = delete(RelationTuple).where(
			RelationTuple.object_type == object_type,
			RelationTuple.object_id == object_id,
			RelationTuple.relation == relation,
			RelationTuple.subject_type == subject_type,
			RelationTuple.subject_id == subject_id,
			RelationTuple.subject_relation == subject_relation,
		)
		result = self.db.execute(stmt)
		self.db.commit()
		return result.rowcount > 0

	async def delete_object(
		self,
		object_type: str,
		object_id: str,
	) -> int:
		"""Delete all tuples for an object."""
		stmt = delete(RelationTuple).where(
			RelationTuple.object_type == object_type,
			RelationTuple.object_id == object_id,
		)
		result = self.db.execute(stmt)
		self.db.commit()
		return result.rowcount

	async def delete_subject(
		self,
		subject_type: str,
		subject_id: str,
	) -> int:
		"""Delete all tuples where entity is a subject."""
		stmt = delete(RelationTuple).where(
			RelationTuple.subject_type == subject_type,
			RelationTuple.subject_id == subject_id,
		)
		result = self.db.execute(stmt)
		self.db.commit()
		return result.rowcount

	async def read(
		self,
		object_type: str | None = None,
		object_id: str | None = None,
		relation: str | None = None,
		subject_type: str | None = None,
		subject_id: str | None = None,
		limit: int = 1000,
	) -> list[RelationTuple]:
		"""Read tuples matching the filters."""
		stmt = select(RelationTuple).where(
			RelationTuple.is_active == True
		)

		if object_type:
			stmt = stmt.where(RelationTuple.object_type == object_type)
		if object_id:
			stmt = stmt.where(RelationTuple.object_id == object_id)
		if relation:
			stmt = stmt.where(RelationTuple.relation == relation)
		if subject_type:
			stmt = stmt.where(RelationTuple.subject_type == subject_type)
		if subject_id:
			stmt = stmt.where(RelationTuple.subject_id == subject_id)

		stmt = stmt.limit(limit)
		return list(self.db.scalars(stmt))

	async def exists(
		self,
		object_type: str,
		object_id: str,
		relation: str,
		subject_type: str,
		subject_id: str,
		subject_relation: str | None = None,
	) -> bool:
		"""Check if a tuple exists."""
		stmt = select(RelationTuple.id).where(
			RelationTuple.object_type == object_type,
			RelationTuple.object_id == object_id,
			RelationTuple.relation == relation,
			RelationTuple.subject_type == subject_type,
			RelationTuple.subject_id == subject_id,
			RelationTuple.is_active == True,
		)
		if subject_relation is not None:
			stmt = stmt.where(RelationTuple.subject_relation == subject_relation)
		else:
			stmt = stmt.where(RelationTuple.subject_relation.is_(None))

		result = self.db.scalar(stmt)
		return result is not None

	async def get_object_relations(
		self,
		object_type: str,
		object_id: str,
	) -> list[RelationTuple]:
		"""Get all relations for an object."""
		stmt = select(RelationTuple).where(
			RelationTuple.object_type == object_type,
			RelationTuple.object_id == object_id,
			RelationTuple.is_active == True,
		)
		return list(self.db.scalars(stmt))

	async def get_subject_relations(
		self,
		subject_type: str,
		subject_id: str,
	) -> list[RelationTuple]:
		"""Get all relations where entity is a subject."""
		stmt = select(RelationTuple).where(
			RelationTuple.subject_type == subject_type,
			RelationTuple.subject_id == subject_id,
			RelationTuple.is_active == True,
		)
		return list(self.db.scalars(stmt))

	async def get_subjects(
		self,
		object_type: str,
		object_id: str,
		relation: str,
	) -> list[tuple[str, str, str | None]]:
		"""Get all subjects with a relation to an object."""
		stmt = select(
			RelationTuple.subject_type,
			RelationTuple.subject_id,
			RelationTuple.subject_relation
		).where(
			RelationTuple.object_type == object_type,
			RelationTuple.object_id == object_id,
			RelationTuple.relation == relation,
			RelationTuple.is_active == True,
		)
		return list(self.db.execute(stmt).all())

	async def get_objects(
		self,
		subject_type: str,
		subject_id: str,
		relation: str,
		object_type: str | None = None,
	) -> list[tuple[str, str]]:
		"""Get all objects where subject has a relation."""
		stmt = select(
			RelationTuple.object_type,
			RelationTuple.object_id,
		).where(
			RelationTuple.subject_type == subject_type,
			RelationTuple.subject_id == subject_id,
			RelationTuple.relation == relation,
			RelationTuple.is_active == True,
		)
		if object_type:
			stmt = stmt.where(RelationTuple.object_type == object_type)
		return list(self.db.execute(stmt).all())
