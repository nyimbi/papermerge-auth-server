# (c) Copyright Datacraft, 2026
"""Department and organizational hierarchy models."""
import uuid
from datetime import datetime
from enum import Enum
from typing import List, TYPE_CHECKING
from uuid import UUID

from sqlalchemy import (
	String, ForeignKey, Index, UniqueConstraint, CheckConstraint,
	func, Boolean, Integer, Text
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID as PGUUID, TIMESTAMP, JSONB

from .base import Base
from .orm import utc_now

if TYPE_CHECKING:
	from .orm import User


class DepartmentAccessLevel(str, Enum):
	"""Access levels for department-based permissions."""
	NONE = 'none'
	READ = 'read'
	WRITE = 'write'
	ADMIN = 'admin'


class Department(Base):
	"""Organizational department for hierarchical access control."""

	__tablename__ = "departments"

	id: Mapped[UUID] = mapped_column(
		PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
	)
	name: Mapped[str] = mapped_column(String(100), nullable=False)
	code: Mapped[str] = mapped_column(String(20), nullable=False, unique=True)
	description: Mapped[str | None] = mapped_column(Text, nullable=True)
	parent_id: Mapped[UUID | None] = mapped_column(
		ForeignKey("departments.id", ondelete="CASCADE"),
		nullable=True,
	)
	level: Mapped[int] = mapped_column(Integer, default=0)
	path: Mapped[str] = mapped_column(String(500), default="")
	is_active: Mapped[bool] = mapped_column(Boolean, default=True)
	metadata_: Mapped[dict | None] = mapped_column(
		"metadata", JSONB, nullable=True, default=dict
	)
	created_at: Mapped[datetime] = mapped_column(
		TIMESTAMP(timezone=True), server_default=func.now()
	)
	updated_at: Mapped[datetime] = mapped_column(
		TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now()
	)

	# Relationships
	parent: Mapped["Department | None"] = relationship(
		"Department", remote_side=[id], back_populates="children"
	)
	children: Mapped[List["Department"]] = relationship(
		"Department", back_populates="parent", cascade="all, delete-orphan"
	)
	members: Mapped[List["UserDepartment"]] = relationship(
		"UserDepartment", back_populates="department", cascade="all, delete-orphan"
	)
	access_rules: Mapped[List["DepartmentAccessRule"]] = relationship(
		"DepartmentAccessRule", back_populates="department", cascade="all, delete-orphan"
	)

	__table_args__ = (
		Index("idx_department_parent", "parent_id"),
		Index("idx_department_path", "path"),
		Index("idx_department_code", "code"),
		CheckConstraint("level >= 0", name="ck_department_level_positive"),
	)

	def __repr__(self):
		return f"Department({self.code}: {self.name})"


class UserDepartment(Base):
	"""Association between users and departments with role flags."""

	__tablename__ = "user_departments"

	id: Mapped[UUID] = mapped_column(
		PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
	)
	user_id: Mapped[UUID] = mapped_column(
		ForeignKey("users.id", ondelete="CASCADE"),
		nullable=False,
	)
	department_id: Mapped[UUID] = mapped_column(
		ForeignKey("departments.id", ondelete="CASCADE"),
		nullable=False,
	)
	is_head: Mapped[bool] = mapped_column(Boolean, default=False)
	is_deputy: Mapped[bool] = mapped_column(Boolean, default=False)
	is_primary: Mapped[bool] = mapped_column(Boolean, default=True)
	can_approve: Mapped[bool] = mapped_column(Boolean, default=False)
	joined_at: Mapped[datetime] = mapped_column(
		TIMESTAMP(timezone=True), server_default=func.now()
	)
	left_at: Mapped[datetime | None] = mapped_column(
		TIMESTAMP(timezone=True), nullable=True
	)

	# Relationships
	department: Mapped["Department"] = relationship(
		"Department", back_populates="members"
	)

	__table_args__ = (
		UniqueConstraint("user_id", "department_id", name="uq_user_department"),
		Index("idx_user_department_user", "user_id"),
		Index("idx_user_department_dept", "department_id"),
		Index("idx_user_department_head", "department_id", "is_head"),
	)


class DepartmentAccessRule(Base):
	"""Access rules for departments on document types."""

	__tablename__ = "department_access_rules"

	id: Mapped[UUID] = mapped_column(
		PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
	)
	department_id: Mapped[UUID] = mapped_column(
		ForeignKey("departments.id", ondelete="CASCADE"),
		nullable=False,
	)
	document_type_id: Mapped[UUID] = mapped_column(
		PGUUID(as_uuid=True), nullable=False
	)
	permission_level: Mapped[str] = mapped_column(
		String(20), default=DepartmentAccessLevel.READ.value
	)
	inherit_to_children: Mapped[bool] = mapped_column(Boolean, default=True)
	conditions: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
	created_at: Mapped[datetime] = mapped_column(
		TIMESTAMP(timezone=True), server_default=func.now()
	)
	created_by: Mapped[UUID] = mapped_column(
		ForeignKey("users.id", ondelete="SET NULL"),
		nullable=True,
	)

	# Relationships
	department: Mapped["Department"] = relationship(
		"Department", back_populates="access_rules"
	)

	__table_args__ = (
		UniqueConstraint(
			"department_id", "document_type_id",
			name="uq_department_doctype_rule"
		),
		Index("idx_access_rule_dept", "department_id"),
		Index("idx_access_rule_doctype", "document_type_id"),
		CheckConstraint(
			"permission_level IN ('none', 'read', 'write', 'admin')",
			name="ck_valid_permission_level"
		),
	)
