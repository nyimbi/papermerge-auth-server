# (c) Copyright Datacraft, 2026
"""PBAC data models with versioning and approval workflow."""
import uuid
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from sqlalchemy import (
	String, ForeignKey, Index, UniqueConstraint, Text, Boolean, Integer, func
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID as PGUUID, TIMESTAMP, JSONB

from auth_server.db.base import Base


class PolicyStatus(str, Enum):
	"""Status of a policy."""
	DRAFT = 'draft'
	PENDING_APPROVAL = 'pending_approval'
	ACTIVE = 'active'
	DEPRECATED = 'deprecated'
	ARCHIVED = 'archived'


class PolicyEffect(str, Enum):
	"""Policy effect."""
	ALLOW = 'allow'
	DENY = 'deny'


class PolicyScope(str, Enum):
	"""Scope of policy application."""
	GLOBAL = 'global'
	TENANT = 'tenant'
	DEPARTMENT = 'department'
	RESOURCE_TYPE = 'resource_type'


class PolicySet(Base):
	"""
	Collection of related policies.

	Policy sets allow grouping policies for easier management
	and can define combining algorithms.
	"""

	__tablename__ = "pbac_policy_sets"

	id: Mapped[UUID] = mapped_column(
		PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
	)
	name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
	description: Mapped[str | None] = mapped_column(Text, nullable=True)
	scope: Mapped[str] = mapped_column(String(30), default=PolicyScope.GLOBAL.value)
	scope_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
	is_active: Mapped[bool] = mapped_column(Boolean, default=True)
	priority: Mapped[int] = mapped_column(Integer, default=100)
	combining_algorithm: Mapped[str] = mapped_column(String(30), default='deny_overrides')
	metadata_: Mapped[dict | None] = mapped_column(
		"metadata", JSONB, nullable=True, default=dict
	)
	created_at: Mapped[datetime] = mapped_column(
		TIMESTAMP(timezone=True), server_default=func.now()
	)
	updated_at: Mapped[datetime] = mapped_column(
		TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now()
	)
	created_by: Mapped[UUID | None] = mapped_column(
		ForeignKey("users.id", ondelete="SET NULL"),
		nullable=True,
	)

	# Relationships
	policies: Mapped[list["Policy"]] = relationship(
		"Policy", back_populates="policy_set", cascade="all, delete-orphan"
	)

	__table_args__ = (
		Index("idx_policy_set_scope", "scope", "scope_id"),
	)


class Policy(Base):
	"""
	Individual policy with versioning support.

	Policies are human-readable rules that can be versioned
	and go through approval workflows.
	"""

	__tablename__ = "pbac_policies"

	id: Mapped[UUID] = mapped_column(
		PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
	)
	policy_set_id: Mapped[UUID | None] = mapped_column(
		ForeignKey("pbac_policy_sets.id", ondelete="CASCADE"),
		nullable=True,
	)
	name: Mapped[str] = mapped_column(String(100), nullable=False)
	description: Mapped[str | None] = mapped_column(Text, nullable=True)
	status: Mapped[str] = mapped_column(String(20), default=PolicyStatus.DRAFT.value)
	current_version: Mapped[int] = mapped_column(Integer, default=1)
	effect: Mapped[str] = mapped_column(String(10), default=PolicyEffect.DENY.value)
	priority: Mapped[int] = mapped_column(Integer, default=100)

	# Policy content - human readable
	policy_text: Mapped[str | None] = mapped_column(Text, nullable=True)

	# Compiled conditions (parsed from policy_text or set directly)
	target_resource_types: Mapped[list | None] = mapped_column(JSONB, nullable=True)
	target_actions: Mapped[list | None] = mapped_column(JSONB, nullable=True)
	subject_conditions: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
	resource_conditions: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
	environment_conditions: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

	# Obligations
	obligations: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

	# Temporal constraints
	effective_from: Mapped[datetime | None] = mapped_column(
		TIMESTAMP(timezone=True), nullable=True
	)
	effective_until: Mapped[datetime | None] = mapped_column(
		TIMESTAMP(timezone=True), nullable=True
	)

	# Audit
	created_at: Mapped[datetime] = mapped_column(
		TIMESTAMP(timezone=True), server_default=func.now()
	)
	updated_at: Mapped[datetime] = mapped_column(
		TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now()
	)
	created_by: Mapped[UUID | None] = mapped_column(
		ForeignKey("users.id", ondelete="SET NULL"),
		nullable=True,
	)
	approved_by: Mapped[UUID | None] = mapped_column(
		ForeignKey("users.id", ondelete="SET NULL"),
		nullable=True,
	)
	approved_at: Mapped[datetime | None] = mapped_column(
		TIMESTAMP(timezone=True), nullable=True
	)

	# Relationships
	policy_set: Mapped["PolicySet | None"] = relationship(
		"PolicySet", back_populates="policies"
	)
	versions: Mapped[list["PolicyVersion"]] = relationship(
		"PolicyVersion", back_populates="policy", cascade="all, delete-orphan",
		order_by="PolicyVersion.version.desc()"
	)

	__table_args__ = (
		UniqueConstraint("policy_set_id", "name", name="uq_policy_name_in_set"),
		Index("idx_policy_status", "status"),
		Index("idx_policy_effect", "effect"),
		Index("idx_policy_priority", "priority"),
	)

	def __repr__(self):
		return f"Policy({self.name} v{self.current_version}: {self.effect})"


class PolicyVersion(Base):
	"""
	Version history for policies.

	Stores complete snapshots of policy state for audit
	and rollback purposes.
	"""

	__tablename__ = "pbac_policy_versions"

	id: Mapped[UUID] = mapped_column(
		PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
	)
	policy_id: Mapped[UUID] = mapped_column(
		ForeignKey("pbac_policies.id", ondelete="CASCADE"),
		nullable=False,
	)
	version: Mapped[int] = mapped_column(Integer, nullable=False)
	policy_snapshot: Mapped[dict] = mapped_column(JSONB, nullable=False)
	change_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
	change_type: Mapped[str] = mapped_column(String(20), default='update')
	previous_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
	new_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
	created_at: Mapped[datetime] = mapped_column(
		TIMESTAMP(timezone=True), server_default=func.now()
	)
	created_by: Mapped[UUID | None] = mapped_column(
		ForeignKey("users.id", ondelete="SET NULL"),
		nullable=True,
	)

	# Relationships
	policy: Mapped["Policy"] = relationship("Policy", back_populates="versions")

	__table_args__ = (
		UniqueConstraint("policy_id", "version", name="uq_policy_version"),
		Index("idx_policy_version_lookup", "policy_id", "version"),
	)


class PolicyApproval(Base):
	"""
	Approval workflow for policy changes.

	Tracks approval requests and their outcomes.
	"""

	__tablename__ = "pbac_policy_approvals"

	id: Mapped[UUID] = mapped_column(
		PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
	)
	policy_id: Mapped[UUID] = mapped_column(
		ForeignKey("pbac_policies.id", ondelete="CASCADE"),
		nullable=False,
	)
	version: Mapped[int] = mapped_column(Integer, nullable=False)
	requested_by: Mapped[UUID] = mapped_column(
		ForeignKey("users.id", ondelete="SET NULL"),
		nullable=True,
	)
	requested_at: Mapped[datetime] = mapped_column(
		TIMESTAMP(timezone=True), server_default=func.now()
	)
	status: Mapped[str] = mapped_column(String(20), default='pending')
	reviewed_by: Mapped[UUID | None] = mapped_column(
		ForeignKey("users.id", ondelete="SET NULL"),
		nullable=True,
	)
	reviewed_at: Mapped[datetime | None] = mapped_column(
		TIMESTAMP(timezone=True), nullable=True
	)
	review_comment: Mapped[str | None] = mapped_column(Text, nullable=True)
	diff_summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

	__table_args__ = (
		Index("idx_approval_policy", "policy_id"),
		Index("idx_approval_status", "status"),
	)


class PolicyEvaluationLog(Base):
	"""Audit log for PBAC evaluations."""

	__tablename__ = "pbac_evaluation_logs"

	id: Mapped[UUID] = mapped_column(
		PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
	)
	request_context: Mapped[dict] = mapped_column(JSONB, nullable=False)
	decision: Mapped[str] = mapped_column(String(10), nullable=False)
	matched_policy_id: Mapped[UUID | None] = mapped_column(
		PGUUID(as_uuid=True), nullable=True
	)
	matched_policy_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
	matched_policy_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
	evaluation_time_ms: Mapped[float] = mapped_column(nullable=False)
	obligations_executed: Mapped[list | None] = mapped_column(JSONB, nullable=True)
	created_at: Mapped[datetime] = mapped_column(
		TIMESTAMP(timezone=True), server_default=func.now()
	)

	__table_args__ = (
		Index("idx_pbac_log_created", "created_at"),
		Index("idx_pbac_log_decision", "decision"),
		Index("idx_pbac_log_policy", "matched_policy_id"),
	)
