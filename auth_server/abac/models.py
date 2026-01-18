# (c) Copyright Datacraft, 2026
"""ABAC data models and database schema."""
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import String, ForeignKey, Index, Text, Boolean, Integer, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID as PGUUID, TIMESTAMP, JSONB

from auth_server.db.base import Base


class PolicyEffect(str, Enum):
	"""Effect of a policy rule."""
	ALLOW = 'allow'
	DENY = 'deny'


class ActionType(str, Enum):
	"""Standard actions for access control."""
	CREATE = 'create'
	READ = 'read'
	UPDATE = 'update'
	DELETE = 'delete'
	SHARE = 'share'
	DOWNLOAD = 'download'
	PRINT = 'print'
	EXPORT = 'export'
	APPROVE = 'approve'
	REJECT = 'reject'
	ARCHIVE = 'archive'
	RESTORE = 'restore'


class AttributeType(str, Enum):
	"""Types of attributes for ABAC evaluation."""
	STRING = 'string'
	NUMBER = 'number'
	BOOLEAN = 'boolean'
	DATE = 'date'
	DATETIME = 'datetime'
	LIST = 'list'
	OBJECT = 'object'


class CombiningAlgorithm(str, Enum):
	"""Policy combining algorithms."""
	DENY_OVERRIDES = 'deny_overrides'
	PERMIT_OVERRIDES = 'permit_overrides'
	FIRST_APPLICABLE = 'first_applicable'
	ONLY_ONE_APPLICABLE = 'only_one_applicable'


# Pydantic models for ABAC context

class SubjectAttributes(BaseModel):
	"""Attributes describing the subject (user) making the request."""
	model_config = ConfigDict(extra='allow')

	user_id: UUID
	username: str | None = None
	email: str | None = None
	roles: list[str] = Field(default_factory=list)
	groups: list[str] = Field(default_factory=list)
	departments: list[str] = Field(default_factory=list)
	is_superuser: bool = False
	is_department_head: bool = False
	clearance_level: int = 0
	tenure_days: int = 0


class ResourceAttributes(BaseModel):
	"""Attributes describing the resource being accessed."""
	model_config = ConfigDict(extra='allow')

	resource_id: UUID
	resource_type: str  # document, folder, etc.
	owner_id: UUID | None = None
	owner_type: str | None = None  # user, group
	document_type: str | None = None
	classification: str | None = None  # public, internal, confidential, secret
	department: str | None = None
	tags: list[str] = Field(default_factory=list)
	created_at: datetime | None = None
	status: str | None = None


class EnvironmentAttributes(BaseModel):
	"""Attributes describing the environment/context of the request."""
	model_config = ConfigDict(extra='allow')

	current_time: datetime
	ip_address: str | None = None
	user_agent: str | None = None
	is_business_hours: bool = True
	is_internal_network: bool = False
	mfa_verified: bool = False
	session_age_minutes: int = 0


class ABACRequest(BaseModel):
	"""Complete ABAC authorization request."""
	subject: SubjectAttributes
	resource: ResourceAttributes
	action: ActionType
	environment: EnvironmentAttributes


# SQLAlchemy models for policy storage

class ABACPolicy(Base):
	"""ABAC Policy container with versioning."""

	__tablename__ = "abac_policies"

	id: Mapped[UUID] = mapped_column(
		PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
	)
	name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
	description: Mapped[str | None] = mapped_column(Text, nullable=True)
	version: Mapped[int] = mapped_column(Integer, default=1)
	is_active: Mapped[bool] = mapped_column(Boolean, default=True)
	priority: Mapped[int] = mapped_column(Integer, default=100)
	combining_algorithm: Mapped[str] = mapped_column(
		String(30), default=CombiningAlgorithm.DENY_OVERRIDES.value
	)
	target_conditions: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
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
	rules: Mapped[list["ABACRule"]] = relationship(
		"ABACRule", back_populates="policy", cascade="all, delete-orphan",
		order_by="ABACRule.priority"
	)
	versions: Mapped[list["ABACPolicyVersion"]] = relationship(
		"ABACPolicyVersion", back_populates="policy", cascade="all, delete-orphan"
	)

	__table_args__ = (
		Index("idx_policy_name", "name"),
		Index("idx_policy_active", "is_active"),
		Index("idx_policy_priority", "priority"),
	)

	def __repr__(self):
		return f"ABACPolicy({self.name} v{self.version})"


class ABACRule(Base):
	"""Individual rule within an ABAC policy."""

	__tablename__ = "abac_rules"

	id: Mapped[UUID] = mapped_column(
		PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
	)
	policy_id: Mapped[UUID] = mapped_column(
		ForeignKey("abac_policies.id", ondelete="CASCADE"),
		nullable=False,
	)
	name: Mapped[str] = mapped_column(String(100), nullable=False)
	description: Mapped[str | None] = mapped_column(Text, nullable=True)
	effect: Mapped[str] = mapped_column(String(10), default=PolicyEffect.DENY.value)
	priority: Mapped[int] = mapped_column(Integer, default=100)
	is_active: Mapped[bool] = mapped_column(Boolean, default=True)

	# Conditions as JSONB for flexible evaluation
	subject_conditions: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
	resource_conditions: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
	action_conditions: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
	environment_conditions: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

	# Obligations to be executed if rule matches
	obligations: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

	created_at: Mapped[datetime] = mapped_column(
		TIMESTAMP(timezone=True), server_default=func.now()
	)

	# Relationships
	policy: Mapped["ABACPolicy"] = relationship("ABACPolicy", back_populates="rules")

	__table_args__ = (
		Index("idx_rule_policy", "policy_id"),
		Index("idx_rule_priority", "priority"),
		Index("idx_rule_active", "is_active"),
	)

	def __repr__(self):
		return f"ABACRule({self.name}: {self.effect})"


class ABACPolicyVersion(Base):
	"""Version history for ABAC policies."""

	__tablename__ = "abac_policy_versions"

	id: Mapped[UUID] = mapped_column(
		PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
	)
	policy_id: Mapped[UUID] = mapped_column(
		ForeignKey("abac_policies.id", ondelete="CASCADE"),
		nullable=False,
	)
	version: Mapped[int] = mapped_column(Integer, nullable=False)
	policy_snapshot: Mapped[dict] = mapped_column(JSONB, nullable=False)
	change_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
	created_at: Mapped[datetime] = mapped_column(
		TIMESTAMP(timezone=True), server_default=func.now()
	)
	created_by: Mapped[UUID | None] = mapped_column(
		ForeignKey("users.id", ondelete="SET NULL"),
		nullable=True,
	)

	# Relationships
	policy: Mapped["ABACPolicy"] = relationship(
		"ABACPolicy", back_populates="versions"
	)

	__table_args__ = (
		Index("idx_policy_version", "policy_id", "version"),
	)


class ABACEvaluationLog(Base):
	"""Audit log for ABAC evaluations."""

	__tablename__ = "abac_evaluation_logs"

	id: Mapped[UUID] = mapped_column(
		PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
	)
	request_context: Mapped[dict] = mapped_column(JSONB, nullable=False)
	decision: Mapped[str] = mapped_column(String(10), nullable=False)
	matched_policies: Mapped[list | None] = mapped_column(JSONB, nullable=True)
	matched_rules: Mapped[list | None] = mapped_column(JSONB, nullable=True)
	evaluation_time_ms: Mapped[float] = mapped_column(nullable=False)
	obligations_executed: Mapped[list | None] = mapped_column(JSONB, nullable=True)
	created_at: Mapped[datetime] = mapped_column(
		TIMESTAMP(timezone=True), server_default=func.now()
	)

	__table_args__ = (
		Index("idx_eval_log_created", "created_at"),
		Index("idx_eval_log_decision", "decision"),
	)
